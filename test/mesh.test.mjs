import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { once } from 'node:events'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { MeshNode } from '../dist/index.js'

const tool = {name: 'send_parent', description: 'Report', parameters: {type: 'object'}}
const planner = {
  owner: 'web:user', layer: 'L2', bindingId: 'plan', parentBindingId: 'lead',
  model: {id: 'planner', description: 'from hub'}, workspace: {projectId: 'p', nodeId: 'worker', cwd: '/hub/path'},
  allowedTools: [], delegationCeiling: ['read'], systemPrompt: 'hub prompt',
}
const worker = {...planner, layer: 'L3', bindingId: 'child', parentBindingId: 'plan', allowedTools: ['read']}

async function pair(t, runner) {
  const dir = await mkdtemp(join(tmpdir(), 'prism-mesh-'))
  const env = 'DSH_PRISM_TEST_' + randomUUID().replaceAll('-', '')
  process.env[env] = randomUUID()
  const node = new MeshNode({nodeId: 'worker', stateDirectory: dir, incoming: [
    {id: 'hub', tokenEnv: env, projects: ['p','q']},
  ]})
  const server = createServer((req, res) => node.handle(req, res))
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const url = 'http://127.0.0.1:' + server.address().port
  const hub = new MeshNode({nodeId: 'hub', peers: [{id: 'worker', tokenEnv: env, url}]})
  node.attach({
    runner,
    authorize(spec) {
      assert.equal(spec.workspace.cwd, '')
      assert.equal(spec.systemPrompt, '')
      if (spec.owner !== 'web:user') throw Error('acl')
      return {...spec, workspace: {...spec.workspace, cwd: '/worker/' + spec.workspace.projectId}, systemPrompt: 'worker prompt'}
    },
    definitionsFor: () => [tool],
  })
  t.after(async () => {
    delete process.env[env]
    await Promise.all([node.close(), hub.close()])
    await new Promise(resolve => server.close(resolve))
    await rm(dir, {recursive:true, force:true})
  })
  return {runner:hub.runnerFor('worker'), url}
}

test('two nodes transfer formal session identity, explicit tool calls and read-only history', async t => {
  const sessions = new Map()
  const {runner, url} = await pair(t, {
    async run(spec, text, tools, signal, onReady) {
      assert.match(spec.bindingId, /^mesh-/)
      assert.equal(spec.workspace.cwd, '/worker/p')
      assert.equal(spec.systemPrompt, 'worker prompt')
      onReady('formal-' + spec.bindingId)
      const response = await tools.invoke('send_parent', {text})
      assert.deepEqual(response, {received: true})
      sessions.set(spec.bindingId, [{role:'user', text}])
    },
    async transcript(spec) { return sessions.get(spec.bindingId) },
  })
  const calls = []
  const tools = {definitions:[tool], async invoke(name,args) {calls.push({name,args}); return {received:true}}}
  const ready = []
  await runner.run(planner, 'plan', tools, undefined, id => ready.push(id))
  await runner.run(worker, 'execute', tools, undefined, id => ready.push(id))
  assert.equal(ready.length, 2)
  assert.notEqual(ready[0], ready[1])
  assert.match(ready[0], /^formal-mesh-/)
  assert.deepEqual(calls, [{name:'send_parent',args:{text:'plan'}},{name:'send_parent',args:{text:'execute'}}])
  assert.deepEqual(await runner.transcript(worker), [{role:'user', text:'execute'}])
  await assert.rejects(runner.transcript({...worker,owner:'someone-else'}), /403/)
  await assert.rejects(runner.run({...worker,allowedTools:['bash']}, 'expand grant', tools), /403/)
  await assert.rejects(runner.run({...worker,workspace:{...worker.workspace,projectId:'q'}}, 'switch workspace', tools), /403/)
  await assert.rejects(runner.run({...worker,parentBindingId:'missing'}, 'forge parent', tools), /403/)
  await assert.rejects(runner.run({...planner,layer:'L1'}, 'attach root', tools), /403/)
  await assert.rejects(runner.run(planner, 'unknown tool', {definitions:[{...tool,name:'bash'}]}), /403/)
  const res = await fetch(url + '/prism/mesh/v1', {method:'POST',headers:{'x-prism-node':'hub',authorization:'Bearer wrong'}})
  assert.equal(res.status, 401)
})

test('cancellation aborts the remote DSH turn and waits for its cleanup', async t => {
  const stopped = Promise.withResolvers()
  const {runner} = await pair(t, {
    async run(_spec, _text, _tools, signal, ready) {
      ready('session')
      if (!signal.aborted) await once(signal, 'abort')
      stopped.resolve()
    },
  })
  const controller = new AbortController()
  const active = Promise.withResolvers()
  const run = runner.run(planner, 'start', {definitions:[],invoke:async()=>{}}, controller.signal, active.resolve)
  await active.promise
  controller.abort()
  await assert.rejects(run)
  await stopped.promise
})
