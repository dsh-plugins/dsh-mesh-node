import { test } from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { MeshNode } from '../dist/index.js'
import { meshNetwork } from './network-fixture.mjs'

const tool = {name: 'send_parent', description: 'Report', parameters: {type: 'object'}}
const planner = {
  owner: 'web:user', layer: 'L2', bindingId: 'plan', parentBindingId: 'lead',
  model: {id: 'planner', description: 'from hub'}, workspace: {projectId: 'p', nodeId: 'worker', cwd: '/hub/path'},
  allowedTools: [], delegationCeiling: ['read'], systemPrompt: 'hub prompt',
}
const worker = {...planner, layer: 'L3', bindingId: 'child', parentBindingId: 'plan', allowedTools: ['read']}

async function pair(t, runner, options = {}) {
  const { ice, ...services } = options
  const network = await meshNetwork(t, { hub: { worker: [] }, worker: { hub: ['p', 'q'] } }, ice)
  const node = new MeshNode(network.config('worker'))
  const hub = new MeshNode(network.config('hub'))
  node.attach({
    runner,
    authorize(spec) {
      assert.equal(spec.workspace.cwd, '')
      assert.equal(spec.systemPrompt, '')
      if (spec.owner !== 'web:user') throw Error('acl')
      return {...spec, workspace: {...spec.workspace, cwd: '/worker/' + spec.workspace.projectId}, systemPrompt: 'worker prompt'}
    },
    definitionsFor: () => [tool],
    ...services,
  })
  network.cleanup(() => Promise.all([node.close(), hub.close()]))
  return { runner: hub.runnerFor('worker'), hub, node }
}

test('WebRTC preserves native session identity, tool callbacks, lineage and project permission', { timeout: 25_000 }, async t => {
  const {runner, hub, node} = await pair(t, {
    async run(spec, text, tools, signal, onReady) {
      assert.match(spec.bindingId, /^mesh-/)
      assert.equal(spec.workspace.cwd, '/worker/p')
      assert.equal(spec.systemPrompt, 'worker prompt')
      onReady('formal-' + spec.bindingId)
      const response = await tools.invoke('send_parent', {text})
      assert.deepEqual(response, {received: true})
    },
  })
  const assertion = hub.sign('data-channel-assertion')
  assert.equal(node.verify('hub', 'data-channel-assertion', assertion), true)
  assert.equal(node.verify('unknown', 'data-channel-assertion', assertion), false)
  assert.equal(node.verify('hub', 'other-data', assertion), false)
  const calls = []
  const tools = {definitions:[tool], async invoke(name,args) {calls.push({name,args}); return {received:true}}}
  const ready = []
  await runner.run(planner, 'plan', tools, undefined, id => ready.push(id))
  const largeMessage = 'execute 资料'.repeat(15_000)
  await runner.run(worker, largeMessage, tools, undefined, id => ready.push(id))
  assert.equal(ready.length, 2)
  assert.notEqual(ready[0], ready[1])
  assert.match(ready[0], /^formal-mesh-/)
  assert.deepEqual(calls, [{name:'send_parent',args:{text:'plan'}},{name:'send_parent',args:{text:largeMessage}}])
  const denied = {status: 403}
  await assert.rejects(runner.run({...worker,owner:'someone-else'}, 'wrong owner', tools), denied)
  await assert.rejects(runner.run({...worker,allowedTools:['bash']}, 'expand grant', tools), denied)
  await assert.rejects(runner.run({...worker,workspace:{...worker.workspace,projectId:'q'}}, 'switch workspace', tools), denied)
  await assert.rejects(runner.run({...worker,parentBindingId:'missing'}, 'forge parent', tools), denied)
  await assert.rejects(runner.run({...planner,layer:'L1'}, 'attach root', tools), denied)
  await assert.rejects(runner.run(planner, 'unknown tool', {definitions:[{...tool,name:'bash'}]}), denied)
})

test('cancellation aborts the remote DSH turn and waits for its cleanup', { timeout: 25_000 }, async t => {
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

test('remote project indexes are restricted to the authenticated peer and public fields', { timeout: 25_000 }, async t => {
  const listed = {
    id:'p', nodeId:'worker', description:'Visible project', stack:['TypeScript'], permissions:['read'],
    gitRemote:'https://owner:secret@example.com/repo.git?secret=token#branch',
    workspace:'/private/workspaces', credentials:'private', principals:['web:user'],
  }
  const { hub } = await pair(t, {}, {
    queryProjects(owner, search) {
      assert.equal(search, 'p')
      return owner === 'web:user' ? [
        listed, {...listed, id:'unshared'}, {...listed, id:'q', nodeId:'someone-else'},
      ] : []
    },
  })
  assert.deepEqual(await hub.queryProjects('worker', 'web:user', 'p'), [{
    id:'p', nodeId:'worker', description:'Visible project', stack:['TypeScript'], permissions:['read'],
    gitRemote:'https://example.com/repo.git',
  }])
  assert.deepEqual(await hub.queryProjects('worker', 'someone-else', 'p'), [])
})
