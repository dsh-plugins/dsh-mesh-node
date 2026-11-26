import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtemp, readFile, realpath, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { model, startHost } from '../../test/host-helpers.mjs'
import { completeText, privateText } from '../../test/fixture-model.mjs'
import { MeshNode } from '../dist/index.js'

test('a remote default project runs a formal L1 session on its assigned DSH host', {timeout: 85000}, async t => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'prism-remote-root-')))
  const tokenEnv = 'PRISM_TEST_' + randomUUID().replaceAll('-', '')
  process.env[tokenEnv] = randomUUID()
  try {
    const peer = {id:'hub',tokenEnv,projects:['desk','other']}
    const desk = {id:'desk',description:'登记项目',stack:[],nodeId:'station',workspace:directory,principals:'*',permissions:[]}
    const host = await startHost(t, directory, {
      mesh: {nodeId:'station', incoming:[peer]}, registry:{projects:[desk,{...desk,id:'other'}]},
      orchestrator:{defaultProjectId:'desk',models:{L1:[model('flash')],L2:[model('plan')],L3:[model('exec')]}},
    })
    const hub = new MeshNode({nodeId:'hub',peers:[{id:'station',url:host.origin,tokenEnv}]})
    t.after(() => hub.close())
    const runner = hub.runnerFor('station')
    const spec = {bindingId:'remote-root',owner:'web:remote',layer:'L1',model:{id:'flash',description:''},
      allowedTools:[],workspace:{projectId:'desk',nodeId:'station',cwd:'/coordinator/path'},systemPrompt:'ignored'}
    const tools = {
      definitions:[{name:'send_user',description:'explicit',parameters:{type:'object'}}],
      invoke:async(name,args) => {assert.equal(name,'send_user'); assert.equal(args.text,completeText); return {}},
    }
    let id
    await runner.run(spec, JSON.stringify({kind:'task_settled'}), tools, undefined, formalId => {id=formalId})
    const requests = (await readFile(host.logFile,'utf8')).trim().split('\n').map(row => JSON.parse(row))
    assert.ok(requests.some(r => r.exchange?.name === 'send_user' && !r.exchange.isError))
    assert.ok(requests.every(r => r.session === id && r.model === 'flash'))
    assert.ok(requests.every(r => r.tools.length === 1 && r.tools[0] === 'send_user'))
    assert.ok(requests.every(r => r.system.includes('PROBE-PROMPT-flash')))
    assert.ok((await runner.transcript(spec)).some(r => r.text === privateText))
    await assert.rejects(runner.run({...spec,workspace:{...spec.workspace,projectId:'other'}}, 'wrong root', tools), /403/)
  } finally {
    delete process.env[tokenEnv]
    t.after(() => rm(directory,{recursive:true,force:true}))
  }
})
