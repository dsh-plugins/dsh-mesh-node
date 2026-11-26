import { messages } from './messages.js'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-host-webserver'
import { dshPath } from '@deepseek-ai/dsh-home-paths'
import { MeshRunner } from './client.js'
import { MeshWorker, type WorkerServices } from './worker.js'
import { authenticated, body, credentialHash, endpoint, maxBody, MeshError, names, string, token,
  type InboundPeer, type MeshConfig } from './protocol.js'

export { MeshRunner } from './client.js'
export type { MeshConfig } from './protocol.js'
export type { WorkerServices } from './worker.js'

export const name = 'dsh-mesh-node'
export const inject = ['webServer']

declare module '@deepseek-ai/cordis' {
  interface Context { dshMesh: MeshNode }
}

/** Registered by the orchestrator as a standard SubagentProvider for each node ID. */
export class MeshNode {
  readonly nodeId: string
  readonly nodeIds: string[]
  private readonly worker: MeshWorker
  private readonly peers = new Map<string, MeshRunner>()
  private readonly incoming = new Map<string, {peer: InboundPeer; hash: Buffer}>()

  constructor(config: MeshConfig) {
    this.nodeId = string(config.nodeId, 128)
    for (const peer of config.peers ?? []) {
      string(peer.id, 128)
      if (peer.id === this.nodeId || this.peers.has(peer.id)) throw new Error(messages.duplicate)
      this.peers.set(peer.id, new MeshRunner(this.nodeId, peer, token(peer.tokenEnv)))
    }
    const hashes = new Set<string>()
    for (const peer of config.incoming ?? []) {
      string(peer.id, 128)
      names(peer.projects)
      const hash = credentialHash(token(peer.tokenEnv))
      if (peer.id === this.nodeId || this.incoming.has(peer.id) || hashes.has(hash.toString('hex'))) {
        throw new Error(messages.credential)
      }
      hashes.add(hash.toString('hex'))
      this.incoming.set(peer.id, {peer, hash})
    }
    this.nodeIds = Array.from(this.peers.keys())
    this.worker = new MeshWorker(this.nodeId, config.stateDirectory ?? dshPath('data', 'prism', 'mesh'))
  }

  runnerFor(nodeId: string): MeshRunner {
    const runner = this.peers.get(nodeId)
    if (!runner) throw new Error(messages.unknown)
    return runner
  }

  attach(services: WorkerServices) { return this.worker.attach(services) }
  close() { return this.worker.close() }

  async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    res.setHeader('content-type', 'application/json; charset=utf-8')
    res.setHeader('cache-control', 'no-store')
    try {
      if (req.method !== 'POST') throw new MeshError(405, 'POST required')
      const id = req.headers['x-prism-node']
      const entry = typeof id === 'string' ? this.incoming.get(id) : undefined
      if (!entry || !authenticated(entry.hash, req.headers.authorization)) throw new MeshError(401, 'Unauthorized')
      if (req.headers['content-type']?.split(';')[0] !== 'application/json') throw new MeshError(415, 'JSON required')
      const result = await this.worker.handle(entry.peer, await body(req))
      const serialized = JSON.stringify(result)
      if (Buffer.byteLength(serialized) > maxBody) throw new MeshError(413, 'Mesh response too large')
      res.end(serialized)
    } catch (error) {
      res.statusCode = error instanceof MeshError ? error.status : 500
      res.end(JSON.stringify({error: error instanceof MeshError ? error.message : 'Mesh operation failed'}))
    }
  }
}

export function apply(ctx: Context, config: MeshConfig) {
  const node = new MeshNode(config)
  ctx.provide('dshMesh', node)
  ctx.webServer.register({kind: 'exact', path: endpoint, auth: 'anonymous', handler: (req, res) => node.handle(req, res)})
  ctx.effect(() => () => node.close(), 'prism.mesh')
}
