import type { KeyObject } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { dshPath } from '@deepseek-ai/dsh-home-paths'
import type { ProjectMetadata } from '@dsh-prism/dsh-orchestrator/contracts'
import { MeshRunner } from './client.js'
import { MeshConnections } from './connections.js'
import { MeshIdentity, publicKey } from './identity.js'
import { messages } from './messages.js'
import { assertParticipants, MeshError, names, peerInboxMessage, peerMessage, projectMetadata, record, string } from './protocol.js'
import type { MeshAgentAddress, MeshConfig, MeshPeer, PeerInboxMessage, PeerMessage } from './protocol.js'
import { isNodeId } from './signaling-protocol.js'
import { MeshWorker } from './worker.js'
import type { WorkerServices } from './worker.js'

export { MeshRunner } from './client.js'
export type { MeshAgentAddress, MeshConfig, MeshPeer, MeshRoom, MeshTurnSpec, PeerInboxMessage, PeerMessage, WebRtcConfig } from './protocol.js'
export type { WorkerServices } from './worker.js'

export const name = 'dsh-mesh-node'

declare module '@deepseek-ai/cordis' {
  interface Context { dshMesh: MeshNode }
}

/** 提供供编排器注册的节点及互认设备身份，工作节点使用同一授权入口处理远程轮次。 */
export class MeshNode {
  readonly nodeId: string
  readonly nodeIds: readonly string[]
  private readonly worker: MeshWorker
  private readonly identity: MeshIdentity
  private readonly connections?: MeshConnections
  private readonly peers = new Map<string, MeshPeer>()

  constructor(config: MeshConfig) {
    if (!isNodeId(config.nodeId)) {
      throw new Error('Invalid Mesh node ID')
    }
    if (Object.hasOwn(config, 'incoming') || (config.peers?.length && !config.webrtc)) {
      throw new Error('Mesh peers now require a WebRTC configuration and pinned public keys')
    }
    this.nodeId = config.nodeId
    const directory = config.stateDirectory ?? dshPath('data', 'prism', 'mesh')
    const keys = new Map<string, KeyObject>()
    const pins = new Set<string>()
    for (const peer of config.peers ?? []) {
      if (!isNodeId(peer.id) || peer.id === this.nodeId || keys.has(peer.id) || pins.has(peer.publicKey)) {
        throw new Error(messages.duplicate)
      }
      keys.set(peer.id, publicKey(peer.publicKey))
      pins.add(peer.publicKey)
      this.peers.set(peer.id, { ...peer, projects: names(peer.projects ?? []) })
    }
    this.nodeIds = Array.from(this.peers.keys())
    if (config.webrtc && (typeof config.webrtc.privateKeyEnv !== 'string' || !config.webrtc.privateKeyEnv.trim())) {
      throw new Error('Mesh WebRTC requires a private key environment variable')
    }
    this.identity = new MeshIdentity(this.nodeId, directory, keys, config.webrtc?.privateKeyEnv)
    if (config.webrtc) {
      const check = this.identity.sign('prism-mesh-v2-local-identity')
      if (this.nodeIds.some(id => this.identity.verify(id, 'prism-mesh-v2-local-identity', check))) {
        throw new Error('Mesh peer key matches the local device key')
      }
      this.connections = new MeshConnections(this.nodeId, new Set(this.nodeIds), this.identity, config.webrtc,
        (id, payload, signal) => this.worker.handle(this.peers.get(id)!, payload, signal))
    }
    this.worker = new MeshWorker(this.nodeId, directory)
  }

  runnerFor(nodeId: string): MeshRunner {
    if (!this.peers.has(nodeId)) {
      throw new Error(messages.unknown)
    }
    return new MeshRunner(nodeId, (payload, signal) => this.request(nodeId, payload, signal))
  }

  attach(services: WorkerServices) { return this.worker.attach(services) }

  async queryProjects(nodeId: string, owner: string, search?: string, signal?: AbortSignal): Promise<ProjectMetadata[]> {
    if (!this.peers.has(nodeId)) {
      throw new Error(messages.unknown)
    }
    const rows = await this.request(nodeId, {
      op: 'projects', owner: string(owner, 2_048), search: search?.trim() || undefined,
    }, signal)
    if (!Array.isArray(rows) || rows.length > 128) {
      throw new MeshError(400, 'Invalid Mesh project index')
    }
    return rows.map(row => projectMetadata(row, nodeId))
  }

  async peerSend(target: MeshAgentAddress, body: Omit<PeerMessage, 'targetAgentId'>, signal?: AbortSignal): Promise<void> {
    const message = peerMessage({ ...body, targetAgentId: target.agentId })
    assertParticipants(message, this.nodeId, target.nodeId)
    await this.sendRoom(target.nodeId, { op: 'peer_send', message }, signal)
  }

  async submitPeerInbox(coordinatorNode: string, body: PeerInboxMessage, signal?: AbortSignal): Promise<void> {
    const message = peerInboxMessage(body)
    if (message.room.coordinatorNode !== coordinatorNode || message.targetNodeId !== this.nodeId) {
      throw new MeshError(403, 'Mesh Room coordinator unavailable')
    }
    assertParticipants(message, message.sourceNodeId, message.targetNodeId)
    await this.sendRoom(coordinatorNode, { op: 'peer_inbox', message }, signal)
  }

  private async sendRoom(nodeId: string, payload: Record<string, unknown>, signal?: AbortSignal) {
    signal?.throwIfAborted()
    const result = nodeId === this.nodeId
      ? await this.worker.handle({ id: this.nodeId }, payload, signal)
      : await this.request(nodeId, payload, signal)
    if (record(result).accepted !== true) {
      throw new MeshError(503, 'Mesh Room message not accepted')
    }
  }

  sign(data: string): string { return this.identity.sign(data) }

  verify(nodeId: string, data: string, signature: string): boolean { return this.identity.verify(nodeId, data, signature) }

  async close() {
    await this.connections?.close()
    await this.worker.close()
  }

  private async request(nodeId: string, payload: Record<string, unknown>, signal?: AbortSignal): Promise<unknown> {
    if (!this.connections) {
      throw new Error(messages.unknown)
    }
    for (let attempt = 0; ; attempt++) {
      const timeout = AbortSignal.timeout(35_000)
      const cancellation = signal ? AbortSignal.any([timeout, signal]) : timeout
      try {
        return await this.connections.request(nodeId, payload, cancellation)
      } catch (error) {
        signal?.throwIfAborted()
        if (attempt >= 1 || (error instanceof MeshError && error.status < 500)) {
          throw error
        }
      }
    }
  }
}

export function apply(ctx: Context, config: MeshConfig) {
  const node = new MeshNode(config)
  ctx.provide('dshMesh', node)
  ctx.effect(() => () => node.close(), 'prism.mesh')
}
