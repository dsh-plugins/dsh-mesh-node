import type { KeyObject } from 'node:crypto'
import { join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { dshPath } from '@deepseek-ai/dsh-home-paths'
import type { HostAPI } from '@dsh-plugin/dsh-loader'
import type { ProjectMetadata } from '@dsh-prism/dsh-orchestrator/contracts'
import { MeshAdministration } from './administration.js'
import { meshAdminRoute } from './admin-route.js'
import { MeshRunner } from './client.js'
import { MeshConnections, type TransportConfig } from './connections.js'
import { MeshIdentity, publicKey } from './identity.js'
import { messages } from './messages.js'
import { pairingNodeId } from './pairing-protocol.js'
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
  readonly staticMode: boolean
  private readonly worker: MeshWorker
  private readonly identity: MeshIdentity
  private connections?: MeshConnections
  private readonly peers = new Map<string, MeshPeer>()
  private readonly keys = new Map<string, KeyObject>()
  private readonly watchers = new Set<() => void>()
  private readonly closing = new Set<Promise<void>>()
  private transportConfig?: string
  private managedNodeId?: string

  constructor(private readonly config: MeshConfig) {
    if (!isNodeId(config.nodeId)) {
      throw new Error('Invalid Mesh node ID')
    }
    if (Object.hasOwn(config, 'incoming') || (config.peers?.length && !config.webrtc)) {
      throw new Error('Mesh peers now require a WebRTC configuration and pinned public keys')
    }
    this.nodeId = config.nodeId
    this.staticMode = !!config.webrtc
    const directory = config.stateDirectory ?? dshPath('data', 'prism', 'mesh')
    const pins = new Set<string>()
    for (const peer of config.peers ?? []) {
      if (!isNodeId(peer.id) || peer.id === this.nodeId || this.keys.has(peer.id) || pins.has(peer.publicKey)) {
        throw new Error(messages.duplicate)
      }
      this.keys.set(peer.id, publicKey(peer.publicKey))
      pins.add(peer.publicKey)
      this.peers.set(peer.id, { ...peer, projects: names(peer.projects ?? []) })
    }
    if (config.webrtc && (typeof config.webrtc.privateKeyEnv !== 'string' || !config.webrtc.privateKeyEnv.trim())) {
      throw new Error('Mesh WebRTC requires a private key environment variable')
    }
    this.identity = new MeshIdentity(this.nodeId, directory, this.keys, config.webrtc?.privateKeyEnv)
    if (config.webrtc) {
      const check = this.identity.sign('prism-mesh-v2-local-identity')
      if (this.nodeIds.some(id => this.identity.verify(id, 'prism-mesh-v2-local-identity', check))) {
        throw new Error('Mesh peer key matches the local device key')
      }
      this.configureTransport(this.nodeId, config.webrtc)
    }
    this.worker = new MeshWorker(this.nodeId, directory)
  }

  get nodeIds(): readonly string[] { return Array.from(this.peers.keys()) }

  get wireNodeId(): string { return this.managedNodeId ?? this.nodeId }

  /** 保留本机历史中的逻辑 ID，跨机身份独立由已持久化的公钥派生。 */
  managedIdentity() {
    if (this.staticMode) {
      throw new MeshError(409, '静态 Mesh 节点由 Cordis 配置管理')
    }
    const pin = this.identity.pin()
    this.managedNodeId ??= pairingNodeId(pin)
    return { nodeId: this.managedNodeId, publicKey: pin, sign: (data: string) => this.identity.sign(data) }
  }

  onNodesChanged(listener: () => void): () => void {
    this.watchers.add(listener)
    return () => { this.watchers.delete(listener) }
  }

  addManagedPeer(id: string, pin: string) {
    const own = this.managedIdentity()
    if (id !== pairingNodeId(pin) || pin === own.publicKey || id === own.nodeId || id === this.nodeId) {
      throw new MeshError(409, '远端节点身份无效')
    }
    const previous = this.peers.get(id)
    if (previous) {
      if (previous.publicKey !== pin) {
        throw new MeshError(409, '远端节点公钥不匹配')
      }
      return
    }
    const projects = Object.hasOwn(this.config.managedPeerProjects ?? {}, id) ? this.config.managedPeerProjects?.[id] : undefined
    const granted = names(projects ?? [])
    this.keys.set(id, publicKey(pin))
    this.peers.set(id, { id, publicKey: pin, projects: granted })
    for (const listener of this.watchers) { listener() }
  }

  removeManagedPeer(id: string) {
    if (!this.staticMode && this.peers.delete(id)) {
      this.keys.delete(id)
      this.connections?.disconnect(id)
      this.worker.revoke(id)
      for (const listener of this.watchers) { listener() }
    }
  }

  peerStatus(id: string) { return this.connections?.status(id) ?? 'offline' }

  staticClient() {
    const { webrtc } = this.config
    return webrtc && { signalingUrl: webrtc.signalingUrl, iceUrls: webrtc.iceServers?.flatMap(entry => entry.urls) ?? [] }
  }

  async connectPeer(id: string, signal: AbortSignal): Promise<void> {
    if (this.connections) {
      await this.connections.connect(id, signal)
    }
  }

  configureManaged(config: TransportConfig, onRevoked: (id: string, pairId: string) => void) {
    this.configureTransport(this.managedIdentity().nodeId, config, onRevoked)
  }

  private configureTransport(address: string, config: TransportConfig, onRevoked?: (id: string, pairId: string) => void) {
    const fingerprint = JSON.stringify(config)
    if (this.transportConfig === fingerprint) {
      return
    }
    const previous = this.connections
    this.connections = new MeshConnections(address, this.peers, this.identity, config, (id, payload, signal) => {
      const peer = this.peers.get(id)
      if (!peer) {
        throw new MeshError(403, 'Mesh peer authorization withdrawn')
      }
      return this.worker.handle(peer, payload, signal, address)
    }, onRevoked)
    this.transportConfig = fingerprint
    if (previous) {
      const stopping = previous.close().catch(error => console.error('[dsh-mesh] 无法关闭旧连接', error))
      this.closing.add(stopping)
      void stopping.then(() => this.closing.delete(stopping))
    }
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
    const local = message.room.coordinatorNode === this.nodeId ? this.nodeId : this.wireNodeId
    assertParticipants(message, local, target.nodeId)
    await this.sendRoom(target.nodeId, { op: 'peer_send', message }, signal)
  }

  async submitPeerInbox(coordinatorNode: string, body: PeerInboxMessage, signal?: AbortSignal): Promise<void> {
    const message = peerInboxMessage(body)
    const local = message.room.coordinatorNode === this.nodeId ? this.nodeId : this.wireNodeId
    if (message.room.coordinatorNode !== coordinatorNode || message.targetNodeId !== local) {
      throw new MeshError(403, 'Mesh Room coordinator unavailable')
    }
    assertParticipants(message, message.sourceNodeId, message.targetNodeId)
    await this.sendRoom(coordinatorNode, { op: 'peer_inbox', message }, signal)
  }

  private async sendRoom(nodeId: string, payload: Record<string, unknown>, signal?: AbortSignal) {
    signal?.throwIfAborted()
    const result = nodeId === this.nodeId || nodeId === this.wireNodeId
      ? await this.worker.handle({ id: nodeId }, payload, signal, nodeId)
      : await this.request(nodeId, payload, signal)
    if (record(result).accepted !== true) {
      throw new MeshError(503, 'Mesh Room message not accepted')
    }
  }

  sign(data: string): string { return this.identity.sign(data) }

  verify(nodeId: string, data: string, signature: string): boolean {
    return this.identity.verify(nodeId === this.wireNodeId ? this.nodeId : nodeId, data, signature)
  }

  async close() {
    this.watchers.clear()
    try {
      await Promise.all([this.connections?.close(), ...this.closing])
    } finally {
      await this.worker.close()
    }
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
  const profile = ctx.get('profileContext', true) as { dir: string } | undefined
  const stateDirectory = config.stateDirectory ?? (profile && join(profile.dir, 'data', 'dsh-prism', 'mesh'))
  const node = new MeshNode({ ...config, stateDirectory })
  ctx.provide('dshMesh', node)
  const report = (message: string) => ctx.logger.warn(message)
  const admin = new MeshAdministration(node, stateDirectory ?? dshPath('data', 'prism', 'mesh'), report)
  ctx.effect(() => () => admin.close().finally(() => node.close()), 'prism.mesh')
  ctx.inject(['dshLoader'], scope => {
    const loader = scope.get('dshLoader', true) as HostAPI
    scope.effect(() => loader.web.registerOwner(meshAdminRoute(admin)), 'prism.mesh.settings')
  })
}
