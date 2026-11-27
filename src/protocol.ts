import type { ProjectMetadata, TurnSpec } from '@dsh-prism/dsh-orchestrator/contracts'
import { isNodeId } from './signaling-protocol.js'

export const maxBody = 4 * 1024 * 1024

export class MeshError extends Error {
  constructor(readonly status: number, message: string) { super(message) }
}

export function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new MeshError(400, 'Invalid mesh object')
  return value as Record<string, unknown>
}

export function string(value: unknown, limit = 512): string {
  if (typeof value !== 'string' || !value.trim() || value.length > limit) throw new MeshError(400, 'Invalid mesh field')
  return value
}

export function names(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 128) throw new MeshError(400, 'Invalid list')
  const result = value.map(v => string(v, 128))
  if (new Set(result).size !== result.length) throw new MeshError(400, 'Duplicate name')
  return result
}

/** 只复制项目索引允许的字段，工作节点路径与 ACL 留在节点本地。 */
export function projectMetadata(raw: unknown, nodeId: string): ProjectMetadata {
  const value = record(raw)
  if (value.nodeId !== nodeId || !Array.isArray(value.stack) || value.stack.length > 128) {
    throw new MeshError(400, 'Invalid Mesh project metadata')
  }
  let gitRemote: string | undefined
  if (value.gitRemote !== undefined) {
    const url = URL.parse(string(value.gitRemote, 2_048))
    if (!url?.hostname || !['https:', 'http:', 'ssh:', 'git:'].includes(url.protocol)) {
      throw new MeshError(400, 'Invalid Mesh project repository')
    }
    url.username = ''
    url.password = ''
    url.search = ''
    url.hash = ''
    gitRemote = url.href
  }
  return {
    nodeId, id: string(value.id, 128), description: string(value.description, 8_192),
    stack: value.stack.map(item => string(item, 256)), permissions: names(value.permissions),
    ...(gitRemote === undefined ? {} : { gitRemote }),
  }
}

/** 跨节点执行描述，工作区路径和模型凭据由执行节点解析。 */
export interface WireTarget {
  bindingId: string
  owner: string
  parentBindingId?: string
  layer: TurnSpec['layer']
  projectId: string
  nodeId: string
  modelId: string
  allowedTools: string[]
  delegationCeiling?: string[]
  room?: MeshRoom
  depth?: number
  maxDepth?: number
}

export function wireTarget(spec: MeshTurnSpec): WireTarget {
  return {
    bindingId: spec.bindingId, owner: spec.owner, parentBindingId: spec.parentBindingId,
    layer: spec.layer, projectId: spec.workspace.projectId, nodeId: spec.workspace.nodeId,
    modelId: spec.model.id, allowedTools: spec.allowedTools, delegationCeiling: spec.delegationCeiling,
    room: spec.room, depth: spec.depth, maxDepth: spec.maxDepth,
  }
}

function depth(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new MeshError(400, 'Invalid Mesh delegation depth')
  }
  return value
}

export function parseTarget(raw: unknown, nodeId: string): MeshTurnSpec {
  const v = record(raw)
  if (v.nodeId !== nodeId || (v.layer !== 'L1' && v.layer !== 'L2' && v.layer !== 'L3')) throw new MeshError(403, 'Invalid delegation')
  if (v.layer === 'L1' && v.parentBindingId !== undefined) throw new MeshError(403, 'Invalid root delegation')
  if (v.room !== undefined && v.layer !== 'L2') {
    throw new MeshError(403, 'Only a planner can join a Mesh Room')
  }
  return {
    layer: v.layer, workspace: { nodeId, projectId: string(v.projectId), cwd: '' },
    model: {id: string(v.modelId), description: ''}, bindingId: string(v.bindingId),
    owner: string(v.owner, 2048),
    ...(v.layer !== 'L1' && {parentBindingId: string(v.parentBindingId)}),
    allowedTools: names(v.allowedTools), systemPrompt: '',
    ...(v.layer === 'L2' && {delegationCeiling: names(v.delegationCeiling ?? [])}),
    ...(v.room === undefined ? {} : { room: parseRoom(v.room) }),
    ...(v.depth === undefined ? {} : { depth: depth(v.depth) }),
    ...(v.maxDepth === undefined ? {} : { maxDepth: depth(v.maxDepth) }),
  }
}

/** 已授权的 Room 成员地址，节点身份仍由 DataChannel 独立认证。 */
export interface MeshAgentAddress { nodeId: string; agentId: string }

/** 由协调节点签名的成员快照，业务授权由编排器签发和撤销。 */
export interface MeshRoom {
  id: string
  coordinatorNode: string
  members: MeshAgentAddress[]
  grant: string
}

/** 工作节点解析的执行描述，Room 仅随 L2 到达执行节点。 */
export type MeshTurnSpec = TurnSpec & { room?: MeshRoom; depth?: number; maxDepth?: number }

/** 一次定向对等通信，来源节点由消息所在的安全链路提供。 */
export interface PeerMessage {
  messageId: string
  room: MeshRoom
  senderAgentId: string
  targetAgentId: string
  text: string
  proof: string
}

/** 目标节点代为向协调端确认收到消息，使编排器能持久化收件箱。 */
export interface PeerInboxMessage extends PeerMessage {
  sourceNodeId: string
  targetNodeId: string
}

function node(value: unknown): string {
  if (!isNodeId(value)) {
    throw new MeshError(400, 'Invalid Mesh node ID')
  }
  return value
}

function parseRoom(raw: unknown): MeshRoom {
  const room = record(raw)
  if (!Array.isArray(room.members) || !room.members.length || room.members.length > 128) {
    throw new MeshError(400, 'Invalid Mesh Room membership')
  }
  const members = room.members.map(raw => {
    const item = record(raw)
    return { nodeId: node(item.nodeId), agentId: string(item.agentId, 256) }
  })
  if (new Set(members.map(item => JSON.stringify([item.nodeId, item.agentId]))).size !== members.length) {
    throw new MeshError(400, 'Duplicate Mesh Room member')
  }
  return {
    id: string(room.id, 256), coordinatorNode: node(room.coordinatorNode), members, grant: string(room.grant, 8_192),
  }
}

export function peerMessage(value: unknown): PeerMessage {
  const message = record(value)
  if (typeof message.proof !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(message.proof)) {
    throw new MeshError(400, 'Invalid Mesh Room message proof')
  }
  return {
    messageId: string(message.messageId, 256), room: parseRoom(message.room),
    senderAgentId: string(message.senderAgentId, 256), targetAgentId: string(message.targetAgentId, 256),
    text: string(message.text, 16_384), proof: message.proof,
  }
}

export function peerInboxMessage(value: unknown): PeerInboxMessage {
  const message = record(value)
  return {
    ...peerMessage(message), sourceNodeId: node(message.sourceNodeId), targetNodeId: node(message.targetNodeId),
  }
}

export function assertParticipants(message: PeerMessage, source: string, target: string) {
  const members = message.room.members
  if (!members.some(member => member.nodeId === source && member.agentId === message.senderAgentId)
      || !members.some(member => member.nodeId === target && member.agentId === message.targetAgentId)) {
    throw new MeshError(403, 'Mesh Room participants unavailable')
  }
}

/** 双向设备身份固定，projects 仅授权对端使用列出的本地项目。 */
export interface MeshPeer { id: string; publicKey: string; projects?: string[] }

/** 设备信令和 ICE 只使用运营者配置的基础设施及凭据。 */
export interface WebRtcConfig {
  signalingUrl: string
  privateKeyEnv: string
  signalingCaFile?: string
  iceServers?: { urls: string[]; username?: string; credentialEnv?: string }[]
  iceTransportPolicy?: 'all' | 'relay'
}

/** 缺省仅启用本机执行，配置远端设备时必须启用 WebRTC。 */
export interface MeshConfig {
  nodeId: string
  peers?: MeshPeer[]
  webrtc?: WebRtcConfig
  stateDirectory?: string
}
