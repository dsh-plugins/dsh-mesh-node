import type { ProjectMetadata, TurnSpec } from '@dsh-prism/dsh-orchestrator/contracts'

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

/** Workspace paths, provider options and system prompts are resolved on the device. */
export function wireTarget(spec: TurnSpec) {
  return {
    bindingId: spec.bindingId, owner: spec.owner, parentBindingId: spec.parentBindingId,
    layer: spec.layer, projectId: spec.workspace.projectId, nodeId: spec.workspace.nodeId,
    modelId: spec.model.id, allowedTools: spec.allowedTools, delegationCeiling: spec.delegationCeiling,
  }
}

export function parseTarget(raw: unknown, nodeId: string): TurnSpec {
  const v = record(raw)
  if (v.nodeId !== nodeId || (v.layer !== 'L1' && v.layer !== 'L2' && v.layer !== 'L3')) throw new MeshError(403, 'Invalid delegation')
  if (v.layer === 'L1' && v.parentBindingId !== undefined) throw new MeshError(403, 'Invalid root delegation')
  return {
    layer: v.layer, workspace: { nodeId, projectId: string(v.projectId), cwd: '' },
    model: {id: string(v.modelId), description: ''}, bindingId: string(v.bindingId),
    owner: string(v.owner, 2048),
    ...(v.layer !== 'L1' && {parentBindingId: string(v.parentBindingId)}),
    allowedTools: names(v.allowedTools), systemPrompt: '',
    ...(v.layer === 'L2' && {delegationCeiling: names(v.delegationCeiling ?? [])}),
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
