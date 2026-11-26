import { createHash, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import type { TurnSpec } from '@dsh-prism/dsh-orchestrator/contracts'

export const endpoint = '/prism/mesh/v1'
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

export interface InboundPeer { id: string; tokenEnv: string; projects: string[] }
export interface OutboundPeer { id: string; tokenEnv: string; url: string }
export interface MeshConfig { nodeId: string; peers?: OutboundPeer[]; incoming?: InboundPeer[]; stateDirectory?: string }

export function token(envName: string): string {
  const value = process.env[envName]
  if (!value || !/^[\x21-\x7E]+$/.test(value)) throw new Error('Invalid Mesh peer credential in ' + envName)
  return value
}

export function credentialHash(value: string): Buffer {
  return createHash('sha256').update(value).digest()
}

export function authenticated(expected: Buffer, authorization?: string): boolean {
  return !!authorization?.startsWith('Bearer ') && timingSafeEqual(expected, credentialHash(authorization.slice(7)))
}

export function peerUrl(url: string): URL {
  const parsed = new URL(url)
  if (parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== '/') {
    throw new Error('Mesh peer URL must be an origin')
  }
  const local = ['127.0.0.1', '[::1]', 'localhost'].includes(parsed.hostname)
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && local)) {
    throw new Error('Mesh uses HTTPS between devices')
  }
  return new URL(endpoint, parsed)
}

export async function body(request: IncomingMessage): Promise<unknown> {
  if (Number(request.headers['content-length']) > maxBody) throw new MeshError(413, 'Request too large')
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of request.iterator({destroyOnReturn: false})) {
    const buffer = Buffer.from(chunk)
    total += buffer.length
    if (total > maxBody) {
      request.resume()
      throw new MeshError(413, 'Request too large')
    }
    chunks.push(buffer)
  }
  try { return JSON.parse(Buffer.concat(chunks).toString()) }
  catch { throw new MeshError(400, 'Invalid JSON') }
}
