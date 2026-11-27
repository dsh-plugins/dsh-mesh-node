export const signalingPath = '/prism/mesh/signaling/v2'
export const signalingLimit = 96 * 1024
const maxClockSkew = 120_000

export type SignalKind = 'dial' | 'offer' | 'answer' | 'candidate'

/** 签名绑定连接两端及整段 SDP，信令服务不能替换 DTLS 指纹。 */
export interface SignalPacket {
  kind: SignalKind
  from: string
  to: string
  connectionId: string
  at: number
  sdp: string
  signature: string
}

export function isNodeId(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value)
}

export function isConnectionId(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9-]{36}$/.test(value)
}

export function signalData(packet: Omit<SignalPacket, 'signature'>): string {
  return JSON.stringify(['prism-mesh-v2', packet.kind, packet.from, packet.to, packet.connectionId, packet.at, packet.sdp])
}

export function signInData(nodeId: string, challenge: string): string {
  return JSON.stringify(['prism-mesh-v2', 'sign-in', nodeId, challenge])
}

export function object(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined
}

export function decodeSignal(value: unknown): SignalPacket | undefined {
  const packet = object(value)
  if (!packet || !isNodeId(packet.from) || !isNodeId(packet.to) || packet.from === packet.to
      || !isConnectionId(packet.connectionId) || typeof packet.at !== 'number' || !Number.isSafeInteger(packet.at)
      || Math.abs(Date.now() - packet.at) > maxClockSkew || typeof packet.signature !== 'string'
      || (packet.kind !== 'dial' && packet.kind !== 'offer' && packet.kind !== 'answer' && packet.kind !== 'candidate')
      || typeof packet.sdp !== 'string' || Buffer.byteLength(packet.sdp) > 64 * 1024) {
    return undefined
  }
  if ((packet.kind === 'dial' && packet.sdp !== '')
      || ((packet.kind === 'offer' || packet.kind === 'answer') && !packet.sdp.startsWith('v=0'))
      || (packet.kind === 'candidate' && Buffer.byteLength(packet.sdp) > 4_096)) {
    return undefined
  }
  return {
    kind: packet.kind, from: packet.from, to: packet.to, connectionId: packet.connectionId,
    at: packet.at, sdp: packet.sdp, signature: packet.signature,
  }
}
