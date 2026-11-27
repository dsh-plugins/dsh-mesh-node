import { createHash, createHmac, hkdfSync, timingSafeEqual } from 'node:crypto'
import { isIP } from 'node:net'
import { checkSignature, publicKey } from './identity.js'
import { isNodeId, object } from './signaling-protocol.js'

export const pairingPath = '/prism/mesh/pairing/v1'
export const pairingTimeout = 10 * 60_000
export const pairingLimit = 8 * 1024

const protocol = 'prism-mesh-pairing-v1'
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u
const digest = /^[A-Za-z0-9_-]{43}$/u

/** 匹配会话绑定临时随机数、持久公钥及由公钥导出的网络节点 ID。 */
export interface PairParticipant {
  nodeId: string
  publicKey: string
  nonce: string
}

/** 持有同一个连接码的证明由节点签名，信令服务只能验证签名。 */
export interface PairProof {
  proof: string
  signature: string
}

/** 客户端保留配对 ID，区分同一设备先后建立的多次配对。 */
export interface PairReceipt {
  pairId: string
  members: [PairParticipant & PairProof & { confirmation: string }, PairParticipant & PairProof & { confirmation: string }]
}

/** 撤销由当前配对的一方签名，离线对端可在下次信令登录时接收。 */
export interface PairRevocation {
  kind: 'pair-revoked'
  pairId: string
  nodeId: string
  peerId: string
  challenge: string
  signature: string
}

export type PairErrorCode = 'busy' | 'cancelled' | 'conflict' | 'expired' | 'invalid' | 'unavailable' | 'used'

export function isPairId(value: unknown): value is string {
  return typeof value === 'string' && uuid.test(value)
}

export function isPairDigest(value: unknown): value is string {
  return typeof value === 'string' && digest.test(value)
}

export function isLoopbackAddress(address: string) {
  const host = address.replace(/^\[|\]$/gu, '').toLowerCase().replace(/^::ffff:/u, '')
  return host === 'localhost' || host === '::1' ||
    (isIP(host) === 4 && host.startsWith('127.'))
}

/** 配对与信令的客户端 URL 使用相同的传输限制。 */
export function validateSignalUrl(url: URL) {
  const local = url.protocol === 'ws:' && url.port === '8080' && isLoopbackAddress(url.hostname)
  if ((!local && url.protocol !== 'wss:') || url.username || url.password || url.hash || url.search) {
    throw new Error('信令需要 WSS，回环测试可使用 8080 端口的 WS')
  }
}

export function pairingNodeId(pin: string) {
  const valid = publicKey(pin)
  return 'mesh-' + createHash('sha256').update(valid.export({ type: 'spki', format: 'der' })).digest('hex')
}

export function participant(value: unknown): PairParticipant | undefined {
  const row = object(value)
  if (!row || typeof row.publicKey !== 'string' || !isPairId(row.nonce) || !isNodeId(row.nodeId)) {
    return undefined
  }
  try {
    if (pairingNodeId(row.publicKey) === row.nodeId) {
      return { nodeId: row.nodeId, publicKey: row.publicKey, nonce: row.nonce }
    }
  } catch {
    // 公钥来自网络输入，拒绝不符合固定 Ed25519 编码的记录。
    return undefined
  }
  return undefined
}

export function pairingSecrets(code: string) {
  if (typeof code !== 'string' || code.length > 64 || !/^[0-9a-f -]+$/iu.test(code)) {
    throw new Error('连接码应包含 32 位十六进制字符')
  }
  const normalized = code.replace(/[ -]/gu, '').toLowerCase()
  if (normalized.length !== 32) {
    throw new Error('连接码应包含 32 位十六进制字符')
  }
  const key = Buffer.from(normalized, 'hex')
  const lookup = Buffer.from(hkdfSync('sha256', key, protocol, 'lookup', 32)).toString('base64url')
  const proofKey = Buffer.from(hkdfSync('sha256', key, protocol, 'proof', 32))
  return { lookup, proofKey }
}

function fields(member: PairParticipant) {
  return [member.nodeId, member.publicKey, member.nonce]
}

export function joinData(challenge: string, lookup: string, member: PairParticipant) {
  return JSON.stringify([protocol, 'join', challenge, lookup, fields(member)])
}

export function pairTranscript(pairId: string, lookup: string, first: PairParticipant, second: PairParticipant) {
  const members = first.nodeId < second.nodeId ? [first, second] : [second, first]
  return JSON.stringify([protocol, 'pair', pairId, lookup, ...members.map(fields)])
}

export function pairProof(key: Buffer, transcript: string, nodeId: string) {
  return createHmac('sha256', key).update(JSON.stringify([transcript, nodeId])).digest('base64url')
}

export function proofData(transcript: string, nodeId: string, proof: string) {
  return JSON.stringify([protocol, 'proof', transcript, nodeId, proof])
}

export function checkProof(key: Buffer, transcript: string, peer: PairParticipant, evidence: PairProof) {
  return isPairDigest(evidence.proof) &&
    timingSafeEqual(Buffer.from(evidence.proof), Buffer.from(pairProof(key, transcript, peer.nodeId))) &&
    checkSignature(publicKey(peer.publicKey), proofData(transcript, peer.nodeId, evidence.proof), evidence.signature)
}

export function confirmationData(transcript: string, nodeId: string) {
  return JSON.stringify([protocol, 'confirm', transcript, nodeId])
}

export function revocationData(input: Pick<PairRevocation, 'pairId' | 'nodeId' | 'peerId' | 'challenge'>) {
  return JSON.stringify([protocol, 'revoke', input.pairId, input.nodeId, input.peerId, input.challenge])
}

export function decodeRevocation(value: unknown): PairRevocation | undefined {
  const row = object(value)
  if (row?.kind !== 'pair-revoked' || !isPairId(row.pairId) || !isPairId(row.challenge) ||
      !isNodeId(row.nodeId) || !isNodeId(row.peerId) || row.nodeId === row.peerId || typeof row.signature !== 'string') {
    return undefined
  }
  return { kind: 'pair-revoked', pairId: row.pairId, nodeId: row.nodeId, peerId: row.peerId,
    challenge: row.challenge, signature: row.signature }
}

export function decodeReceipt(value: unknown): PairReceipt | undefined {
  const row = object(value)
  if (!row || !isPairId(row.pairId) || !Array.isArray(row.members) || row.members.length !== 2) {
    return undefined
  }
  const member = (item: unknown) => {
    const data = object(item)
    const identity = participant(data)
    if (identity && data && isPairDigest(data.proof) && typeof data.signature === 'string' && typeof data.confirmation === 'string') {
      return { ...identity, proof: data.proof, signature: data.signature, confirmation: data.confirmation }
    }
    return undefined
  }
  const [first, second] = row.members.map(member)
  if (first && second && first.nodeId !== second.nodeId && first.nonce !== second.nonce) {
    return { pairId: row.pairId, members: [first, second] }
  }
  return undefined
}
