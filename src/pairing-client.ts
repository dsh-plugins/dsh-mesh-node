import { randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import WebSocket from 'ws'
import { checkSignature, publicKey } from './identity.js'
import { checkProof, confirmationData, decodeReceipt, isPairDigest, isPairId, joinData, pairingLimit, pairingPath,
  pairingSecrets, pairingTimeout, pairProof, pairTranscript, participant, proofData, revocationData, validateSignalUrl } from './pairing-protocol.js'
import type { PairErrorCode, PairParticipant } from './pairing-protocol.js'
import { isNodeId, object } from './signaling-protocol.js'

interface PairConnection {
  url: URL
  nodeId: string
  ca?: string
  signal: AbortSignal
  sign(data: string): string
}

/** 配对成功后交给 Mesh 固定节点公钥及对应的配对 ID。 */
export interface PairedNode {
  nodeId: string
  publicKey: string
  pairId: string
}

const pairErrors: Record<PairErrorCode, string> = {
  busy: '信令服务当前配对请求过多，请稍后重试',
  cancelled: '对端已取消配对，请重试',
  conflict: '相同连接码已有两台设备，或当前设备已在等待',
  expired: '连接码的等待时间已到期',
  invalid: '信令拒绝配对请求或对端身份验证失败',
  unavailable: '信令暂时无法完成配对',
  used: '连接码已使用，请重新生成',
}

function rejectMessage(message: Record<string, unknown>) {
  if (message.kind === 'pair-error') {
    const code = message.code
    throw new Error(typeof code === 'string' && Object.hasOwn(pairErrors, code) ? pairErrors[code as PairErrorCode] : pairErrors.invalid)
  }
}

function exchange<T>(options: PairConnection, timeout: number,
  receive: (message: Record<string, unknown>, send: (message: object) => void, complete: (result: T) => void) => void): Promise<T> {
  validateSignalUrl(options.url)
  const cancellation = AbortSignal.any([options.signal, AbortSignal.timeout(timeout)])
  cancellation.throwIfAborted()
  const url = new URL(pairingPath, options.url)
  const socket = new WebSocket(url, {
    ca: options.ca === undefined ? undefined : readFileSync(options.ca),
    handshakeTimeout: 5_000,
    maxPayload: pairingLimit,
    perMessageDeflate: false,
  })
  return new Promise<T>((resolve, reject) => {
    const fail = (reason: unknown) => { socket.terminate(); reject(reason) }
    const abort = () => fail(options.signal.aborted ? options.signal.reason : new Error(pairErrors.expired))
    const finish = (result: T) => { resolve(result); socket.terminate() }
    const send = (message: object) => socket.send(JSON.stringify(message), error => {
      if (error) {
        fail(new Error(pairErrors.unavailable))
      }
    })
    cancellation.addEventListener('abort', abort, { once: true })
    socket.once('error', () => fail(new Error('无法连接配对信令，请检查地址和 TLS 证书')))
    socket.once('close', () => {
      cancellation.removeEventListener('abort', abort)
      reject(new Error('信令在完成配对操作前断开'))
    })
    socket.on('message', (data, binary) => {
      try {
        const message = binary ? undefined : object(JSON.parse(data.toString()))
        if (!message) {
          throw new Error(pairErrors.invalid)
        }
        rejectMessage(message)
        receive(message, send, finish)
      } catch (error) {
        fail(error instanceof SyntaxError ? new Error(pairErrors.invalid) : error)
      }
    })
  })
}

/** 两端都确认对方的固定密钥和同码证明后，接收持久配对的签名回执。 */
export async function pairWithCode(options: PairConnection & { publicKey: string; code: string }): Promise<PairedNode> {
  const { lookup, proofKey } = pairingSecrets(options.code)
  const local = participant({ nodeId: options.nodeId, publicKey: options.publicKey, nonce: randomUUID() })
  if (!local) {
    throw new Error('本机配对身份无效')
  }
  let started = false
  let match: { pairId: string; peer: PairParticipant; transcript: string } | undefined
  let confirmed = false
  return exchange(options, pairingTimeout + 5_000, (message, send, finish) => {
    if (!started) {
      if (message.kind !== 'challenge' || !isPairId(message.challenge)) {
        throw new Error(pairErrors.invalid)
      }
      const signature = options.sign(joinData(message.challenge, lookup, local))
      send({ kind: 'join', lookup, ...local, signature })
      started = true
      return
    }
    if (message.kind === 'waiting' && !match) {
      return
    }
    if (message.kind === 'match' && !match && isPairId(message.pairId)) {
      const peer = participant(message.peer)
      if (!peer || peer.nodeId === local.nodeId || peer.nonce === local.nonce) {
        throw new Error(pairErrors.invalid)
      }
      const transcript = pairTranscript(message.pairId, lookup, local, peer)
      match = { pairId: message.pairId, peer, transcript }
      const proof = pairProof(proofKey, transcript, local.nodeId)
      send({ kind: 'proof', pairId: match.pairId, proof, signature: options.sign(proofData(transcript, local.nodeId, proof)) })
      return
    }
    if (message.kind === 'proof' && match && !confirmed && message.pairId === match.pairId &&
        isPairDigest(message.proof) && typeof message.signature === 'string') {
      if (!checkProof(proofKey, match.transcript, match.peer, { proof: message.proof, signature: message.signature })) {
        throw new Error(pairErrors.invalid)
      }
      send({ kind: 'confirm', pairId: match.pairId, signature: options.sign(confirmationData(match.transcript, local.nodeId)) })
      confirmed = true
      return
    }
    if (message.kind !== 'committed') {
      throw new Error(pairErrors.invalid)
    }
    const receipt = decodeReceipt(message.receipt)
    const own = receipt?.members.find(member => member.nodeId === local.nodeId && member.publicKey === local.publicKey)
    const other = receipt?.members.find(member => member.nodeId !== local.nodeId)
    if (!receipt || !own || !other || (match && (!confirmed || receipt.pairId !== match.pairId ||
        own.nonce !== local.nonce || other.nodeId !== match.peer.nodeId || other.nonce !== match.peer.nonce))) {
      throw new Error(pairErrors.invalid)
    }
    // 最终回执可在断线后由原参与者重新获取，仍需验证两份原始证明。
    const transcript = pairTranscript(receipt.pairId, lookup, own, other)
    for (const member of receipt.members) {
      if (!checkProof(proofKey, transcript, member, member) ||
          !checkSignature(publicKey(member.publicKey), confirmationData(transcript, member.nodeId), member.confirmation)) {
        throw new Error(pairErrors.invalid)
      }
    }
    finish({ pairId: receipt.pairId, nodeId: other.nodeId, publicKey: other.publicKey })
  })
}

/** 撤销请求从信令挑战得到新签名，之前的撤销标识不能用于重配对的连接。 */
export async function revokePair(options: PairConnection & { peerId: string; pairId: string }): Promise<void> {
  if (!isNodeId(options.nodeId) || !isNodeId(options.peerId) || !isPairId(options.pairId) || options.peerId === options.nodeId) {
    throw new Error(pairErrors.invalid)
  }
  let sent = false
  return exchange(options, 10_000, (message, send, finish) => {
    if (!sent && message.kind === 'challenge' && isPairId(message.challenge)) {
      const revocation = { kind: 'pair-revoked', pairId: options.pairId, nodeId: options.nodeId,
        peerId: options.peerId, challenge: message.challenge }
      send({ ...revocation, signature: options.sign(revocationData(revocation)) })
      sent = true
      return
    }
    if (sent && message.kind === 'removed' && message.pairId === options.pairId) {
      finish(undefined)
      return
    }
    throw new Error(pairErrors.invalid)
  })
}
