import { randomUUID } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import WebSocket from 'ws'
import { checkSignature, publicKey } from './identity.js'
import { confirmationData, decodeRevocation, isPairDigest, joinData, pairingTimeout, pairTranscript, participant,
  proofData, revocationData } from './pairing-protocol.js'
import type { PairErrorCode, PairParticipant, PairProof, PairReceipt, PairRevocation } from './pairing-protocol.js'
import type { PairingStore } from './pairing-store.js'
import { object } from './signaling-protocol.js'

interface Member {
  device: PairParticipant
  key: KeyObject
  socket: WebSocket
  proof?: PairProof
  confirmation?: string
}

interface Session {
  id: string
  members: Member[]
  deadline: NodeJS.Timeout
}

const maxWaitingSessions = 128
const maxJoinRate = 24
const maxSourceAddresses = 1024

function send(socket: WebSocket, message: object, close = false) {
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(message), () => {
      if (close) {
        socket.close()
      }
    })
  }
}

/** 同码配对先交换端到端证明，双方确认后才写入信令授权边。 */
export class PairingSessions {
  private readonly pending = new Map<string, Session>()
  private readonly rates = new Map<string, { reset: number; count: number }>()

  constructor(private readonly store: PairingStore, private readonly isStatic: (member: PairParticipant) => boolean,
    private readonly revoked: (notice: PairRevocation) => void) {}

  connect(socket: WebSocket, request: IncomingMessage) {
    socket.on('error', () => socket.terminate())
    if (!this.admit(request.socket.remoteAddress ?? '')) {
      send(socket, { kind: 'pair-error', code: 'busy' }, true)
      return
    }
    const challenge = randomUUID()
    const challengeDeadline = setTimeout(() => socket.terminate(), 5_000).unref()
    let joined: { lookup: string; session: Session; member: Member } | undefined
    let finishing = false
    send(socket, { kind: 'challenge', challenge })
    socket.on('message', (message, isBinary) => {
      if (finishing) {
        return
      }
      let value: Record<string, unknown> | undefined
      try {
        value = isBinary ? undefined : object(JSON.parse(message.toString()))
      } catch {
        // 解析失败的客户端收到同样的协议错误，不记录网络报文。
        value = undefined
      }
      if (!value) {
        finishing = true
        send(socket, { kind: 'pair-error', code: 'invalid' }, true)
        return
      }
      try {
        if (joined) {
          this.advance(joined.lookup, joined.session, joined.member, value)
          return
        }
        clearTimeout(challengeDeadline)
        if (value.kind === 'pair-revoked') {
          finishing = true
          this.revoke(socket, challenge, value)
          return
        }
        joined = this.join(socket, challenge, value)
        finishing = joined === undefined
      } catch (error) {
        console.error('[dsh-mesh] 无法写入信令配对状态', error instanceof Error ? error.name : 'Error')
        finishing = true
        if (joined) {
          this.end(joined.lookup, joined.session, 'unavailable')
        } else {
          send(socket, { kind: 'pair-error', code: 'unavailable' }, true)
        }
      }
    })
    socket.once('close', () => {
      clearTimeout(challengeDeadline)
      if (joined) {
        this.end(joined.lookup, joined.session, 'cancelled')
      }
    })
  }

  close() {
    for (const [lookup, session] of this.pending) {
      this.end(lookup, session, 'cancelled')
    }
    this.rates.clear()
  }

  private admit(source: string) {
    const now = Date.now()
    let rate = this.rates.get(source)
    if (!rate || rate.reset <= now) {
      if (!rate && this.rates.size >= maxSourceAddresses) {
        for (const [address, entry] of this.rates) {
          if (entry.reset <= now) {
            this.rates.delete(address)
          }
        }
        if (this.rates.size >= maxSourceAddresses) {
          return false
        }
      }
      rate = { reset: now + 60_000, count: 0 }
      this.rates.set(source, rate)
    }
    return ++rate.count <= maxJoinRate
  }

  private join(socket: WebSocket, challenge: string, value: Record<string, unknown>) {
    const device = participant(value)
    const { lookup, signature } = value
    if (value.kind !== 'join' || !device || !isPairDigest(lookup) || typeof signature !== 'string' || this.isStatic(device)) {
      send(socket, { kind: 'pair-error', code: 'invalid' }, true)
      return undefined
    }
    const key = publicKey(device.publicKey)
    if (!checkSignature(key, joinData(challenge, lookup, device), signature)) {
      send(socket, { kind: 'pair-error', code: 'invalid' }, true)
      return undefined
    }
    const previous = this.store.consumed(lookup, device.nodeId)
    if (previous) {
      send(socket, previous.receipt ? { kind: 'committed', receipt: previous.receipt } : { kind: 'pair-error', code: 'used' }, true)
      return undefined
    }
    const member = { device, key, socket }
    let session = this.pending.get(lookup)
    if (!session) {
      if (this.pending.size >= maxWaitingSessions) {
        send(socket, { kind: 'pair-error', code: 'busy' }, true)
        return undefined
      }
      const waiting: Session = {
        id: randomUUID(), members: [member],
        deadline: setTimeout(() => this.end(lookup, waiting, 'expired'), pairingTimeout).unref(),
      }
      this.pending.set(lookup, waiting)
      send(socket, { kind: 'waiting' })
      return { lookup, session: waiting, member }
    }
    const [first] = session.members
    if (session.members.length !== 1 || first.device.nodeId === device.nodeId || first.device.nonce === device.nonce) {
      send(socket, { kind: 'pair-error', code: 'conflict' }, true)
      return undefined
    }
    session.members.push(member)
    send(first.socket, { kind: 'match', pairId: session.id, peer: device })
    send(socket, { kind: 'match', pairId: session.id, peer: first.device })
    return { lookup, session, member }
  }

  private advance(lookup: string, session: Session, member: Member, value: Record<string, unknown>) {
    if (this.pending.get(lookup) !== session) {
      return
    }
    const [first, second] = session.members
    if (!second || value.pairId !== session.id || typeof value.signature !== 'string') {
      this.end(lookup, session, 'invalid')
      return
    }
    const transcript = pairTranscript(session.id, lookup, first.device, second.device)
    if (value.kind === 'proof' && !member.proof && isPairDigest(value.proof) &&
        checkSignature(member.key, proofData(transcript, member.device.nodeId, value.proof), value.signature)) {
      member.proof = { proof: value.proof, signature: value.signature }
      if (first.proof && second.proof) {
        send(first.socket, { kind: 'proof', pairId: session.id, ...second.proof })
        send(second.socket, { kind: 'proof', pairId: session.id, ...first.proof })
      }
      return
    }
    if (value.kind !== 'confirm' || member.confirmation || !first.proof || !second.proof ||
        !checkSignature(member.key, confirmationData(transcript, member.device.nodeId), value.signature)) {
      this.end(lookup, session, 'invalid')
      return
    }
    member.confirmation = value.signature
    if (first.confirmation && second.confirmation) {
      const receipt: PairReceipt = { pairId: session.id, members: [
        { ...first.device, ...first.proof, confirmation: first.confirmation },
        { ...second.device, ...second.proof, confirmation: second.confirmation },
      ] }
      this.store.commit(lookup, receipt)
      this.end(lookup, session)
      send(first.socket, { kind: 'committed', receipt }, true)
      send(second.socket, { kind: 'committed', receipt }, true)
    }
  }

  private revoke(socket: WebSocket, challenge: string, value: Record<string, unknown>) {
    const message = decodeRevocation(value)
    const key = message && this.store.key(message.nodeId)
    if (!message || !key || message.challenge !== challenge ||
        !checkSignature(key, revocationData(message), message.signature) || !this.store.revoke(message)) {
      send(socket, { kind: 'pair-error', code: 'invalid' }, true)
      return
    }
    this.revoked(message)
    send(socket, { kind: 'removed', pairId: message.pairId }, true)
  }

  private end(lookup: string, session: Session, error?: PairErrorCode) {
    if (this.pending.get(lookup) !== session) {
      return
    }
    this.pending.delete(lookup)
    clearTimeout(session.deadline)
    if (error) {
      for (const member of session.members) {
        send(member.socket, { kind: 'pair-error', code: error }, true)
      }
    }
  }
}
