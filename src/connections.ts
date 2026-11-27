import { randomUUID } from 'node:crypto'
import { setTimeout as sleep } from 'node:timers/promises'
import { RTCPeerConnection } from 'werift'
import type { RTCDataChannel, RTCIceServer, RTCIceCandidateInit } from 'werift'
import type { MeshIdentity } from './identity.js'
import type { WebRtcConfig } from './protocol.js'
import { isConnectionId, object } from './signaling-protocol.js'
import type { SignalPacket } from './signaling-protocol.js'
import { SignalSocket, until } from './signal-socket.js'
import { controlLabel, MeshWire } from './wire.js'

interface Link {
  cancellation: AbortController
  ready: PromiseWithResolvers<MeshWire>
  timer: NodeJS.Timeout
  pc?: RTCPeerConnection
  connectionId?: string
  wire?: MeshWire
  localCandidates: string[]
  remoteCandidates: string[]
  advertisementSent: boolean
  active: boolean
  remoteApplied: boolean
  knownCandidates: Set<string>
}

function iceServers(config: WebRtcConfig): RTCIceServer[] {
  const entries = config.iceServers ?? []
  const servers = entries.map(entry => {
    if (!Array.isArray(entry.urls) || !entry.urls.length || entry.urls.some(url => typeof url !== 'string' || !/^(stun:|turn:|turns:)/.test(url) || url.includes('@'))) {
      throw new Error('Invalid Mesh ICE server URL')
    }
    const turn = entry.urls.some(url => /^(turn:|turns:)/.test(url))
    const credential = entry.credentialEnv === undefined ? undefined : process.env[entry.credentialEnv]
    if (turn && (!entry.username || !credential)) {
      throw new Error('Mesh TURN requires a username and credential environment variable')
    }
    return { urls: entry.urls, username: entry.username, credential }
  })
  if (config.iceTransportPolicy === 'relay' && !entries.some(entry => entry.urls.some(url => /^(turn:|turns:)/.test(url)))) {
    throw new Error('Relay-only Mesh requires a TURN server')
  }
  return servers
}

function validateDescription(sdp: string) {
  const media = sdp.split(/\r?\n/).filter(line => line.startsWith('m='))
  if (media.length !== 1 || !media[0].startsWith('m=application ')
      || !sdp.split(/\r?\n/).some(line => /^a=fingerprint:sha-256 (?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i.test(line))) {
    throw new Error('Invalid Mesh DataChannel SDP')
  }
}

function parseCandidate(raw: string): RTCIceCandidateInit | null {
  if (!raw) {
    return null
  }
  const data = object(JSON.parse(raw))
  if (!data || typeof data.candidate !== 'string' || !data.candidate.startsWith('candidate:')
      || (data.sdpMid !== undefined && data.sdpMid !== null && typeof data.sdpMid !== 'string')
      || (data.sdpMLineIndex !== undefined && data.sdpMLineIndex !== null && data.sdpMLineIndex !== 0)
      || (data.usernameFragment !== undefined && data.usernameFragment !== null && typeof data.usernameFragment !== 'string')) {
    throw new Error('Invalid Mesh ICE candidate')
  }
  return data as RTCIceCandidateInit
}

/** 每对设备使用一条惰性连接，固定发起方消除双方同时建立通道时的冲突。 */
export class MeshConnections {
  private readonly links = new Map<string, Link>()
  private readonly seen = new Map<string, Map<string, number>>()
  private readonly closing = new Set<Promise<void>>()
  private readonly signal: SignalSocket
  private readonly servers: RTCIceServer[]
  private stopped = false

  constructor(private readonly nodeId: string, private readonly peerIds: ReadonlySet<string>,
    identity: MeshIdentity, private readonly config: WebRtcConfig,
    private readonly handle: (nodeId: string, payload: unknown, signal: AbortSignal) => Promise<unknown>) {
    const url = new URL(config.signalingUrl)
    if (url.protocol !== 'wss:' || url.username || url.password || url.hash || url.search) {
      throw new Error('Mesh signaling requires a WSS URL without credentials')
    }
    if (config.iceTransportPolicy !== undefined && config.iceTransportPolicy !== 'all' && config.iceTransportPolicy !== 'relay') {
      throw new Error('Invalid Mesh ICE transport policy')
    }
    this.servers = iceServers(config)
    this.signal = new SignalSocket(nodeId, url, identity, packet => this.onPacket(packet), config.signalingCaFile)
  }

  private createLink(nodeId: string): Link {
    const link: Link = {
      cancellation: new AbortController(), ready: Promise.withResolvers<MeshWire>(),
      timer: setTimeout(() => this.end(nodeId, link, new Error('Mesh peer connection timed out')), 30_000).unref(),
      localCandidates: [], remoteCandidates: [], advertisementSent: false, active: false, remoteApplied: false, knownCandidates: new Set(),
    }
    void link.ready.promise.catch(() => undefined)
    this.links.set(nodeId, link)
    return link
  }

  private end(nodeId: string, link: Link, reason: Error) {
    if (link.cancellation.signal.aborted) {
      return
    }
    if (this.links.get(nodeId) === link) {
      this.links.delete(nodeId)
    }
    clearTimeout(link.timer)
    link.cancellation.abort(reason)
    link.ready.reject(reason)
    link.wire?.close(reason)
    if (link.pc) {
      const closed = link.pc.close().catch(error => { console.error('[dsh-mesh] Peer connection cleanup failed', error) })
      this.closing.add(closed)
      void closed.then(() => this.closing.delete(closed))
    }
  }

  private openChannel(nodeId: string, link: Link, channel: RTCDataChannel) {
    if (link.wire || channel.label !== controlLabel || channel.protocol !== controlLabel || !channel.ordered
        || channel.maxRetransmits !== null || channel.maxPacketLifeTime !== null) {
      channel.close()
      return
    }
    const wire = new MeshWire(channel, (payload, signal) => this.handle(nodeId, payload, signal),
      reason => this.end(nodeId, link, reason))
    link.wire = wire
    const open = () => {
      clearTimeout(link.timer)
      link.active = true
      link.ready.resolve(wire)
    }
    if (channel.readyState === 'open') {
      open()
    } else {
      channel.stateChanged.subscribe(state => { if (state === 'open') { open() } })
    }
  }

  private attachPeer(nodeId: string, link: Link, connectionId: string) {
    const pc = new RTCPeerConnection({
      iceServers: this.servers, iceTransportPolicy: this.config.iceTransportPolicy ?? 'all',
      iceUseDefaultStunServer: false, dtlsHandshakeValidation: 'standard',
    })
    link.pc = pc
    link.connectionId = connectionId
    pc.connectionStateChange.subscribe(state => {
      if (state === 'failed' || state === 'closed') {
        this.end(nodeId, link, new Error('Mesh peer connection failed'))
      }
    })
    pc.onDataChannel.subscribe(channel => this.openChannel(nodeId, link, channel))
    pc.onIceCandidate.subscribe(candidate => {
      const raw = candidate === undefined ? '' : JSON.stringify(candidate.toJSON())
      if (link.advertisementSent) {
        void this.signal.send('candidate', nodeId, connectionId, raw, link.cancellation.signal).catch(() => {
          if (!link.active) {
            this.end(nodeId, link, new Error('Mesh ICE signaling failed'))
          }
        })
      } else {
        link.localCandidates.push(raw)
      }
    })
    return pc
  }

  private async advertise(nodeId: string, link: Link, kind: 'offer' | 'answer') {
    const description = link.pc?.localDescription
    const connectionId = link.connectionId
    if (!description || !connectionId) {
      throw new Error('Mesh local description unavailable')
    }
    await this.signal.send(kind, nodeId, connectionId, description.sdp, link.cancellation.signal)
    while (link.localCandidates.length > 0) {
      for (const candidate of link.localCandidates.splice(0)) {
        if (candidate ? !description.sdp.includes(parseCandidate(candidate)?.candidate ?? '') : !description.sdp.includes('a=end-of-candidates')) {
          await this.signal.send('candidate', nodeId, connectionId, candidate, link.cancellation.signal)
        }
      }
    }
    link.advertisementSent = true
  }

  private async offer(nodeId: string, link: Link, connectionId: string) {
    const pc = this.attachPeer(nodeId, link, connectionId)
    this.openChannel(nodeId, link, pc.createDataChannel(controlLabel, { ordered: true, protocol: controlLabel }))
    await pc.setLocalDescription(await pc.createOffer())
    await this.advertise(nodeId, link, 'offer')
    await this.retryInitial(nodeId, link, 'offer', connectionId)
  }

  private async dial(nodeId: string, link: Link, connectionId: string) {
    await this.signal.send('dial', nodeId, connectionId, '', link.cancellation.signal)
    await this.retryInitial(nodeId, link, 'dial', connectionId)
  }

  private async retryInitial(nodeId: string, link: Link, kind: 'dial' | 'offer', connectionId: string) {
    const signal = link.cancellation.signal
    for (;;) {
      await sleep(500, undefined, { signal })
      if (kind === 'dial' ? link.pc !== undefined : link.remoteApplied) {
        return
      }
      // 对端重新登录信令时可能错过首包。保持连接 ID，让已收到的对端幂等丢弃重发。
      const sdp = kind === 'offer' ? link.pc?.localDescription?.sdp ?? '' : ''
      await this.signal.send(kind, nodeId, connectionId, sdp, signal)
    }
  }

  private async addCandidate(link: Link, raw: string) {
    if (!link.remoteApplied) {
      if (link.remoteCandidates.length >= 128) {
        throw new Error('Too many Mesh ICE candidates')
      }
      link.remoteCandidates.push(raw)
      return
    }
    const candidate = parseCandidate(raw)
    const line = candidate?.candidate ?? ''
    if (!link.knownCandidates.has(line)) {
      link.knownCandidates.add(line)
      await link.pc?.addIceCandidate(candidate)
    }
  }

  private async applyRemote(link: Link, kind: 'offer' | 'answer', sdp: string) {
    validateDescription(sdp)
    for (const line of sdp.split(/\r?\n/)) {
      if (line.startsWith('a=candidate:')) {
        link.knownCandidates.add(line.slice(2))
      }
    }
    if (sdp.includes('a=end-of-candidates')) {
      link.knownCandidates.add('')
    }
    await link.pc?.setRemoteDescription({ type: kind, sdp })
    link.remoteApplied = true
    for (const raw of link.remoteCandidates.splice(0)) {
      await this.addCandidate(link, raw)
    }
  }

  private async answer(nodeId: string, link: Link, packet: SignalPacket) {
    const pc = this.attachPeer(nodeId, link, packet.connectionId)
    await this.applyRemote(link, 'offer', packet.sdp)
    await pc.setLocalDescription(await pc.createAnswer())
    await this.advertise(nodeId, link, 'answer')
  }

  private schedule(nodeId: string, link: Link, operation: Promise<unknown>) {
    void operation.catch(() => this.end(nodeId, link, new Error('Mesh peer negotiation failed')))
  }

  private remember(packet: SignalPacket): boolean {
    const entries = this.seen.get(packet.from) ?? new Map<string, number>()
    this.seen.set(packet.from, entries)
    const key = packet.kind + ':' + packet.connectionId
    for (const [id, expires] of entries) {
      if (expires < Date.now()) {
        entries.delete(id)
      }
    }
    if (entries.has(key) || entries.size >= 256) {
      return false
    }
    entries.set(key, packet.at + 120_000)
    return true
  }

  private onPacket(packet: SignalPacket) {
    const nodeId = packet.from
    if (this.stopped || !this.peerIds.has(nodeId) || !isConnectionId(packet.connectionId)) {
      return
    }
    const current = this.links.get(nodeId)
    if (packet.kind === 'offer' || packet.kind === 'dial') {
      if ((packet.kind === 'offer' ? nodeId > this.nodeId : nodeId < this.nodeId) || !this.remember(packet)) {
        return
      }
      if (packet.kind === 'dial' && current?.pc && !current.active) {
        return
      }
      if (current?.pc) {
        this.end(nodeId, current, new Error('Mesh peer started a new connection'))
      }
      const link = this.links.get(nodeId) ?? this.createLink(nodeId)
      this.schedule(nodeId, link, packet.kind === 'dial'
        ? this.offer(nodeId, link, packet.connectionId) : this.answer(nodeId, link, packet))
      return
    }
    if (!current?.pc || current.connectionId !== packet.connectionId) {
      return
    }
    if (packet.kind === 'candidate') {
      this.schedule(nodeId, current, this.addCandidate(current, packet.sdp))
    } else if (this.nodeId < nodeId && this.remember(packet)) {
      this.schedule(nodeId, current, this.applyRemote(current, 'answer', packet.sdp))
    }
  }

  async request(nodeId: string, payload: unknown, signal: AbortSignal): Promise<unknown> {
    signal.throwIfAborted()
    if (this.stopped || !this.peerIds.has(nodeId)) {
      throw new Error('Mesh peer unavailable')
    }
    let link = this.links.get(nodeId)
    if (!link) {
      link = this.createLink(nodeId)
      const connectionId = randomUUID()
      this.schedule(nodeId, link, this.nodeId < nodeId
        ? this.offer(nodeId, link, connectionId)
        : this.dial(nodeId, link, connectionId))
    }
    try {
      const wire = await until(link.ready.promise, signal)
      return await wire.request(payload, signal)
    } catch (error) {
      if (error instanceof Error && error.name === 'TimeoutError') {
        this.end(nodeId, link, error)
      }
      throw error
    }
  }

  async close() {
    this.stopped = true
    this.signal.close()
    for (const [nodeId, link] of this.links) {
      this.end(nodeId, link, new Error('Mesh closed'))
    }
    await Promise.all(this.closing)
  }
}
