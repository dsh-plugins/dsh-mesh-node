import { readFileSync } from 'node:fs'
import WebSocket from 'ws'
import type { MeshIdentity } from './identity.js'
import { decodeSignal, isConnectionId, object, signalData, signalingLimit, signInData } from './signaling-protocol.js'
import type { SignalKind, SignalPacket } from './signaling-protocol.js'

export async function until<T>(waiting: Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted()
  const cancellation = Promise.withResolvers<never>()
  const abort = () => cancellation.reject(signal.reason)
  signal.addEventListener('abort', abort, { once: true })
  try {
    return await Promise.race([waiting, cancellation.promise])
  } finally {
    signal.removeEventListener('abort', abort)
  }
}

/** 同一 WSS 链路只负责连接建立。已打开的数据通道不依赖它持续在线。 */
export class SignalSocket {
  private socket?: WebSocket
  private reconnect?: NodeJS.Timeout
  private ready = Promise.withResolvers<WebSocket>()
  private stopped = false
  private readonly ca?: Buffer

  constructor(private readonly nodeId: string, private readonly url: URL, private readonly identity: MeshIdentity,
    private readonly onPacket: (packet: SignalPacket) => void, caFile?: string) {
    if (caFile !== undefined) {
      this.ca = readFileSync(caFile)
    }
    this.connect()
  }

  private connect() {
    const socket = new WebSocket(this.url, {
      ca: this.ca, handshakeTimeout: 5_000, maxPayload: signalingLimit, perMessageDeflate: false,
    })
    this.socket = socket
    let admitted = false
    const deadline = setTimeout(() => socket.terminate(), 6_000).unref()
    socket.on('error', () => socket.terminate())
    socket.on('message', (data, binary) => {
      let value: unknown
      try {
        if (binary) {
          throw new Error('Expected signaling JSON')
        }
        value = JSON.parse(data.toString())
      } catch {
        socket.terminate()
        return
      }

      if (!admitted) {
        const message = object(value)
        if (message?.kind === 'challenge' && isConnectionId(message.challenge)) {
          socket.send(JSON.stringify({
            kind: 'sign-in', nodeId: this.nodeId,
            signature: this.identity.sign(signInData(this.nodeId, message.challenge)),
          }))
        } else if (message?.kind === 'ready') {
          admitted = true
          clearTimeout(deadline)
          this.ready.resolve(socket)
        } else {
          socket.terminate()
        }
        return
      }
      const packet = decodeSignal(value)
      if (packet?.to === this.nodeId && this.identity.verify(packet.from, signalData(packet), packet.signature)) {
        this.onPacket(packet)
      }
    })
    socket.once('close', () => {
      clearTimeout(deadline)
      if (admitted) {
        this.ready = Promise.withResolvers<WebSocket>()
      }
      if (!this.stopped) {
        this.reconnect = setTimeout(() => this.connect(), 1_000).unref()
      }
    })
  }

  async send(kind: SignalKind, to: string, connectionId: string, sdp: string, signal: AbortSignal) {
    const socket = await until(this.ready.promise, signal)
    signal.throwIfAborted()
    if (this.stopped || socket.readyState !== WebSocket.OPEN) {
      throw new Error('Mesh signaling disconnected')
    }
    const packet = { kind, from: this.nodeId, to, connectionId, at: Date.now(), sdp }
    await new Promise<void>((resolve, reject) => {
      socket.send(JSON.stringify({ ...packet, signature: this.identity.sign(signalData(packet)) }),
        error => error ? reject(error) : resolve())
    })
  }

  close() {
    this.stopped = true
    clearTimeout(this.reconnect)
    this.socket?.terminate()
  }
}
