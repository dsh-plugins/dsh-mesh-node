import { randomUUID } from 'node:crypto'
import { setTimeout as sleep } from 'node:timers/promises'
import type { RTCDataChannel } from 'werift'
import { maxBody, MeshError } from './protocol.js'
import { isConnectionId, object } from './signaling-protocol.js'
import { until } from './signal-socket.js'

export const controlLabel = 'prism-mesh-v2'
const fragmentLimit = 12 * 1024
const pendingLimit = 64

/** 可靠有序通道的消息分帧提供边界与响应关联，单条逻辑消息仍受旧传输大小上限约束。 */
export class MeshWire {
  private readonly cancellation = new AbortController()
  private readonly requests = new Map<string, PromiseWithResolvers<unknown>>()
  private concurrent = 0
  private fragments: Buffer[] = []
  private bytes = 0
  private sending: Promise<void> = Promise.resolve()

  constructor(private readonly channel: RTCDataChannel,
    private readonly handle: (payload: unknown, signal: AbortSignal) => Promise<unknown>,
    private readonly onClose: (reason: Error) => void) {
    channel.onMessage.subscribe(frame => {
      try {
        this.read(frame)
      } catch {
        this.close(new Error('Invalid Mesh DataChannel message'))
      }
    })
    channel.stateChanged.subscribe(state => {
      if (state === 'closed' || state === 'closing') {
        this.close(new Error('Mesh DataChannel disconnected'))
      }
    })
    channel.error.subscribe(() => this.close(new Error('Mesh DataChannel failed')))
  }

  private transmit(value: unknown, signal?: AbortSignal): Promise<void> {
    const body = Buffer.from(JSON.stringify(value))
    if (body.length > maxBody) {
      throw new MeshError(413, 'Mesh message too large')
    }
    const send = this.sending.then(async () => {
      signal?.throwIfAborted()
      const deadline = AbortSignal.any([AbortSignal.timeout(25_000), this.cancellation.signal])
      for (let offset = 0; offset < body.length; offset += fragmentLimit - 1) {
        deadline.throwIfAborted()
        while (this.channel.bufferedAmount > 256 * 1024) {
          await sleep(10, undefined, { signal: deadline })
        }
        if (this.channel.readyState !== 'open') {
          throw new Error('Mesh DataChannel disconnected')
        }
        const end = Math.min(body.length, offset + fragmentLimit - 1)
        this.channel.send(Buffer.concat([Buffer.from([end === body.length ? 1 : 0]), body.subarray(offset, end)]))
      }
    })
    this.sending = send.catch(error => {
      if (!signal?.aborted || error !== signal.reason) {
        this.close(new Error('Mesh DataChannel send failed'))
      }
    })
    return send
  }

  async request(payload: unknown, signal: AbortSignal): Promise<unknown> {
    if (this.requests.size >= pendingLimit) {
      throw new MeshError(429, 'Mesh peer has too many pending requests')
    }
    const id = randomUUID()
    const result = Promise.withResolvers<unknown>()
    this.requests.set(id, result)
    const cancellation = AbortSignal.any([signal, this.cancellation.signal])
    try {
      const sending = this.transmit({ kind: 'request', id, payload }, cancellation)
      const reply = until(result.promise, cancellation)
      return (await Promise.all([sending, reply]))[1]
    } finally {
      this.requests.delete(id)
    }
  }

  private read(frame: string | Buffer) {
    if (!Buffer.isBuffer(frame) || frame.length < 2 || frame.length > fragmentLimit || frame[0] > 1) {
      throw new Error('Invalid Mesh fragment')
    }
    this.bytes += frame.length - 1
    if (this.bytes > maxBody) {
      throw new Error('Mesh message too large')
    }
    this.fragments.push(frame.subarray(1))
    if (frame[0] === 0) {
      return
    }
    const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(this.fragments))
    this.fragments = []
    this.bytes = 0
    const message = object(JSON.parse(text))
    if (!message || !isConnectionId(message.id)) {
      throw new Error('Invalid Mesh message')
    }
    if (message.kind === 'request' && Object.hasOwn(message, 'payload')) {
      void this.respond(message.id, message.payload)
    } else if (message.kind === 'response' && message.ok === true) {
      this.requests.get(message.id)?.resolve(message.result)
    } else if (message.kind === 'response' && message.ok === false
        && typeof message.status === 'number' && Number.isInteger(message.status)
        && message.status >= 400 && message.status <= 599 && typeof message.message === 'string') {
      this.requests.get(message.id)?.reject(new MeshError(message.status, message.message))
    } else {
      throw new Error('Invalid Mesh message')
    }
  }

  private async respond(id: string, payload: unknown) {
    this.concurrent++
    try {
      try {
        if (this.concurrent > pendingLimit) {
          throw new MeshError(429, 'Mesh peer has too many pending requests')
        }
        const result = await this.handle(payload, this.cancellation.signal)
        await this.transmit({ kind: 'response', id, ok: true, result })
      } catch (error) {
        if (!this.cancellation.signal.aborted) {
          await this.transmit({
            kind: 'response', id, ok: false, status: error instanceof MeshError ? error.status : 500,
            message: error instanceof MeshError ? error.message : 'Mesh operation failed',
          })
        }
      }
    } catch {
      this.close(new Error('Mesh DataChannel response failed'))
    } finally {
      this.concurrent--
    }
  }

  close(reason: Error) {
    if (this.cancellation.signal.aborted) {
      return
    }
    this.cancellation.abort(reason)
    this.fragments = []
    this.onClose(reason)
  }
}
