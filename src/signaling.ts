import { randomUUID } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import { createServer } from 'node:https'
import type { ServerOptions } from 'node:https'
import WebSocket, { WebSocketServer } from 'ws'
import { checkSignature, publicKey } from './identity.js'
import { decodeSignal, isNodeId, object, signalData, signalingLimit, signalingPath, signInData } from './signaling-protocol.js'

/** 信令节点只能为固定注册的设备转发 WebRTC 协商消息。 */
export interface SignalingOptions {
  tls: ServerOptions
  nodes: Readonly<Record<string, string>>
  path?: string
}

/** 创建独立 TLS 监听器和信令路由，调用者持有监听与关闭生命周期。 */
export function createSignalingServer(options: SignalingOptions) {
  const keys = new Map<string, KeyObject>()
  for (const [id, pin] of Object.entries(options.nodes)) {
    if (!isNodeId(id)) {
      throw new Error('Invalid Mesh signaling node ID')
    }
    keys.set(id, publicKey(pin))
  }
  if (!keys.size) {
    throw new Error('Mesh signaling requires registered node identities')
  }

  const server = createServer(options.tls, (_request, response) => {
    response.writeHead(404)
    response.end()
  })
  const sockets = new WebSocketServer({
    server, path: options.path ?? signalingPath, maxPayload: signalingLimit, perMessageDeflate: false,
  })
  const peers = new Map<string, WebSocket>()
  const alive = new Set<WebSocket>()
  const heartbeat = setInterval(() => {
    for (const socket of sockets.clients) {
      if (!alive.delete(socket)) {
        socket.terminate()
      } else {
        socket.ping()
      }
    }
  }, 20_000).unref()
  server.once('close', () => clearInterval(heartbeat))

  sockets.on('connection', (socket) => {
    socket.on('error', () => socket.terminate())
    if (sockets.clients.size > keys.size * 2 + 16) {
      socket.close(1013, 'Mesh signaling is busy')
      return
    }
    alive.add(socket)
    socket.on('pong', () => alive.add(socket))
    const challenge = randomUUID()
    const deadline = setTimeout(() => socket.terminate(), 5_000).unref()
    let nodeId: string | undefined
    socket.send(JSON.stringify({ kind: 'challenge', challenge }))
    socket.on('message', (message, isBinary) => {
      let value: unknown
      try {
        if (isBinary) {
          throw new Error('Expected signaling JSON')
        }
        value = JSON.parse(message.toString())
      } catch {
        socket.close(1008, 'Invalid Mesh signaling message')
        return
      }
      if (nodeId === undefined) {
        const hello = object(value)
        const id = hello?.nodeId
        const signature = hello?.signature
        const key = isNodeId(id) ? keys.get(id) : undefined
        if (hello?.kind !== 'sign-in' || typeof id !== 'string' || !key || typeof signature !== 'string'
            || !checkSignature(key, signInData(id, challenge), signature)) {
          socket.close(1008, 'Mesh signaling identity rejected')
          return
        }
        nodeId = id
        clearTimeout(deadline)
        peers.get(id)?.close(1008, 'Mesh node reconnected')
        peers.set(id, socket)
        socket.send(JSON.stringify({ kind: 'ready' }))
        return
      }
      const packet = decodeSignal(value)
      const key = keys.get(nodeId)
      if (!packet || packet.from !== nodeId || !key || !keys.has(packet.to)
          || !checkSignature(key, signalData(packet), packet.signature)) {
        socket.close(1008, 'Invalid Mesh signaling message')
        return
      }
      const destination = peers.get(packet.to)
      if (destination?.readyState === WebSocket.OPEN && destination.bufferedAmount < signalingLimit * 4) {
        destination.send(JSON.stringify(packet))
      }
    })
    socket.once('close', () => {
      alive.delete(socket)
      clearTimeout(deadline)
      if (nodeId !== undefined && peers.get(nodeId) === socket) {
        peers.delete(nodeId)
      }
    })
  })

  return {
    server,
    close: async () => {
      clearInterval(heartbeat)
      for (const socket of sockets.clients) {
        socket.terminate()
      }
      await new Promise<void>((resolve, reject) => sockets.close(error => error ? reject(error) : resolve()))
      if (server.listening) {
        await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
      }
    },
  }
}
