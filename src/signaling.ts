import { randomUUID } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import { createServer as createHttpServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import type { ServerOptions } from 'node:https'
import WebSocket, { WebSocketServer } from 'ws'
import { checkSignature, publicKey } from './identity.js'
import { isLoopbackAddress, pairingLimit, pairingPath } from './pairing-protocol.js'
import { PairingSessions } from './pairing-server.js'
import { PairingStore } from './pairing-store.js'
import { decodeSignal, isNodeId, object, signalData, signalingLimit, signalingPath, signInData } from './signaling-protocol.js'

/** 既有显式节点互认可选，托管配对需要单独的持久目录。 */
export interface SignalingOptions {
  tls?: ServerOptions
  nodes?: Readonly<Record<string, string>>
  path?: string
  localTest?: boolean
  pairingDirectory?: string
}

/** 创建信令监听器，托管配对和签名协商使用独立 WebSocket 路径。 */
export function createSignalingServer(options: SignalingOptions) {
  const path = options.path ?? signalingPath
  if ((!options.tls && !options.localTest) || (options.pairingDirectory && path === pairingPath)) {
    throw new Error('Invalid Mesh signaling listener configuration')
  }
  const keys = new Map<string, KeyObject>()
  const pins = new Set<string>()
  for (const [id, pin] of Object.entries(options.nodes ?? {})) {
    if (!isNodeId(id) || pins.has(pin)) {
      throw new Error('Invalid or duplicate Mesh signaling identity')
    }
    keys.set(id, publicKey(pin))
    pins.add(pin)
  }
  if (!keys.size && !options.pairingDirectory) {
    throw new Error('Mesh signaling requires registered node identities')
  }

  const respondNotFound = (_request: IncomingMessage, response: ServerResponse) => {
    response.writeHead(404)
    response.end()
  }
  const server = options.tls ? createHttpsServer(options.tls, respondNotFound) : createHttpServer(respondNotFound)
  const store = options.pairingDirectory ? new PairingStore(options.pairingDirectory) : undefined
  const sockets = new WebSocketServer({
    noServer: true, maxPayload: signalingLimit, perMessageDeflate: false,
  })
  const pairing = store && new WebSocketServer({ noServer: true, maxPayload: pairingLimit, perMessageDeflate: false })
  const peers = new Map<string, WebSocket>()
  const alive = new Set<WebSocket>()
  const sessions = store && new PairingSessions(store, identity => keys.has(identity.nodeId) || pins.has(identity.publicKey), notice => {
    const target = peers.get(notice.peerId)
    if (target?.readyState === WebSocket.OPEN) {
      target.send(JSON.stringify(notice))
    }
  })
  const servers = pairing ? [sockets, pairing] : [sockets]
  const heartbeat = setInterval(() => {
    for (const target of servers) {
      for (const socket of target.clients) {
        if (!alive.delete(socket)) {
          socket.terminate()
        } else if (socket.readyState === WebSocket.OPEN) {
          socket.ping()
        }
      }
    }
  }, 20_000).unref()
  server.once('close', () => clearInterval(heartbeat))

  server.on('upgrade', (request, socket, head) => {
    const target = request.url === path ? sockets : request.url === pairingPath ? pairing : undefined
    if (!target || (!options.tls && !isLoopbackAddress(request.socket.remoteAddress ?? '')) ||
        (target === pairing && request.headers.origin !== undefined)) {
      socket.destroy()
      return
    }
    target.handleUpgrade(request, socket, head, client => target.emit('connection', client, request))
  })

  for (const target of servers) {
    target.on('connection', (socket: WebSocket) => {
      alive.add(socket)
      socket.on('pong', () => alive.add(socket))
      socket.once('close', () => alive.delete(socket))
    })
  }
  pairing?.on('connection', (socket: WebSocket, request: IncomingMessage) => {
    if (pairing.clients.size > 272) {
      socket.close(1013, 'Mesh pairing is busy')
      return
    }
    sessions?.connect(socket, request)
  })

  sockets.on('connection', (socket) => {
    socket.on('error', () => socket.terminate())
    if (sockets.clients.size > (keys.size + (store?.nodeCount ?? 0)) * 2 + 16) {
      socket.close(1013, 'Mesh signaling is busy')
      return
    }
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
        const key = isNodeId(id) ? keys.get(id) ?? store?.key(id) : undefined
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
        for (const notice of store?.revocationsFor(id) ?? []) {
          socket.send(JSON.stringify(notice))
        }
        return
      }
      const packet = decodeSignal(value)
      const key = keys.get(nodeId) ?? store?.key(nodeId)
      if (!packet || packet.from !== nodeId || !key
          || !checkSignature(key, signalData(packet), packet.signature)) {
        socket.close(1008, 'Invalid Mesh signaling message')
        return
      }
      if (!(keys.has(nodeId) && keys.has(packet.to)) && !store?.allows(nodeId, packet.to)) {
        if (!store) {
          socket.close(1008, 'Invalid Mesh signaling message')
        }
        return
      }
      const destination = peers.get(packet.to)
      if (destination?.readyState === WebSocket.OPEN && destination.bufferedAmount < signalingLimit * 4) {
        destination.send(JSON.stringify(packet))
      }
    })
    socket.once('close', () => {
      clearTimeout(deadline)
      if (nodeId !== undefined && peers.get(nodeId) === socket) {
        peers.delete(nodeId)
      }
    })
  })

  let closing: Promise<void> | undefined
  return {
    server,
    close: () => closing ??= (async () => {
      clearInterval(heartbeat)
      sessions?.close()
      try {
        for (const target of servers) {
          for (const socket of target.clients) {
            socket.terminate()
          }
        }
        await Promise.all(servers.map(target => new Promise<void>((resolve, reject) =>
          target.close(error => error ? reject(error) : resolve()))))
        if (server.listening) {
          await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
        }
      } finally {
        store?.close()
      }
    })(),
  }
}
