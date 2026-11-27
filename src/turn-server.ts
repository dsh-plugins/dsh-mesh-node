import { createHmac, randomUUID } from 'node:crypto'
import { createSocket } from 'node:dgram'
import type { Socket as DatagramSocket } from 'node:dgram'
import { createServer as createTcpServer, isIPv6 } from 'node:net'
import type { Server as StreamServer, Socket } from 'node:net'
import { Duplex } from 'node:stream'
import { createServer as createTlsServer } from 'node:tls'
import type { AuthOptions, ListenEntry, Server, ServerOptions } from 'turn-server'
import { compatibleTurnChallenge } from './turn-challenge.js'

const maxConnections = 256

/** 来自属主配置的 TURN 鉴权方式。密码与共享密钥仅在宿主使用。 */
export interface ManagedTurnAuth {
  mode: 'long-term' | 'shared-secret'
  realm: string
  username?: string
  password?: string
  secret?: string
}

/** STUN/TURN 共享控制端口，仅在启用中继时读取认证及中继参数。 */
export interface ManagedIceConfig {
  enabled: boolean
  port: number
  relay: boolean
  tlsPort?: number
  minPort: number
  maxPort: number
  behindNat: boolean
  externalIp?: string
  certFile?: string
  keyFile?: string
  auth: ManagedTurnAuth
}

/** 监听器的关闭句柄，由 DSH 插件生命周期持有。 */
export interface ManagedListener {
  close(): Promise<void>
}

function authentication(config: ManagedIceConfig): AuthOptions {
  if (!config.relay) {
    return { mechanism: 'none' }
  }
  const { mode, realm, username, password, secret } = config.auth
  return mode === 'shared-secret'
    ? { mechanism: 'long-term', realm, secret }
    : { mechanism: 'long-term', realm, credentials: { [username!]: password! } }
}

function listenDatagram(server: Server, entry: ListenEntry): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => finish(new Error('等待 STUN/TURN 监听超时')), 8_000).unref()
    const bound = ({ transport }: { transport: ListenEntry['transport'] }) => {
      if (transport === entry.transport) {
        finish()
      }
    }
    function finish(error?: Error) {
      clearTimeout(timeout)
      server.off('listening', bound)
      server.off('error', fail)
      if (error) {
        reject(error)
      } else {
        resolve()
      }
    }
    function fail(error: Error) { finish(error) }
    server.on('listening', bound)
    server.on('error', fail)
    try {
      server.listen([entry])
    } catch (error) {
      finish(error as Error)
    }
  })
}

// 上游的流转交通道尚未列入 0.10.0 的类型声明，外部 UDP 只需要地址和发送入口。
interface StreamTurnServer extends Server {
  handleTcpConnection(socket: TurnStream): void
  handleSecureConnection(socket: TurnStream): void
}

interface DatagramOutput {
  address(): ReturnType<DatagramSocket['address']>
  send(data: Buffer, offset: number, length: number, port: number, address: string, callback: (error: Error | null) => void): void
}

type ExternalTurnOptions = Omit<ServerOptions, 'socket' | 'socket6'> & { socket?: DatagramOutput; socket6?: DatagramOutput }

class TurnStream extends Duplex {
  constructor(private readonly socket: Socket) {
    super()
    socket.on('data', (chunk: Buffer) => {
      if (!this.push(chunk)) {
        socket.pause()
      }
    })
    socket.on('end', () => this.push(null))
    socket.on('close', () => { this.destroy() })
    socket.on('error', error => { this.destroy(error) })
  }

  get localAddress() { return this.socket.localAddress }
  get localPort() { return this.socket.localPort }
  get remoteAddress() { return this.socket.remoteAddress }
  get remotePort() { return this.socket.remotePort }
  setNoDelay(enabled: boolean) { this.socket.setNoDelay(enabled) }
  _read() { this.socket.resume() }
  _write(data: Buffer, _encoding: BufferEncoding, done: (error?: Error | null) => void) {
    this.socket.write(compatibleTurnChallenge(data), done)
  }
  _final(done: () => void) { this.socket.end(done) }
  _destroy(error: Error | null, done: (error?: Error | null) => void) {
    this.socket.destroy()
    done(error)
  }
}

function bindDatagram(socket: DatagramSocket, port: number, host: string): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.once('error', reject)
    socket.bind(port, host, () => {
      socket.off('error', reject)
      resolve()
    })
  })
}

function closeDatagram(socket: DatagramSocket): Promise<void> {
  return new Promise((resolve, reject) => {
    try {
      socket.close(resolve)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ERR_SOCKET_DGRAM_NOT_RUNNING') {
        resolve()
      } else {
        reject(error)
      }
    }
  })
}

/** 只在属主启用服务时加载 TURN 库，避免影响纯客户端及旧的静态配置。 */
export async function startManagedTurn(
  config: ManagedIceConfig,
  host: string,
  tls: { cert: Buffer; key: Buffer } | undefined,
  onError: (error: Error) => void,
): Promise<ManagedListener> {
  const createServer = (await import('turn-server')).createServer as (options: ExternalTurnOptions) => StreamTurnServer
  const ipv6 = isIPv6(host)
  const udp = createSocket(ipv6 ? 'udp6' : 'udp4')
  let server: StreamTurnServer | undefined
  const streams: StreamServer[] = []
  const sockets = new Set<Socket>()
  let started = false
  const report = (error: Error) => {
    if (started) {
      onError(error)
    }
  }
  udp.on('error', report)
  let closing: Promise<void> | undefined
  const close = () => {
    started = false
    if (!closing) {
      for (const socket of sockets) {
        socket.destroy()
      }
      closing = Promise.all([
        server && new Promise<void>(resolve => { server?.stop(resolve) }),
        closeDatagram(udp),
        ...streams.map(stream => new Promise<void>(resolve => {
          stream.close(() => { resolve() })
        })),
      ]).then(() => undefined)
    }
    return closing
  }
  function listenStream(stream: StreamServer, port: number): Promise<void> {
    stream.maxConnections = maxConnections
    streams.push(stream)
    stream.on('connection', socket => {
      sockets.add(socket)
      socket.once('close', () => { sockets.delete(socket) })
    })
    stream.on('error', report)
    return new Promise((resolve, reject) => {
      stream.once('error', reject)
      stream.listen(port, host, () => {
        stream.off('error', reject)
        resolve()
      })
    })
  }
  try {
    await bindDatagram(udp, config.port, host)
    const udpOutput: DatagramOutput = {
      address: () => udp.address(),
      send(data, offset, length, port, address, sent) {
        udp.send(compatibleTurnChallenge(data.subarray(offset, offset + length)), port, address, sent)
      },
    }
    const turn = createServer({
      auth: authentication(config),
      relay: { ip: host, externalIp: config.externalIp, portRange: [config.minPort, config.maxPort] },
      ...(ipv6 ? { socket6: udpOutput } : { socket: udpOutput }),
      maxConnections,
      totalQuota: 64,
      userQuota: 8,
      maxPermissionsPerAllocation: 64,
      maxChannelsPerAllocation: 64,
      idleTimeout: 300_000,
    })
    server = turn
    turn.on('error', report)
    udp.on('message', (data, source) => turn.handlePacket(data, source))
    if (!config.relay) {
      turn.on('beforeAllocate', (_info, respond) => respond(false))
    }
    limitStunReplies(turn)
    // 自行管理流式监听器，关闭时也可释放尚在 TLS 握手的连接。
    await listenStream(createTcpServer({ pauseOnConnect: true }, socket => {
      turn.handleTcpConnection(new TurnStream(socket))
    }), config.port)
    if (config.relay && config.tlsPort !== undefined && tls) {
      await listenStream(createTlsServer({ ...tls, ALPNProtocols: ['stun.turn', 'stun.nat-discovery'],
        handshakeTimeout: 8_000, minVersion: 'TLSv1.2' }, socket => {
        socket.pause()
        turn.handleSecureConnection(new TurnStream(socket))
      }), config.tlsPort)
    }
    if (config.relay && config.tlsPort !== undefined && tls) {
      await listenDatagram(turn, { address: host, port: config.tlsPort, transport: 'dtls', ...tls })
    }
    started = true
    return { close }
  } catch (error) {
    await close()
    throw error
  }
}

// 限制未认证的 STUN Binding 响应速率，单个源地址不能占满响应预算。
function limitStunReplies(server: Server) {
  let windowSecond = 0
  let replies = 0
  const sources = new Map<string, number>()
  server.on('beforeBindingResponse', ({ source }, respond) => {
    const second = Math.floor(Date.now() / 1_000)
    if (second !== windowSecond) {
      windowSecond = second
      replies = 0
      sources.clear()
    }
    const count = sources.get(source.ip) ?? 0
    if (replies >= 512 || count >= 32) {
      respond(false)
      return
    }
    replies++
    sources.set(source.ip, count + 1)
    respond(true)
  })
}

/** 以 TURN REST 约定签发短时凭据，传给客户端的结果不含服务器密钥。 */
export function issueTurnCredentials(secret: string, now = Date.now()) {
  const expires = Math.floor(now / 1_000) + 3_600
  const username = `${expires}:${randomUUID()}`
  const password = createHmac('sha1', secret).update(username).digest('base64')
  return { username, password, expiresAt: expires * 1_000 }
}
