import { randomUUID } from 'node:crypto'
import { mkdirSync, readFileSync, realpathSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { TransportConfig } from './connections.js'
import { publicKey } from './identity.js'
import type { MeshNode } from './index.js'
import { defaultManagedServerConfig, ManagedMeshServers, validateManagedServerConfig, type ManagedServerConfig } from './managed-server.js'
import { pairWithCode, revokePair } from './pairing-client.js'
import { pairingNodeId } from './pairing-protocol.js'
import { MeshError } from './protocol.js'
import { createSignalingServer } from './signaling.js'
import { isConnectionId, isNodeId, object, signalingPath } from './signaling-protocol.js'

type Client = { signalingUrl: string; iceUrls: string[]; turnUsername?: string; turnPassword?: string }
type Peer = { nodeId: string; publicKey: string; pairId: string }
type Revocation = { signalingUrl: string; peerId: string; pairId: string }
type Settings = { client?: Client; peers: Peer[]; revocations: Revocation[]; server: ManagedServerConfig }
type PairingView = { status: 'idle' | 'waiting' | 'error'; error?: string }

function invalid(message: string): never { throw new MeshError(400, message) }

function field(value: unknown, label: string, max = 2048): string | undefined {
  if (value === undefined || value === '') {
    return undefined
  }
  if (typeof value !== 'string' || Buffer.byteLength(value) > max || /[\x00-\x1f\x7f]/u.test(value)) {
    return invalid(`${label}格式无效`)
  }
  return value
}

function signalAddress(input: unknown): URL {
  const url = URL.parse(field(input, '信令地址')?.trim() ?? '')
  const local = url?.protocol === 'ws:' && url.port === '8080' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
  if (!url || (!local && url.protocol !== 'wss:') || !url.hostname || url.username || url.password || url.search || url.hash) {
    return invalid('信令需使用 WSS 地址，回环测试可使用 WS 8080')
  }
  if (url.pathname === '/') {
    url.pathname = signalingPath
  }
  return url
}

function isTurn(url: string): boolean { return /^turns?:/u.test(url) }

function readClient(value: Record<string, unknown>, previous?: Client): Client {
  const signalingUrl = signalAddress(value.signalingUrl).href
  if (!Array.isArray(value.iceUrls) || value.iceUrls.length > 8) {
    return invalid('最多可配置八个 STUN/TURN 地址')
  }
  const iceUrls = [...new Set(value.iceUrls.map(input => {
    const url = field(input, 'STUN/TURN 地址', 512)?.trim()
    if (!url || !/^(stun|turn|turns):(?:[\w.-]+|\[[0-9a-fA-F:]+\])(?::[0-9]{1,5})?(?:\?transport=(?:udp|tcp))?$/u.test(url) ||
        (url.startsWith('stun:') && url.includes('?')) || (url.startsWith('turns:') && url.endsWith('transport=udp'))) {
      return invalid('STUN/TURN 地址无效，TURN TLS 客户端需使用 TCP')
    }
    const port = /:([0-9]+)(?:\?|$)/u.exec(url.split(']').at(-1) ?? url)?.[1]
    if (port !== undefined && (Number(port) < 1 || Number(port) > 65_535)) {
      return invalid('STUN/TURN 端口须在 1 至 65535 之间')
    }
    return url
  }))]
  const turnUrls = iceUrls.filter(isTurn).sort()
  if (!turnUrls.length) {
    return { signalingUrl, iceUrls }
  }
  const turnUsername = field(value.turnUsername, 'TURN 用户名', 512)?.trim()
  const sameTurn = turnUsername === previous?.turnUsername &&
    JSON.stringify(turnUrls) === JSON.stringify(previous?.iceUrls.filter(isTurn).sort())
  const turnPassword = field(value.turnPassword, 'TURN 密码', 4096) ?? (sameTurn ? previous?.turnPassword : undefined)
  if (!turnUsername || !turnPassword) {
    return invalid('TURN 地址需要填写用户名和密码')
  }
  return { signalingUrl, iceUrls, turnUsername, turnPassword }
}

function transport(client: Client): TransportConfig {
  return { signalingUrl: client.signalingUrl, localTest: client.signalingUrl.startsWith('ws:'), iceServers: client.iceUrls.map(url => ({
    urls: [url], ...(isTurn(url) && { username: client.turnUsername, credential: client.turnPassword }),
  })) }
}

function readSettings(file: string): Settings {
  let json: string
  try {
    if (realpathSync(file) !== file) {
      throw new Error('Mesh settings path redirected')
    }
    json = readFileSync(file, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return { peers: [], revocations: [], server: defaultManagedServerConfig() }
    }
    throw error
  }
  const raw = object(JSON.parse(json))
  if (raw?.version !== 1 || !Array.isArray(raw.peers) || !Array.isArray(raw.revocations)) {
    throw new Error('Invalid Mesh settings')
  }
  const client = raw.client === undefined ? undefined : readClient(object(raw.client) ?? {})
  const peers: Peer[] = raw.peers.map((candidate: unknown) => {
    const peer = object(candidate)
    if (!client || !isNodeId(peer?.nodeId) || typeof peer.publicKey !== 'string' || !isConnectionId(peer.pairId) ||
        peer.nodeId !== pairingNodeId(peer.publicKey)) {
      throw new Error('Invalid stored Mesh peer')
    }
    publicKey(peer.publicKey)
    return { nodeId: peer.nodeId, publicKey: peer.publicKey, pairId: peer.pairId }
  })
  if (new Set(peers.map(peer => peer.nodeId)).size !== peers.length) {
    throw new Error('Duplicate stored Mesh peer')
  }
  const revocations: Revocation[] = raw.revocations.map((candidate: unknown) => {
    const item = object(candidate)
    if (!isNodeId(item?.peerId) || !isConnectionId(item.pairId)) {
      throw new Error('Invalid stored Mesh revocation')
    }
    return { peerId: item.peerId, pairId: item.pairId, signalingUrl: signalAddress(item.signalingUrl).href }
  })
  return { client, peers, revocations, server: validateManagedServerConfig(raw.server) }
}

function maskedServer(config: ManagedServerConfig) {
  const { password, secret, ...auth } = config.ice.auth
  return { ...config, ice: { ...config.ice, auth: { ...auth, hasPassword: !!password, hasSecret: !!secret } } }
}

function serverInput(input: unknown, previous: ManagedServerConfig): ManagedServerConfig {
  const config = object(input)
  const ice = object(config?.ice)
  const auth = object(ice?.auth)
  if (!config || !ice || !auth) {
    return invalid('棱镜服务端配置格式无效')
  }
  const prior = previous.ice.auth
  const password = auth.mode === 'long-term'
    ? auth.password ?? (prior.mode === auth.mode && auth.realm === prior.realm && auth.username === prior.username ? prior.password : undefined)
    : undefined
  const secret = auth.mode === 'shared-secret'
    ? auth.secret ?? (prior.mode === auth.mode && auth.realm === prior.realm ? prior.secret : undefined)
    : undefined
  return validateManagedServerConfig({ ...config, ice: { ...ice, auth: { ...auth, password, secret } } })
}

/** 将托管配对与监听状态保存在当前配置档，不接触旧 Cordis 静态配置。 */
export class MeshAdministration {
  private readonly directory: string
  private readonly file: string
  private readonly lifetime = new AbortController()
  private readonly servers: ManagedMeshServers
  private readonly timer: NodeJS.Timeout
  private state: Settings
  private loadError?: string
  private serverError?: string
  private pairing: PairingView = { status: 'idle' }
  private join?: AbortController
  private opening?: Promise<void>
  private applying?: Promise<void>
  private retrying?: Promise<void>

  constructor(private readonly node: MeshNode, directory: string, private readonly report: (message: string) => void) {
    mkdirSync(directory, { recursive: true, mode: 0o700 })
    this.directory = realpathSync(directory)
    this.file = join(this.directory, 'settings.json')
    try {
      this.state = readSettings(this.file)
    } catch {
      this.state = { peers: [], revocations: [], server: defaultManagedServerConfig() }
      this.loadError = '无法读取棱镜连接配置，请检查配置档中的 Mesh 状态文件'
      this.report(this.loadError)
    }
    this.servers = new ManagedMeshServers(async (config, { host, port, tls }, onError) => {
      const service = createSignalingServer({ tls, localTest: config.localTest, pairingDirectory: this.directory })
      try {
        await new Promise<void>((resolve, reject) => {
          service.server.once('error', reject)
          service.server.listen(port, host, () => {
            service.server.removeListener('error', reject)
            service.server.on('error', onError)
            resolve()
          })
        })
        return service
      } catch (error) {
        await service.close().catch(() => this.report('棱镜信令启动失败后的清理未完成'))
        throw error
      }
    })
    if (!this.loadError && !node.staticMode && this.state.client) {
      try {
        for (const peer of this.state.peers) {
          this.node.addManagedPeer(peer.nodeId, peer.publicKey)
        }
        this.configureClient(this.state.client)
      } catch {
        for (const id of this.node.nodeIds) { this.node.removeManagedPeer(id) }
        this.loadError = '无法恢复已保存的棱镜配对，请检查配置档中的 Mesh 状态文件'
        this.report(this.loadError)
      }
    }
    this.applying = this.servers.apply(this.state.server).catch(error => {
      this.serverError = error instanceof MeshError ? error.message : '无法恢复棱镜监听服务'
      this.report(this.serverError)
    }).finally(() => { this.applying = undefined })
    this.timer = setInterval(() => this.reconnect(), 5_000).unref()
    this.reconnect()
  }

  private save(change: Partial<Settings>) {
    const next = { ...this.state, ...change }
    const temporary = join(this.directory, `.settings-${randomUUID()}.tmp`)
    try {
      writeFileSync(temporary, JSON.stringify({ version: 1, ...next }) + '\n', { mode: 0o600, flag: 'wx', flush: true })
      renameSync(temporary, this.file)
      this.state = next
    } catch {
      try { unlinkSync(temporary) } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
          this.report('无法清理棱镜设置临时文件')
        }
      }
      throw new MeshError(503, '无法写入棱镜连接配置')
    }
  }

  view() {
    const { client, server } = this.state
    const { signaling, ice } = this.servers.status()
    const states = [signaling.state, ice.state]
    const error = this.loadError ?? this.serverError ?? signaling.error ?? ice.error
    const status = error || states.includes('error') ? 'error' : states.includes('starting') ? 'starting'
      : states.includes('running') ? 'running' : 'stopped'
    return {
      nodeId: this.node.staticMode ? this.node.nodeId : this.node.managedIdentity().nodeId,
      mode: this.node.staticMode ? 'static' : 'managed',
      ...(this.node.staticMode ? { client: this.node.staticClient() } : client && { client: {
        signalingUrl: client.signalingUrl, iceUrls: client.iceUrls,
        turnUsername: client.turnUsername, hasTurnPassword: !!client.turnPassword,
      } }),
      pairing: this.loadError ? { status: 'error', error: this.loadError } : this.pairing,
      nodes: this.node.nodeIds.map(id => ({ id, status: this.node.peerStatus(id), managed: !this.node.staticMode })),
      server: { config: maskedServer(server), status, error },
    }
  }

  async execute(input: unknown) {
    const value = object(input)
    if (!value) { return invalid('无效的棱镜连接请求') }
    if (this.loadError || this.lifetime.signal.aborted) {
      throw new MeshError(503, this.loadError ?? '棱镜连接正在关闭')
    }
    switch (value.op) {
      case 'connect': this.startPairing(value); break
      case 'saveClient': this.saveClient(value); break
      case 'cancel': this.join?.abort(); this.pairing = { status: 'idle' }; break
      case 'forget': this.forget(value.nodeId); break
      case 'applyServer': await this.applyServer(value.config); break
      case 'issueTurnCredentials': return this.servers.issueTurnCredentials()
      default: return invalid('未知的棱镜连接操作')
    }
    return this.view()
  }

  private clientSettings(input: Record<string, unknown>): Client {
    if (this.node.staticMode) { throw new MeshError(409, '静态 Mesh 节点由 Cordis 配置管理') }
    if (this.opening) { throw new MeshError(409, '已有配对请求正在进行') }
    const client = readClient(input, this.state.client)
    if (this.state.peers.length && client.signalingUrl !== this.state.client?.signalingUrl) {
      throw new MeshError(409, '请先解除当前信令服务器的配对，再切换地址')
    }
    return client
  }

  private saveClient(input: Record<string, unknown>) {
    const client = this.clientSettings(input)
    this.save({ client })
    if (this.state.peers.length) {
      this.configureClient(client)
      this.reconnect()
    }
  }

  private startPairing(input: Record<string, unknown>) {
    const client = this.clientSettings(input)
    const code = field(input.code, '连接码', 64)?.replace(/[\s-]/gu, '').toLowerCase()
    if (!code || !/^[0-9a-f]{32}$/u.test(code)) {
      return invalid('请使用生成的 128 位连接码')
    }
    const identity = this.node.managedIdentity()
    const join = new AbortController()
    this.join = join
    this.pairing = { status: 'waiting' }
    const signal = AbortSignal.any([join.signal, this.lifetime.signal, AbortSignal.timeout(600_000)])
    this.opening = (async () => {
      const peer = await pairWithCode({ ...identity, url: new URL(client.signalingUrl), code, signal })
      signal.throwIfAborted()
      this.node.addManagedPeer(peer.nodeId, peer.publicKey)
      try {
        this.save({ client, peers: [...this.state.peers.filter(item => item.nodeId !== peer.nodeId), peer] })
      } catch (error) {
        if (!this.state.peers.some(item => item.nodeId === peer.nodeId)) { this.node.removeManagedPeer(peer.nodeId) }
        await revokePair({ ...identity, url: new URL(client.signalingUrl), peerId: peer.nodeId,
          pairId: peer.pairId, signal: AbortSignal.timeout(5_000) }).catch(() => this.report('无法撤销未保存的棱镜配对'))
        throw error
      }
      this.configureClient(client)
      this.pairing = { status: 'idle' }
      this.reconnect()
    })().catch(error => {
      if (join.signal.aborted || this.lifetime.signal.aborted) { return }
      this.pairing = { status: 'error', error: error instanceof MeshError ? error.message
        : '配对未完成，请核对两台设备的信令地址和连接码后重试' }
    }).finally(() => { this.join = undefined; this.opening = undefined })
  }

  private configureClient(client: Client) {
    this.node.configureManaged(transport(client), (id, pairId) => {
      if (!this.state.peers.some(peer => peer.nodeId === id && peer.pairId === pairId)) { return }
      this.node.removeManagedPeer(id)
      try {
        this.save({ peers: this.state.peers.filter(peer => peer.nodeId !== id) })
      } catch {
        const error = '节点已断开，无法保存撤权记录'
        this.pairing = { status: 'error', error }
        this.report(error)
      }
    })
  }

  private forget(id: unknown) {
    if (this.node.staticMode) { throw new MeshError(409, '静态 Mesh 节点由 Cordis 配置管理') }
    const peer = this.state.peers.find(peer => peer.nodeId === id)
    if (!peer || !this.state.client) {
      throw new MeshError(404, '找不到该配对节点')
    }
    const item = { signalingUrl: this.state.client.signalingUrl, peerId: peer.nodeId, pairId: peer.pairId }
    this.save({ peers: this.state.peers.filter(peer => peer.nodeId !== id), revocations: [...this.state.revocations, item] })
    this.node.removeManagedPeer(peer.nodeId)
    this.reconnect()
  }

  private reconnect() {
    if (this.node.staticMode || this.loadError || this.lifetime.signal.aborted) { return }
    for (const peer of this.state.peers) {
      if (this.node.peerStatus(peer.nodeId) === 'offline') {
        const signal = AbortSignal.any([this.lifetime.signal, AbortSignal.timeout(35_000)])
        // DataChannel 连接失败时节点保持离线，下一轮按相同公钥重连。
        void this.node.connectPeer(peer.nodeId, signal).catch(() => undefined)
      }
    }
    if (!this.retrying && this.state.revocations.length) {
      const identity = this.node.managedIdentity()
      this.retrying = (async () => {
        for (const item of this.state.revocations) {
          const signal = AbortSignal.any([this.lifetime.signal, AbortSignal.timeout(5_000)])
          try {
            await revokePair({ ...identity, url: new URL(item.signalingUrl), peerId: item.peerId, pairId: item.pairId, signal })
            this.save({ revocations: this.state.revocations.filter(entry => entry !== item) })
          } catch {
            // 服务器恢复连接后继续提交已在本地撤销的配对。
            if (this.lifetime.signal.aborted) { return }
          }
        }
      })().finally(() => { this.retrying = undefined })
    }
  }

  private async applyServer(input: unknown) {
    if (this.applying) { throw new MeshError(409, '服务端设置正在应用') }
    const previous = this.state.server
    const config = serverInput(input, previous)
    this.serverError = undefined
    this.applying = (async () => {
      await this.servers.apply(config)
      try { this.save({ server: config }) } catch (error) {
        await this.servers.apply(previous).catch(() => this.report('无法恢复上一次棱镜监听配置'))
        throw error
      }
    })()
    try {
      await this.applying
    } catch (error) {
      this.serverError = error instanceof MeshError ? error.message : '无法应用棱镜监听配置'
      throw error
    } finally {
      this.applying = undefined
    }
  }

  async close() {
    clearInterval(this.timer)
    this.lifetime.abort()
    await Promise.allSettled([this.applying, this.opening, this.retrying])
    await this.servers.close()
  }
}
