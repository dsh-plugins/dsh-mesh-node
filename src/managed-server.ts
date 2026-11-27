import { readFile } from 'node:fs/promises'
import { BlockList, isIP } from 'node:net'
import { isAbsolute } from 'node:path'
import { createSecureContext } from 'node:tls'
import { MeshError } from './protocol.js'
import { object } from './signaling-protocol.js'
import { issueTurnCredentials, startManagedTurn } from './turn-server.js'
import type { ManagedIceConfig, ManagedListener } from './turn-server.js'

/** 属主管理的信令监听设置。回环测试模式不读取证书。 */
export interface ManagedSignalConfig {
  enabled: boolean
  port: number
  localTest: boolean
  certFile?: string
  keyFile?: string
}

/** 一个 Profile 同时管理的两项监听服务。 */
export interface ManagedServerConfig {
  enabled: boolean
  host: string
  signaling: ManagedSignalConfig
  ice: ManagedIceConfig
}

const services = ['signaling', 'ice'] as const
type Service = typeof services[number]
type State = { state: 'stopped' | 'starting' | 'running' | 'error'; error?: string }

/** 可返回浏览器的监听状态，省略私密配置。 */
export type ManagedServerStatus = Record<Service, State>

interface TlsMaterial { cert: Buffer; key: Buffer }
type StartSignal = (config: ManagedSignalConfig, listener: {
  host: string
  port: number
  tls?: TlsMaterial
}, onError: (error: Error) => void) => Promise<ManagedListener>
type StartListener = (onError: (error: Error) => void) => Promise<ManagedListener>

const labels = { signaling: '信令服务', ice: 'STUN/TURN 服务' }
const privateAddress = new BlockList()
for (const [address, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 3],
] as const) {
  privateAddress.addSubnet(address, prefix)
}
const globalV6 = new BlockList()
globalV6.addSubnet('2000::', 3, 'ipv6')
privateAddress.addSubnet('2001:db8::', 32, 'ipv6')

/** 首次打开页面时不启动网络监听。 */
export function defaultManagedServerConfig(): ManagedServerConfig {
  return {
    enabled: false, host: '0.0.0.0',
    signaling: { enabled: false, port: 8443, localTest: false },
    ice: {
      enabled: false, port: 3478, relay: false, minPort: 49152, maxPort: 49251, behindNat: false,
      auth: { mode: 'long-term', realm: 'prism' },
    },
  }
}

function invalid(message: string): never {
  throw new MeshError(400, message)
}

function flag(value: unknown, label: string): boolean {
  return typeof value === 'boolean' ? value : invalid(`${label}必须是开关`)
}

function port(value: unknown, label: string): number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= 65_535
    ? value : invalid(`${label}必须是 1 至 65535 的整数`)
}

function optionalText(value: unknown, label: string, limit = 4_096): string | undefined {
  if (value === undefined || value === null || value === '') {
    return undefined
  }
  return typeof value === 'string' && Buffer.byteLength(value) <= limit && !/[\x00-\x1f\x7f]/.test(value)
    ? value : invalid(`${label}格式无效`)
}

/** 校验持久化配置和属主请求，关闭的监听器可保留编辑中的参数。 */
export function validateManagedServerConfig(input: unknown): ManagedServerConfig {
  const value = object(input)
  const signaling = object(value?.signaling)
  const ice = object(value?.ice)
  const auth = object(ice?.auth)
  if (!value || !signaling || !ice || !auth || (auth.mode !== 'long-term' && auth.mode !== 'shared-secret')) {
    return invalid('棱镜服务端配置格式无效')
  }
  const host = optionalText(value.host, '监听地址')?.trim()
  if (!host || !isIP(host)) {
    return invalid('监听地址必须是 IPv4 或 IPv6 地址')
  }
  const config: ManagedServerConfig = {
    enabled: flag(value.enabled, '作为服务端'), host,
    signaling: {
      enabled: flag(signaling.enabled, '信令服务'), port: port(signaling.port, '信令端口'),
      localTest: flag(signaling.localTest, '信令本地测试模式'),
      certFile: optionalText(signaling.certFile, '信令证书路径'), keyFile: optionalText(signaling.keyFile, '信令私钥路径'),
    },
    ice: {
      enabled: flag(ice.enabled, 'STUN/TURN 服务'), port: port(ice.port, 'STUN/TURN 控制端口'),
      relay: flag(ice.relay, 'TURN 中继'), behindNat: flag(ice.behindNat, 'NAT 部署'),
      tlsPort: ice.tlsPort === undefined || ice.tlsPort === null ? undefined : port(ice.tlsPort, 'TURN TLS/DTLS 端口'),
      minPort: port(ice.minPort, '中继起始端口'), maxPort: port(ice.maxPort, '中继结束端口'),
      externalIp: optionalText(ice.externalIp, 'TURN 公网 IP')?.trim(),
      certFile: optionalText(ice.certFile, 'TURN 证书路径'), keyFile: optionalText(ice.keyFile, 'TURN 私钥路径'),
      auth: {
        mode: auth.mode, realm: optionalText(auth.realm, 'TURN realm', 256)?.trim() ?? '',
        username: optionalText(auth.username, 'TURN 用户名', 512), password: optionalText(auth.password, 'TURN 密码'),
        secret: optionalText(auth.secret, 'TURN 共享密钥'),
      },
    },
  }
  if (!config.enabled) {
    return config
  }
  const signal = config.signaling
  const relay = config.ice
  if (signal.enabled) {
    if (signal.localTest && signal.port !== 8080) {
      return invalid('无 TLS 的信令测试只允许回环地址与 8080 端口')
    }
    if (!signal.localTest) {
      requireCertificate(signal, labels.signaling)
    }
  }
  if (!relay.enabled) {
    return config
  }
  const sharedAddress = !signal.localTest || ['0.0.0.0', '::', '127.0.0.1'].includes(host)
  if (signal.enabled && sharedAddress && (signal.port === relay.port || relay.relay && signal.port === relay.tlsPort)) {
    return invalid('信令端口与 STUN/TURN 控制端口冲突')
  }
  if (relay.relay) {
    const { minPort, maxPort, externalIp, behindNat, tlsPort, auth } = relay
    if (minPort > maxPort || [relay.port, tlsPort].some(p => p !== undefined && p >= minPort && p <= maxPort)) {
      return invalid('TURN 中继端口范围无效或与控制端口冲突')
    }
    if (externalIp || behindNat) {
      const ip = externalIp ?? ''
      const family = isIP(ip)
      if (family === 0 || family === 4 && privateAddress.check(ip)
          || family === 6 && (!globalV6.check(ip, 'ipv6') || privateAddress.check(ip, 'ipv6'))) {
        return invalid('TURN 外部地址必须是有效的公网 IP')
      }
    }
    if (!auth.realm || (auth.mode === 'shared-secret' ? !auth.secret : !auth.username || !auth.password)) {
      return invalid('TURN 中继必须配置 realm 及对应认证凭据')
    }
    if (tlsPort !== undefined) {
      if (tlsPort === relay.port) {
        return invalid('TURN TLS/DTLS 端口与控制端口冲突')
      }
      requireCertificate(relay, 'TURN TLS/DTLS')
    }
  }
  return config
}

function requireCertificate(config: { certFile?: string; keyFile?: string }, name: string): void {
  if (!config.certFile || !config.keyFile || !isAbsolute(config.certFile) || !isAbsolute(config.keyFile)) {
    invalid(`${name}需要绝对的 TLS 证书和私钥路径`)
  }
}

async function loadCertificate(config: { certFile?: string; keyFile?: string }, name: string): Promise<TlsMaterial> {
  try {
    const [cert, key] = await Promise.all([readFile(config.certFile!), readFile(config.keyFile!)])
    createSecureContext({ cert, key })
    return { cert, key }
  } catch {
    throw new MeshError(400, `${name}的 TLS 证书或私钥不可用`)
  }
}

function enabled(config: ManagedServerConfig, service: Service): boolean {
  return config.enabled && config[service].enabled
}

function serviceKey(config: ManagedServerConfig, service: Service): string {
  const host = service === 'signaling' && config.signaling.localTest ? '127.0.0.1' : config.host
  return enabled(config, service) ? JSON.stringify([host, config[service]]) : ''
}

function serviceFailure(service: Service, error: unknown): string {
  switch ((error as NodeJS.ErrnoException | undefined)?.code) {
    case 'EADDRINUSE': return `${labels[service]}的监听端口已被占用`
    case 'EADDRNOTAVAIL': return `${labels[service]}的监听地址在本机不可用`
    case 'EACCES': return `没有权限监听${labels[service]}端口`
    default: return `${labels[service]}启动或运行失败`
  }
}

interface Running {
  start: StartListener
  listener: ManagedListener
}

/** 串行应用监听配置，失败时重新启动受影响的旧监听服务。 */
export class ManagedMeshServers {
  private config = defaultManagedServerConfig()
  private readonly running: Partial<Record<Service, Running>> = {}
  private readonly phases: ManagedServerStatus = { signaling: { state: 'stopped' }, ice: { state: 'stopped' } }
  private pending = Promise.resolve()
  private stopping?: Promise<void>

  constructor(private readonly startSignal: StartSignal) {}

  status(): ManagedServerStatus {
    return { signaling: { ...this.phases.signaling }, ice: { ...this.phases.ice } }
  }

  async apply(input: unknown): Promise<void> {
    if (this.stopping) {
      throw new MeshError(503, '棱镜服务正在关闭')
    }
    const next = validateManagedServerConfig(input)
    return this.queue(() => this.change(next))
  }

  issueTurnCredentials() {
    const { auth, relay } = this.config.ice
    if (!relay || this.phases.ice.state !== 'running' || auth.mode !== 'shared-secret' || !auth.secret) {
      throw new MeshError(409, '请先启动使用共享密钥认证的 TURN 中继')
    }
    return issueTurnCredentials(auth.secret)
  }

  close(): Promise<void> {
    this.stopping ??= this.queue(async () => {
      const results = await Promise.allSettled(services.map(service => this.stop(service)))
      const failures = results.filter(result => result.status === 'rejected')
      if (failures.length) {
        throw new AggregateError(failures.map(value => value.reason), '棱镜监听服务关闭失败')
      }
    })
    return this.stopping
  }

  private queue(callback: () => Promise<void>): Promise<void> {
    const operation = this.pending.then(callback)
    this.pending = operation.catch(() => undefined)
    return operation
  }

  private async prepare(config: ManagedServerConfig, service: Service): Promise<StartListener | undefined> {
    if (!enabled(config, service)) {
      return undefined
    }
    if (service === 'signaling') {
      const signal = config.signaling
      const tls = signal.localTest ? undefined : await loadCertificate(signal, labels.signaling)
      const host = signal.localTest ? '127.0.0.1' : config.host
      return onError => this.startSignal(signal, { host, port: signal.port, tls }, onError)
    }
    const ice = config.ice
    const tls = ice.relay && ice.tlsPort !== undefined ? await loadCertificate(ice, 'TURN TLS/DTLS') : undefined
    return onError => startManagedTurn(ice, config.host, tls, onError)
  }

  private async stop(service: Service): Promise<void> {
    const active = this.running[service]
    if (active) {
      await active.listener.close()
      delete this.running[service]
    }
    this.phases[service] = { state: 'stopped' }
  }

  private async start(service: Service, desired: StartListener): Promise<void> {
    this.phases[service] = { state: 'starting' }
    try {
      const listener = await desired(error => {
        const active = this.running[service]
        if (active?.start !== desired) {
          return
        }
        this.phases[service] = { state: 'error', error: serviceFailure(service, error) }
      })
      this.running[service] = { start: desired, listener }
      this.phases[service] = { state: 'running' }
    } catch (error) {
      this.phases[service] = { state: 'error', error: serviceFailure(service, error) }
      throw new MeshError(503, this.phases[service].error!)
    }
  }

  private async change(next: ManagedServerConfig): Promise<void> {
    const changes = services.filter(service => serviceKey(next, service) !== serviceKey(this.config, service)
      || this.phases[service].state !== (enabled(next, service) ? 'running' : 'stopped'))
    const prepared = await Promise.all(changes.map(service => this.prepare(next, service)))
    const previous = { ...this.running }
    const touched: Service[] = []
    try {
      for (const service of changes) {
        touched.push(service)
        await this.stop(service)
      }
      for (const [index, service] of changes.entries()) {
        const start = prepared[index]
        if (start) {
          await this.start(service, start)
        }
      }
      this.config = next
    } catch (error) {
      const failed = { ...this.phases }
      const results = await Promise.allSettled(touched.map(async service => {
        const old = previous[service]
        const active = this.running[service]
        if (active && active !== old) {
          await this.stop(service)
        }
        if (old && !this.running[service]) {
          await this.start(service, old.start)
        } else if (!old) {
          this.phases[service] = failed[service].state === 'error' ? failed[service] : { state: 'stopped' }
        }
      }))
      if (results.some(result => result.status === 'rejected')) {
        throw new MeshError(503, '棱镜服务配置应用失败，部分旧监听未能恢复')
      }
      throw error
    }
  }
}
