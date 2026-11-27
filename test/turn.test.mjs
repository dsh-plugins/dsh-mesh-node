import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { once } from 'node:events'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createConnection, createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { connect, wire } from 'turn-server'
import { RTCPeerConnection } from 'werift'
import { defaultManagedServerConfig, ManagedMeshServers, validateManagedServerConfig } from '../dist/managed-server.js'
import { compatibleTurnChallenge } from '../dist/turn-challenge.js'
import { issueTurnCredentials } from '../dist/turn-server.js'

const address = '127.0.0.1'

async function occupiedPort() {
  const server = createServer()
  server.listen(0, address)
  await once(server, 'listening')
  return server
}

async function freePort() {
  const server = await occupiedPort()
  const { port } = server.address()
  await new Promise(resolve => server.close(resolve))
  return port
}

async function certificates(t) {
  const directory = await mkdtemp(join(tmpdir(), 'prism-turn-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  let openssl = process.env.PRISM_TEST_OPENSSL
  if (!openssl && process.platform === 'win32') {
    const git = execFileSync('where.exe', ['git'], { encoding: 'utf8' }).trim().split(/\r?\n/)[0]
    openssl = join(dirname(dirname(git)), 'usr', 'bin', 'openssl.exe')
  }
  const certFile = join(directory, 'cert.pem')
  const keyFile = join(directory, 'key.pem')
  execFileSync(openssl || 'openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-out', certFile, '-keyout', keyFile], { stdio: 'ignore', windowsHide: true })
  return { certFile, keyFile, ca: await readFile(certFile) }
}

function fixture(t) {
  const servers = new ManagedMeshServers(async () => { throw new Error('Unexpected signaling listener') })
  const sockets = new Set()
  t.after(async () => {
    for (const socket of sockets) {
      socket.close()
    }
    await servers.close()
  })
  const config = defaultManagedServerConfig()
  return {
    servers,
    config: { ...config, enabled: true, host: address, ice: { ...config.ice, enabled: true } },
    client(uri, options = {}) {
      return new Promise((resolve, reject) => {
        const socket = connect(uri, { autoRefresh: false, rto: 120, timeout: 2_500, ...options }, (error, connected) => {
          if (error) {
            reject(error)
          } else {
            resolve(connected)
          }
        })
        socket.on('error', reject)
        sockets.add(socket)
      })
    },
  }
}

function event(socket, eventName, action, map = value => value) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error(`TURN ${eventName} timed out`)), 3_500)
    function success(...values) { finish(null, map(...values)) }
    function failure(_message, error) { finish(error ?? new Error(`TURN ${eventName} failed`)) }
    function finish(error, value) {
      clearTimeout(timer)
      socket.off(eventName, success)
      socket.off(eventName.replace(':success', ':error'), failure)
      socket.off('error', finish)
      if (error) {
        reject(error)
      } else {
        resolve(value)
      }
    }
    socket.on(eventName, success)
    if (eventName.endsWith(':success')) {
      socket.on(eventName.replace(':success', ':error'), failure)
    }
    socket.on('error', finish)
    action()
  })
}

function binding(socket) {
  return event(socket, 'binding:success', () => socket.binding(),
    message => message.getAttribute(wire.ATTR.XOR_MAPPED_ADDRESS))
}

function allocate(socket) {
  return event(socket, 'allocate:success', () => socket.allocate({ lifetime: 60 }),
    message => message.getAttribute(wire.ATTR.XOR_RELAYED_ADDRESS))
}

async function release(socket) {
  const refreshed = `${wire.METHOD_NAME[wire.METHOD.REFRESH]}:success`
  await event(socket, refreshed, () => socket.refresh({ lifetime: 0 }))
  socket.close()
}

async function relayOnlyDataChannel(endpoint, credentials) {
  const options = {
    iceServers: [{ urls: endpoint, username: credentials.username, credential: credentials.password }],
    iceTransportPolicy: 'relay',
    iceUseDefaultStunServer: false,
    turnTlsOptions: { ca: credentials.ca, servername: 'localhost' },
  }
  const left = new RTCPeerConnection(options)
  const right = new RTCPeerConnection(options)
  const candidateErrors = []
  for (const peer of [left, right]) {
    peer.onIceCandidateError.subscribe(error => candidateErrors.push([error.errorCode, error.errorText]))
  }
  try {
    const sending = left.createDataChannel('mesh')
    const receiving = right.onDataChannel.asPromise(8_000)
    receiving.catch(() => undefined)
    await left.setLocalDescription(await left.createOffer())
    await right.setRemoteDescription(left.localDescription)
    await right.setLocalDescription(await right.createAnswer())
    await left.setRemoteDescription(right.localDescription)
    for (const peer of [left, right]) {
      const sdp = peer.localDescription.sdp
      assert.ok(/ typ relay\b/u.test(sdp), `${endpoint} did not gather a relay candidate: ${JSON.stringify(candidateErrors)}`)
      assert.ok(!/ typ (host|srflx)\b/u.test(sdp), endpoint)
    }
    const [sink] = await receiving
    if (sending.readyState !== 'open') {
      await sending.stateChanged.watch(state => state === 'open', 8_000)
    }
    const received = sink.onMessage.asPromise(8_000)
    sending.send('relay-only')
    assert.equal((await received)[0], 'relay-only', endpoint)
  } finally {
    await Promise.all([left.close(), right.close()])
  }
}

test('rejects ambiguous listener and NAT settings before applying them', () => {
  const config = defaultManagedServerConfig()
  config.enabled = true
  config.signaling = { enabled: true, localTest: true, port: 8080 }
  assert.equal(validateManagedServerConfig(config).host, '0.0.0.0')
  config.signaling.port = 8443
  assert.throws(() => validateManagedServerConfig(config), /8080/)
  config.signaling.port = 8080
  config.ice.enabled = true
  config.ice.port = 8080
  assert.throws(() => validateManagedServerConfig(config), /冲突/)
  config.ice.port = 3478
  config.ice.relay = true
  config.ice.behindNat = true
  config.ice.externalIp = '192.168.1.20'
  assert.throws(() => validateManagedServerConfig(config), /公网 IP/)
  config.ice.externalIp = '8.8.8.8'
  assert.throws(() => validateManagedServerConfig(config), /认证/)
})

test('preserves signed and modern TURN challenges while making legacy MD5 challenges compatible', () => {
  function challenge({ code = 401, nonce = 'abcdef:abcdef', algorithm = 1, integrity } = {}) {
    return Buffer.from(wire.encode_message({
      method: wire.METHOD.ALLOCATE,
      cls: wire.CLASS.ERROR,
      key: integrity && Buffer.alloc(16, 1),
      integrity,
      attributes: [
        { type: wire.ATTR.ERROR_CODE, value: { code } },
        { type: wire.ATTR.REALM, value: 'prism.test' },
        { type: wire.ATTR.NONCE, value: nonce },
        { type: wire.ATTR.PASSWORD_ALGORITHMS, value: [{ algorithm, params: new Uint8Array() }] },
      ],
    }).buf)
  }
  for (const code of [401, 438]) {
    const original = challenge({ code })
    const compatible = compatibleTurnChallenge(original)
    const message = wire.decode_message(compatible)
    assert.equal(message.getAttribute(wire.ATTR.ERROR_CODE).code, code)
    assert.equal(message.getAttribute(wire.ATTR.REALM), 'prism.test')
    assert.equal(message.getAttribute(wire.ATTR.NONCE), 'abcdef:abcdef')
    assert.ok(!message.getAttribute(wire.ATTR.PASSWORD_ALGORITHMS))
    assert.deepEqual(compatible.subarray(8, 20), original.subarray(8, 20))
    assert.ok(wire.check_fingerprint(compatible, message))
  }
  for (const unchanged of [challenge({ integrity: 'sha1' }), challenge({ integrity: 'sha256' }),
    challenge({ nonce: 'obMatJos2gAAAabcdef' }), challenge({ algorithm: 2 }), challenge({ code: 403 }),
    challenge({ nonce: '' }), challenge().subarray(0, 30)]) {
    assert.equal(compatibleTurnChallenge(unchanged), unchanged)
  }
})

test('STUN-only answers Binding over UDP and TCP, denies allocations and recovers from a bind conflict', { timeout: 20_000 }, async t => {
  const { servers, config, client } = fixture(t)
  config.ice.port = await freePort()
  await servers.apply(config)
  for (const transport of ['udp', 'tcp']) {
    const socket = await client(`stun:${address}:${config.ice.port}?transport=${transport}`)
    assert.equal((await binding(socket)).ip, address)
    await assert.rejects(allocate(socket), error => error?.code === 403)
    socket.close()
  }
  const occupied = await occupiedPort()
  t.after(() => new Promise(resolve => occupied.close(resolve)))
  const old = await client(`stun:${address}:${config.ice.port}?transport=tcp`)
  await assert.rejects(servers.apply({ ...config, ice: { ...config.ice, port: occupied.address().port } }), /端口已被占用/)
  old.close()
  assert.equal(servers.status().ice.state, 'running')
  const restored = await client(`stun:${address}:${config.ice.port}?transport=udp`)
  assert.equal((await binding(restored)).ip, address)
})

test('TURN relays across UDP, TCP, TLS and DTLS and closes live streams on shutdown', { timeout: 40_000 }, async t => {
  const { servers, config, client } = fixture(t)
  const { ca, certFile, keyFile } = await certificates(t)
  config.ice = {
    ...config.ice, relay: true, port: await freePort(), tlsPort: await freePort(), certFile, keyFile,
    auth: { mode: 'long-term', realm: 'prism.test', username: 'test-node', password: 'example-only-password' },
  }
  if (config.ice.port === config.ice.tlsPort) {
    config.ice.tlsPort = await freePort()
  }
  const credentials = { username: config.ice.auth.username, password: config.ice.auth.password, ca, servername: 'localhost' }
  await servers.apply(config)
  const uri = [
    `turn:${address}:${config.ice.port}?transport=udp`,
    `turn:${address}:${config.ice.port}?transport=tcp`,
    `turns:${address}:${config.ice.tlsPort}?transport=tcp`,
    `turns:${address}:${config.ice.tlsPort}?transport=udp`,
  ]
  const receiver = await client(uri[0], credentials)
  const receiveAddress = await allocate(receiver)
  for (const endpoint of uri) {
    const sender = await client(endpoint, credentials)
    const senderAddress = await allocate(sender)
    assert.ok(senderAddress.port >= config.ice.minPort && senderAddress.port <= config.ice.maxPort, endpoint)
    const permissions = `${wire.METHOD_NAME[wire.METHOD.CREATE_PERMISSION]}:success`
    await event(receiver, permissions, () => receiver.createPermission(senderAddress))
    await event(sender, permissions, () => sender.createPermission(receiveAddress))
    const data = await event(receiver, 'data', () => sender.send(receiveAddress, Buffer.from('mesh-turn')), (_peer, bytes) => bytes)
    assert.equal(Buffer.from(data).toString(), 'mesh-turn')
    await release(sender)
  }
  await release(receiver)
  for (const endpoint of uri.slice(0, 3)) {
    await relayOnlyDataChannel(endpoint, credentials)
  }
  const raw = createConnection(config.ice.tlsPort, address)
  await once(raw, 'connect')
  const closed = once(raw, 'close')
  await servers.close()
  await closed
  assert.equal(servers.status().ice.state, 'stopped')
})

test('shared-secret credentials allocate until expiry', { timeout: 20_000 }, async t => {
  const { servers, config, client } = fixture(t)
  const secret = 'turn-test-secret-used-only-in-this-fixture'
  config.ice = {
    ...config.ice, relay: true, port: await freePort(),
    auth: { mode: 'shared-secret', realm: 'prism.test', secret },
  }
  const uri = `turn:${address}:${config.ice.port}?transport=udp`
  await servers.apply(config)
  const valid = await client(uri, servers.issueTurnCredentials())
  assert.equal((await allocate(valid)).ip, address)
  const expired = await client(uri, issueTurnCredentials(secret, Date.now() - 7_200_000))
  await assert.rejects(allocate(expired), error => error?.code === 401)
})
