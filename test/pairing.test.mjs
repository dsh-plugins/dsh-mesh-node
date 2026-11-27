import assert from 'node:assert/strict'
import { generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto'
import { EventEmitter, once } from 'node:events'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import WebSocket from 'ws'
import { checkSignature, publicKey } from '../dist/identity.js'
import { pairWithCode, revokePair } from '../dist/pairing-client.js'
import { joinData, pairingNodeId, pairingPath, pairingSecrets, pairingTimeout, pairProof,
  pairTranscript, proofData } from '../dist/pairing-protocol.js'
import { SignalSocket } from '../dist/signal-socket.js'
import { createSignalingServer } from '../dist/signaling.js'
import { signalingPath } from '../dist/signaling-protocol.js'
import { meshCertificate } from './network-fixture.mjs'

function device() {
  const keys = generateKeyPairSync('ed25519')
  const pin = keys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url')
  return {
    nodeId: pairingNodeId(pin), publicKey: pin,
    sign(data) { return sign(null, Buffer.from(data), keys.privateKey).toString('base64url') },
  }
}

async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'prism-pairing-'))
  const { cert, tls } = await meshCertificate(dir)
  const pairingDirectory = join(dir, 'data')
  let server
  let url
  const socketCleanup = []
  const setup = async () => {
    await server?.close()
    server = createSignalingServer({ tls, pairingDirectory })
    server.server.listen(0, '127.0.0.1')
    await once(server.server, 'listening')
    url = new URL(`wss://127.0.0.1:${server.server.address().port}${signalingPath}`)
  }
  t.after(async () => {
    for (const close of socketCleanup) {
      close()
    }
    await server?.close()
    await rm(dir, { recursive: true, force: true })
  })
  await setup()
  function details(member, signal = AbortSignal.timeout(6_000)) { return { ...member, url, ca: cert, signal } }
  function dial(member, code, signal) { return pairWithCode({ ...details(member, signal), code }) }
  function signedSocket(member, pins) {
    const events = new EventEmitter()
    const keys = new Map(pins.map(peer => [peer.nodeId, publicKey(peer.publicKey)]))
    const socket = new SignalSocket(member.nodeId, url, {
      sign: member.sign,
      verify: (nodeId, data, signature) => {
        const key = keys.get(nodeId)
        return !!key && checkSignature(key, data, signature)
      },
    }, packet => events.emit('signal:' + packet.connectionId, packet), cert,
    (other, pairId) => events.emit('revoked', other, pairId))
    socketCleanup.push(() => socket.close())
    const send = (target, id = randomUUID()) => socket.send('dial', target.nodeId, id, '', AbortSignal.timeout(6_000))
    return { events, send, close: () => socket.close() }
  }
  function connectRaw() {
    const socket = new WebSocket(new URL(pairingPath, url), { ca: tls.cert })
    socketCleanup.push(() => socket.terminate())
    return socket
  }
  return { setup, dial, details, signedSocket, connectRaw }
}

const code = () => randomBytes(16).toString('hex')

function next(socket) {
  return once(socket, 'message', { signal: AbortSignal.timeout(6_000) }).then(([data]) => JSON.parse(data.toString()))
}

async function rawJoin(network, current, value) {
  const socket = network.connectRaw()
  const { challenge } = await next(socket)
  const participant = { nodeId: current.nodeId, publicKey: current.publicKey, nonce: randomUUID() }
  const { lookup } = pairingSecrets(value)
  const response = next(socket)
  socket.send(JSON.stringify({ kind: 'join', ...participant, lookup,
    signature: current.sign(joinData(challenge, lookup, participant)) }))
  return { socket, response, lookup, participant }
}

test('same-code peers authenticate each other, persist their grants and cannot signal across pairs', { timeout: 20_000 }, async t => {
  const network = await fixture(t)
  const [first, second, third, fourth] = Array.from({ length: 4 }, device)
  const value = code()
  const [firstPeer, secondPeer] = await Promise.all([
    network.dial(first, value), network.dial(second, value.toUpperCase().match(/.{4}/gu).join('-')),
  ])
  assert.deepEqual(firstPeer, { nodeId: second.nodeId, publicKey: second.publicKey, pairId: secondPeer.pairId })
  assert.deepEqual(secondPeer, { nodeId: first.nodeId, publicKey: first.publicKey, pairId: firstPeer.pairId })
  assert.deepEqual(await network.dial(first, value), firstPeer)
  await assert.rejects(network.dial(third, value), /已使用/u)

  const otherCode = code()
  await Promise.all([network.dial(third, otherCode), network.dial(fourth, otherCode)])
  await network.setup()
  const left = network.signedSocket(first, [second])
  const right = network.signedSocket(second, [first])
  const unrelated = network.signedSocket(third, [first, fourth])
  await Promise.all([left.send(second), right.send(first), unrelated.send(fourth)])
  const marker = randomUUID()
  const accepted = once(right.events, 'signal:' + marker, { signal: AbortSignal.timeout(6_000) })
  await left.send(second, marker)
  const [packet] = await accepted
  assert.equal(packet.connectionId, marker)
  const blockedMarker = randomUUID()
  const blocked = assert.rejects(once(unrelated.events, 'signal:' + blockedMarker, { signal: AbortSignal.timeout(300) }), { name: 'AbortError' })
  await left.send(third, blockedMarker)
  await blocked

  await assert.rejects(revokePair({ ...network.details(third), peerId: first.nodeId, pairId: firstPeer.pairId }), /拒绝/u)
  const revoked = once(right.events, 'revoked', { signal: AbortSignal.timeout(6_000) })
  const request = { ...network.details(first), peerId: second.nodeId, pairId: firstPeer.pairId }
  await revokePair(request)
  assert.deepEqual(await revoked, [first.nodeId, firstPeer.pairId])
  await revokePair(request)
  const retiredMarker = randomUUID()
  const retired = assert.rejects(once(right.events, 'signal:' + retiredMarker, { signal: AbortSignal.timeout(300) }), { name: 'AbortError' })
  await left.send(second, retiredMarker)
  await retired

  left.close()
  right.close()
  unrelated.close()
  await network.setup()
  const restarted = network.signedSocket(second, [first])
  assert.deepEqual(await once(restarted.events, 'revoked', { signal: AbortSignal.timeout(6_000) }),
    [first.nodeId, firstPeer.pairId])
  await assert.rejects(network.dial(first, value), /已使用/u)
})

test('a third device cannot enter a matched code and cannot forge a shared-code proof', { timeout: 15_000 }, async t => {
  const network = await fixture(t)
  const [first, second, third] = Array.from({ length: 3 }, device)
  const value = code()
  const raw = await rawJoin(network, second, value)
  assert.equal((await raw.response).kind, 'waiting')
  const match = next(raw.socket)
  const joining = network.dial(first, value)
  void joining.catch(() => undefined)
  const { pairId, peer } = await match
  const transcript = pairTranscript(pairId, raw.lookup, raw.participant, peer)
  await assert.rejects(network.dial(third, value), /已有两台设备/u)
  const proof = pairProof(pairingSecrets(code()).proofKey, transcript, second.nodeId)
  raw.socket.send(JSON.stringify({ kind: 'proof', pairId, proof,
    signature: second.sign(proofData(transcript, second.nodeId, proof)) }))
  await assert.rejects(joining, /身份验证失败/u)
})

test('different connection codes remain separate and waiting attempts expire or can be cancelled', { timeout: 15_000 }, async t => {
  const network = await fixture(t)
  const [first, second] = Array.from({ length: 2 }, device)
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const [left, right] = await Promise.all([rawJoin(network, first, code()), rawJoin(network, second, code())])
  assert.equal((await left.response).kind, 'waiting')
  assert.equal((await right.response).kind, 'waiting')
  const leftExpiry = next(left.socket)
  const rightExpiry = next(right.socket)
  t.mock.timers.tick(pairingTimeout)
  assert.deepEqual(await leftExpiry, { kind: 'pair-error', code: 'expired' })
  assert.deepEqual(await rightExpiry, { kind: 'pair-error', code: 'expired' })
  t.mock.timers.reset()
  const cancellation = new AbortController()
  const pending = network.dial(first, code(), cancellation.signal)
  cancellation.abort()
  await assert.rejects(pending, { name: 'AbortError' })
})
