import { execFileSync } from 'node:child_process'
import { generateKeyPairSync, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { createSignalingServer } from '../dist/signaling.js'

export async function meshNetwork(t, grants, ice = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'prism-webrtc-'))
  const cleanup = []
  t.after(async () => {
    try {
      await Promise.all(cleanup.map(close => close()))
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
  let openssl = process.env.PRISM_TEST_OPENSSL
  if (!openssl) {
    if (process.platform === 'win32') {
      const git = execFileSync('where.exe', ['git'], { encoding: 'utf8' }).trim().split(/\r?\n/)[0]
      openssl = join(dirname(dirname(git)), 'usr', 'bin', 'openssl.exe')
    } else {
      openssl = 'openssl'
    }
  }
  const cert = join(dir, 'cert.pem')
  const key = join(dir, 'key.pem')
  execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-out', cert, '-keyout', key], { stdio: 'ignore', windowsHide: true })
  const pins = {}
  const privateKeys = {}
  const env = {}
  for (const nodeId of Object.keys(grants)) {
    const pair = generateKeyPairSync('ed25519')
    pins[nodeId] = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url')
    privateKeys[nodeId] = 'PRISM_TEST_' + randomUUID().replaceAll('-', '')
    env[privateKeys[nodeId]] = pair.privateKey.export({ type: 'pkcs8', format: 'pem' })
    process.env[privateKeys[nodeId]] = env[privateKeys[nodeId]]
  }
  const signal = createSignalingServer({
    tls: { cert: await readFile(cert), key: await readFile(key) },
    nodes: pins,
  })
  signal.server.listen(0, '127.0.0.1')
  await once(signal.server, 'listening')
  let stopped
  const closeSignaling = () => stopped ??= signal.close()
  cleanup.push(async () => {
    for (const name of Object.values(privateKeys)) {
      delete process.env[name]
    }
    await closeSignaling()
  })
  const url = 'wss://127.0.0.1:' + signal.server.address().port + '/prism/mesh/signaling/v2'
  return {
    env, pins, url, closeSignaling,
    cleanup(close) { cleanup.unshift(close) },
    config(nodeId) {
      return {
        nodeId, stateDirectory: join(dir, nodeId),
        webrtc: { signalingUrl: url, signalingCaFile: cert, privateKeyEnv: privateKeys[nodeId], ...ice },
        peers: Object.entries(grants[nodeId]).map(([id, projects]) => ({ id, publicKey: pins[id], projects })),
      }
    },
  }
}
