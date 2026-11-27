#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import { isLoopbackAddress } from './pairing-protocol.js'
import { createSignalingServer } from './signaling.js'
import { object, signalingPath } from './signaling-protocol.js'

const { values } = parseArgs({
  options: { config: { type: 'string' }, help: { type: 'boolean' } },
})
if (values.help) {
  console.log('dsh-prism-mesh-signaling --config <signaling.json>')
} else {
  if (!values.config) {
    throw new Error('Use --config to specify the Mesh signaling configuration')
  }
  const file = resolve(values.config)
  const config = object(JSON.parse(await readFile(file, 'utf8')))
  const nodes = object(config?.nodes)
  const pairingDirectory = typeof config?.pairingDirectory === 'string' && config.pairingDirectory.trim() ? config.pairingDirectory : undefined
  const localTest = config?.localTest === true
  const host = typeof config?.host === 'string' ? config.host : '127.0.0.1'
  if ((!nodes && !pairingDirectory) ||
      (!localTest && (typeof config?.certFile !== 'string' || typeof config.keyFile !== 'string'))
      || typeof config.port !== 'number' || !Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
    throw new Error('Mesh signaling requires static nodes or a pairing directory, a TCP port and TLS files')
  }
  if (localTest && (config.port !== 8080 || !isLoopbackAddress(host))) {
    throw new Error('Plain Mesh signaling is only available for loopback testing on port 8080')
  }
  const resolveFile = (path: string) => resolve(dirname(file), path)
  const signaling = createSignalingServer({
    tls: localTest ? undefined : {
      cert: await readFile(resolveFile(config.certFile as string)),
      key: await readFile(resolveFile(config.keyFile as string)),
    },
    localTest,
    pairingDirectory: pairingDirectory && resolveFile(pairingDirectory),
    nodes: nodes as Record<string, string> | undefined,
    path: typeof config.path === 'string' ? config.path : signalingPath,
  })
  signaling.server.listen(config.port, host)
  const close = () => { void signaling.close().catch(error => { console.error(error); process.exitCode = 1 }) }
  process.once('SIGINT', close)
  process.once('SIGTERM', close)
}
