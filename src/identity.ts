import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

export function publicKey(pin: string): KeyObject {
  if (typeof pin !== 'string' || !/^[A-Za-z0-9_-]+$/.test(pin) || pin.length > 128) {
    throw new Error('Invalid Mesh Ed25519 public key')
  }
  const key = createPublicKey({ key: Buffer.from(pin, 'base64url'), format: 'der', type: 'spki' })
  if (key.asymmetricKeyType !== 'ed25519' || key.export({ format: 'der', type: 'spki' }).toString('base64url') !== pin) {
    throw new Error('Invalid Mesh Ed25519 public key')
  }
  return key
}

export function checkSignature(key: KeyObject, data: string, signature: string): boolean {
  return typeof signature === 'string' && /^[A-Za-z0-9_-]{86}$/.test(signature)
    && verify(null, Buffer.from(data), key, Buffer.from(signature, 'base64url'))
}

function privateKey(pem: string): KeyObject {
  const key = createPrivateKey(pem)
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error('Mesh signing key must use Ed25519')
  }
  return key
}

function localKey(directory: string): KeyObject {
  mkdirSync(directory, { recursive: true, mode: 0o700 })
  const file = join(directory, 'identity.pem')
  try {
    return privateKey(readFileSync(file, 'utf8'))
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw error
    }
  }
  const key = generateKeyPairSync('ed25519').privateKey
  try {
    writeFileSync(file, key.export({ format: 'pem', type: 'pkcs8' }), { flag: 'wx', mode: 0o600 })
    return key
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
      throw error
    }
    return privateKey(readFileSync(file, 'utf8'))
  }
}

/** 远端身份由运维固定公钥，本机单节点 Room 使用保存在状态目录的密钥。 */
export class MeshIdentity {
  private key?: KeyObject
  private ownPublic?: KeyObject

  constructor(private readonly nodeId: string, private readonly directory: string,
    private readonly peers: ReadonlyMap<string, KeyObject>, privateKeyEnv?: string) {
    if (privateKeyEnv !== undefined) {
      const secret = process.env[privateKeyEnv]
      if (!secret) {
        throw new Error('Missing Mesh signing key in ' + privateKeyEnv)
      }
      this.key = privateKey(secret)
    }
  }

  sign(data: string): string {
    return sign(null, Buffer.from(data), this.key ??= localKey(this.directory)).toString('base64url')
  }

  /** 配对公开已用于本配置档的签名身份。 */
  pin(): string {
    const key = this.ownPublic ??= createPublicKey(this.key ??= localKey(this.directory))
    return key.export({ format: 'der', type: 'spki' }).toString('base64url')
  }

  verify(nodeId: string, data: string, signature: string): boolean {
    const key = nodeId === this.nodeId
      ? this.ownPublic ??= createPublicKey(this.key ??= localKey(this.directory))
      : this.peers.get(nodeId)
    return key !== undefined && checkSignature(key, data, signature)
  }
}
