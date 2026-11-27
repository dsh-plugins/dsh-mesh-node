import { crc32 } from 'node:zlib'

const headerLength = 20
const magicCookie = 0x2112a442
const errorCode = 0x0009
const messageIntegrity = 0x0008
const nonce = 0x0015
const messageIntegritySha256 = 0x001c
const passwordAlgorithms = 0x8002
const fingerprint = 0x8028
const stunSecurityCookie = Buffer.from('obMatJos2')

/**
 * turn-server 只接受 MD5 派生的长期凭据，Werift 0.29 遇到算法列表则拒绝重试。
 * 仅省略 401/438 挑战中单独宣告 MD5 的可选属性，保留认证算法和所有签名消息。
 */
export function compatibleTurnChallenge(frame: Buffer): Buffer {
  if (frame.length < headerLength || frame.readUInt32BE(4) !== magicCookie
      || (frame.readUInt16BE(0) & 0xc110) !== 0x0110
      || frame.readUInt16BE(2) !== frame.length - headerLength) {
    return frame
  }
  let code: number | undefined
  let legacyNonce = false
  let algorithms: { offset: number; end: number } | undefined
  let fingerprintOffset: number | undefined
  for (let offset = headerLength; offset < frame.length;) {
    if (offset + 4 > frame.length) {
      return frame
    }
    const type = frame.readUInt16BE(offset)
    const length = frame.readUInt16BE(offset + 2)
    const value = offset + 4
    const end = value + Math.ceil(length / 4) * 4
    if (end > frame.length || type === messageIntegrity || type === messageIntegritySha256) {
      return frame
    }
    if (type === errorCode && length >= 4) {
      code = (frame[value + 2] & 7) * 100 + frame[value + 3]
    }
    if (type === nonce) {
      const prefix = frame.subarray(value, Math.min(value + length, value + stunSecurityCookie.length))
      if (!length || legacyNonce || prefix.equals(stunSecurityCookie)) {
        return frame
      }
      legacyNonce = true
    }
    if (type === passwordAlgorithms) {
      if (algorithms || length !== 4 || frame.readUInt16BE(value) !== 1 || frame.readUInt16BE(value + 2) !== 0) {
        return frame
      }
      algorithms = { offset, end }
    }
    if (type === fingerprint) {
      if (length !== 4 || end !== frame.length) {
        return frame
      }
      fingerprintOffset = offset
    }
    offset = end
  }
  if ((code !== 401 && code !== 438) || !legacyNonce || !algorithms) {
    return frame
  }
  const result = Buffer.concat([frame.subarray(0, algorithms.offset), frame.subarray(algorithms.end)])
  result.writeUInt16BE(result.length - headerLength, 2)
  if (fingerprintOffset !== undefined) {
    const offset = fingerprintOffset - (algorithms.end - algorithms.offset)
    result.writeUInt32BE((crc32(result.subarray(0, offset)) ^ 0x5354554e) >>> 0, offset + 4)
  }
  return result
}
