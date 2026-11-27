import type { IncomingMessage } from 'node:http'
import type { HostAPI } from '@dsh-plugin/dsh-loader'
import type { MeshAdministration } from './administration.js'
import { MeshError } from './protocol.js'

async function readRequest(req: IncomingMessage): Promise<unknown> {
  if (req.headers['content-type']?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
    throw new MeshError(400, '请提交 JSON 格式的连接设置')
  }
  const parts: Buffer[] = []
  let size = 0
  for await (const part of req.iterator({ destroyOnReturn: false })) {
    const bytes = Buffer.isBuffer(part) ? part : Buffer.from(part)
    size += bytes.length
    if (size > 32 * 1024) {
      req.resume()
      throw new MeshError(400, '连接设置超过请求大小上限')
    }
    parts.push(bytes)
  }
  try {
    return JSON.parse(Buffer.concat(parts).toString('utf8'))
  } catch {
    throw new MeshError(400, '连接设置不是有效的 JSON')
  }
}

/** 复用 DSH 属主鉴权，写操作还需同源请求头。 */
export function meshAdminRoute(admin: MeshAdministration): Parameters<HostAPI['web']['registerOwner']>[0] {
  return { kind: 'exact', path: '/prism/mesh/admin', async handler(req, res) {
    res.setHeader('Cache-Control', 'private, no-store')
    res.setHeader('Content-Type', 'application/json; charset=utf-8')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'no-referrer')
    const rawOrigin = req.headers.origin
    const origin = typeof rawOrigin === 'string' ? URL.parse(rawOrigin) : null
    const sameOrigin = origin && ['https:', 'http:'].includes(origin.protocol) && origin.host === req.headers.host
    if (req.headers['sec-fetch-site'] === 'cross-site' || (rawOrigin && !sameOrigin) ||
        (req.method === 'POST' && (!sameOrigin || req.headers['x-prism-request'] !== '1'))) {
      res.statusCode = 403
      res.end(JSON.stringify({ error: '只允许 DSH 属主从同源页面修改连接' }))
      return
    }
    if (req.method !== 'GET' && req.method !== 'POST') {
      res.writeHead(405, { Allow: 'GET, POST' }).end()
      return
    }
    try {
      const result = req.method === 'GET' ? admin.view() : await admin.execute(await readRequest(req))
      res.end(JSON.stringify(result))
    } catch (error) {
      res.statusCode = error instanceof MeshError ? error.status : 503
      res.end(JSON.stringify({ error: error instanceof MeshError ? error.message : '暂时无法访问棱镜连接设置' }))
    }
  } }
}
