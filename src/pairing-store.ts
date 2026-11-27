import { closeSync, mkdirSync, openSync } from 'node:fs'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { publicKey } from './identity.js'
import type { KeyObject } from 'node:crypto'
import { decodeReceipt, decodeRevocation, pairingTimeout } from './pairing-protocol.js'
import type { PairReceipt, PairRevocation } from './pairing-protocol.js'

function ordered(first: string, second: string): [string, string] {
  return first < second ? [first, second] : [second, first]
}

/** 信令持久保存公钥和配对边，不持有配对码或设备私钥。 */
export class PairingStore {
  private readonly db: DatabaseSync
  private readonly pins = new Map<string, KeyObject>()

  constructor(directory: string) {
    mkdirSync(directory, { recursive: true, mode: 0o700 })
    const file = join(directory, 'signaling-pairs.sqlite')
    closeSync(openSync(file, 'a', 0o600))
    this.db = new DatabaseSync(file)
    try {
      this.db.exec(`
        PRAGMA busy_timeout = 1000;
        CREATE TABLE IF NOT EXISTS pairing_nodes (node_id TEXT PRIMARY KEY, pin TEXT NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS pairing_edges (
          pair_id TEXT PRIMARY KEY,
          left_id TEXT NOT NULL,
          right_id TEXT NOT NULL,
          UNIQUE(left_id, right_id)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS pairing_codes (
          lookup TEXT PRIMARY KEY,
          receipt TEXT,
          received INTEGER NOT NULL
        ) STRICT;
        CREATE TABLE IF NOT EXISTS pairing_revocations (
          pair_id TEXT PRIMARY KEY,
          target TEXT NOT NULL,
          message TEXT NOT NULL
        ) STRICT;
        CREATE INDEX IF NOT EXISTS revocation_target ON pairing_revocations(target);
      `)
      for (const row of this.db.prepare('SELECT node_id, pin FROM pairing_nodes').all()) {
        this.pins.set(String(row.node_id), publicKey(String(row.pin)))
      }
    } catch (error) {
      this.db.close()
      throw error
    }
  }

  get nodeCount() { return this.pins.size }

  key(nodeId: string) { return this.pins.get(nodeId) }

  allows(first: string, second: string) {
    return this.db.prepare('SELECT 1 FROM pairing_edges WHERE left_id = ? AND right_id = ?')
      .get(...ordered(first, second)) !== undefined
  }

  consumed(lookup: string, nodeId: string): { receipt?: PairReceipt } | undefined {
    const row = this.db.prepare('SELECT receipt, received FROM pairing_codes WHERE lookup = ?').get(lookup)
    if (!row) {
      return undefined
    }
    if (typeof row.receipt !== 'string' || Date.now() - Number(row.received) >= pairingTimeout) {
      return {}
    }
    const receipt = decodeReceipt(JSON.parse(row.receipt))
    if (receipt?.members.some(member => member.nodeId === nodeId) && this.active(receipt.pairId, ...receipt.members.map(member => member.nodeId) as [string, string])) {
      return { receipt }
    }
    return {}
  }

  commit(lookup: string, receipt: PairReceipt) {
    const [first, second] = receipt.members
    const pins = receipt.members.map(member => [member.nodeId, publicKey(member.publicKey)] as const)
    const [left, right] = ordered(first.nodeId, second.nodeId)
    this.transaction(() => {
      const save = this.db.prepare('INSERT INTO pairing_nodes (node_id, pin) VALUES (?, ?) ON CONFLICT (node_id) DO NOTHING')
      for (const member of receipt.members) {
        save.run(member.nodeId, member.publicKey)
      }
      this.db.prepare(`INSERT INTO pairing_edges (pair_id, left_id, right_id) VALUES (?, ?, ?)
        ON CONFLICT (left_id, right_id) DO UPDATE SET pair_id = excluded.pair_id`).run(receipt.pairId, left, right)
      this.db.prepare('UPDATE pairing_codes SET receipt = NULL WHERE receipt IS NOT NULL AND received <= ?')
        .run(Date.now() - pairingTimeout)
      this.db.prepare('INSERT INTO pairing_codes (lookup, receipt, received) VALUES (?, ?, ?)')
        .run(lookup, JSON.stringify(receipt), Date.now())
    })
    for (const [id, key] of pins) {
      this.pins.set(id, key)
    }
  }

  revoke(message: PairRevocation) {
    return this.transaction(() => {
      if (!this.active(message.pairId, message.nodeId, message.peerId)) {
        const previous = this.db.prepare('SELECT message FROM pairing_revocations WHERE pair_id = ?').get(message.pairId)
        const revoked = typeof previous?.message === 'string' ? decodeRevocation(JSON.parse(previous.message)) : undefined
        return !!revoked && ordered(revoked.nodeId, revoked.peerId).every((id, index) => id === ordered(message.nodeId, message.peerId)[index])
      }
      this.db.prepare('DELETE FROM pairing_edges WHERE pair_id = ?').run(message.pairId)
      this.db.prepare('INSERT INTO pairing_revocations (pair_id, target, message) VALUES (?, ?, ?)')
        .run(message.pairId, message.peerId, JSON.stringify(message))
      return true
    })
  }

  revocationsFor(nodeId: string): PairRevocation[] {
    return this.db.prepare('SELECT message FROM pairing_revocations WHERE target = ? ORDER BY rowid')
      .all(nodeId).map(row => {
        const message = decodeRevocation(JSON.parse(String(row.message)))
        if (!message) {
          throw new Error('Mesh signaling revocation database is invalid')
        }
        return message
      })
  }

  close() { this.db.close() }

  private active(pairId: string, first: string, second: string) {
    return this.db.prepare('SELECT 1 FROM pairing_edges WHERE pair_id = ? AND left_id = ? AND right_id = ?')
      .get(pairId, ...ordered(first, second)) !== undefined
  }

  private transaction<T>(update: () => T): T {
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const result = update()
      this.db.exec('COMMIT')
      return result
    } catch (error) {
      this.db.exec('ROLLBACK')
      throw error
    }
  }
}
