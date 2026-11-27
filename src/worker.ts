import { createHash, randomUUID } from 'node:crypto'
import { chmodSync, mkdirSync } from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import { join } from 'node:path'
import type { Layer, SessionRunner, ToolDefinition, TurnSpec } from '@dsh-prism/dsh-orchestrator/contracts'
import { MeshError, names, parseTarget, record, string, type MeshPeer } from './protocol.js'

export interface WorkerServices {
  runner: Pick<SessionRunner, 'run'>
  authorize(spec: TurnSpec): TurnSpec
  definitionsFor(layer: Layer): ToolDefinition[]
}

function digest(parts: unknown): string {
  return createHash('sha256').update(JSON.stringify(parts)).digest('hex')
}

interface Call {
  name: string
  args: unknown
  resolve(value: unknown): void
  reject(error: Error): void
}

/** One model turn. Tool calls stay on the coordinator, indexed until receipt. */
class WorkerTurn {
  readonly calls = new Map<string, Call>()
  private readonly changed = new Set<() => void>()
  readonly controller = new AbortController()
  readonly done: Promise<void>
  touched = Date.now()
  phase: 'running' | 'done' | 'failed' = 'running'
  sessionId?: string

  constructor(readonly fingerprint: string, runner: Pick<SessionRunner, 'run'>, spec: TurnSpec, text: string, definitions: ToolDefinition[]) {
    const invoke = async (name: string, args: unknown) => {
      this.controller.signal.throwIfAborted()
      if (!definitions.some(d => d.name === name)) throw new MeshError(403, 'Tool unavailable')
      return new Promise<unknown>((resolve, reject) => {
        this.calls.set(randomUUID(), {name, args, resolve, reject})
        this.notify()
      })
    }
    this.done = Promise.resolve().then(() => runner.run(spec, text, {definitions, invoke}, this.controller.signal, id => {
      this.sessionId = id
      this.notify()
    })).then(() => { this.phase = 'done' }, () => { this.phase = 'failed' }).finally(() => this.notify())
  }

  private notify(): void {
    for (const wake of this.changed) wake()
  }

  async poll(knownSession: unknown) {
    if (this.phase === 'running' && !this.calls.size && this.sessionId === knownSession) {
      await new Promise<void>(resolve => {
        const wake = () => { clearTimeout(timer); this.changed.delete(wake); resolve() }
        const timer = setTimeout(wake, 10_000)
        this.changed.add(wake)
      })
    }
    return {
      phase: this.phase, sessionId: this.sessionId,
      calls: Array.from(this.calls, ([id, call]) => ({id, name: call.name, args: call.args})),
    }
  }

  reply(id: string, success: boolean, value: unknown) {
    const call = this.calls.get(id)
    if (!call) return // Repeating an acknowledged reply has no side effects.
    this.calls.delete(id)
    if (success) call.resolve(value)
    else call.reject(new Error('Coordinator tool failed'))
  }

  cancel() {
    this.controller.abort()
    for (const call of this.calls.values()) call.reject(new Error('Mesh turn cancelled'))
    this.calls.clear()
    this.notify()
  }
}

/** A physical worker's durable, peer-scoped session lineage and live remote calls. */
export class MeshWorker {
  private readonly turns = new Map<string, WorkerTurn>()
  private readonly sweep: NodeJS.Timeout
  private services?: WorkerServices
  private database?: DatabaseSync
  private lastPrune = 0

  constructor(readonly nodeId: string, private readonly stateDirectory: string) {
    this.sweep = setInterval(() => {
      for (const [id, turn] of this.turns) {
        if (Date.now() - turn.touched < 120_000) continue
        if (turn.phase === 'running') turn.cancel()
        else this.turns.delete(id)
      }
    }, 30_000).unref()
  }

  attach(services: WorkerServices) {
    if (this.services) throw new Error('Mesh worker already attached')
    this.services = services
    return () => {
      if (this.services === services) {
        this.services = undefined
        for (const turn of this.turns.values()) turn.cancel()
      }
    }
  }

  async close() {
    clearInterval(this.sweep)
    for (const turn of this.turns.values()) turn.cancel()
    await Promise.all(Array.from(this.turns.values(), turn => turn.done))
    this.turns.clear()
    this.database?.close()
    this.database = undefined
  }

  private db(): DatabaseSync {
    if (!this.database) {
      mkdirSync(this.stateDirectory, {recursive: true, mode: 0o700})
      const path = join(this.stateDirectory, 'lineage.sqlite')
      const db = new DatabaseSync(path)
      chmodSync(path, 0o600)
      db.exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS lineage (
          id TEXT PRIMARY KEY, owner TEXT, layer TEXT, project TEXT, cwd TEXT, parent TEXT, ceiling TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS starts (run TEXT PRIMARY KEY, at INTEGER NOT NULL)`)
      this.database = db
    }
    return this.database
  }

  private bind(spec: TurnSpec, runKey?: string): void {
    const db = this.db()
    const select = db.prepare('SELECT * FROM lineage WHERE id=?')
    const parentId = spec.parentBindingId ?? null
    const {projectId, cwd} = spec.workspace
    const grant = spec.layer === 'L2' ? spec.delegationCeiling ?? [] : spec.allowedTools
    const permitted = (row: Record<string, unknown>) => {
      const list: string[] = JSON.parse(String(row.ceiling))
      return grant.every(name => list.includes(name))
    }
    db.exec('BEGIN IMMEDIATE')
    try {
      if (runKey) {
        const now = Date.now()
        if (now - this.lastPrune >= 3_600_000) {
          db.prepare('DELETE FROM starts WHERE at < ?').run(now - 86_400_000)
          this.lastPrune = now
        }
        // A lost start reply followed by a worker restart must never repeat an accepted turn.
        if (!db.prepare('INSERT OR IGNORE INTO starts VALUES(?,?)').run(runKey, now).changes) {
          throw new MeshError(409, 'Turn already admitted on a prior worker')
        }
      }
      if (spec.layer === 'L3') {
        const parent = parentId ? select.get(parentId) : undefined
        if (!parent || parent.layer !== 'L2' || parent.owner !== spec.owner ||
            parent.project !== projectId || parent.cwd !== cwd || !permitted(parent)) {
          throw new MeshError(403, 'Invalid parent delegation')
        }
      }
      const current = select.get(spec.bindingId)
      if (!current && runKey) {
        db.prepare('INSERT INTO lineage VALUES(?,?,?,?,?,?,?)')
          .run(spec.bindingId, spec.owner, spec.layer, projectId, cwd, parentId, JSON.stringify(grant))
      } else {
        if (!current || current.owner !== spec.owner || current.layer !== spec.layer ||
            current.project !== projectId || current.cwd !== cwd || current.parent !== parentId || !permitted(current)) {
          throw new MeshError(403, 'Session binding unavailable')
        }
        if (runKey) db.prepare('UPDATE lineage SET ceiling=? WHERE id=?').run(JSON.stringify(grant), spec.bindingId)
      }
      db.exec('COMMIT')
    } catch (err) {
      db.exec('ROLLBACK')
      throw err
    }
  }

  async handle(peer: MeshPeer, input: unknown): Promise<unknown> {
    const data = record(input)
    const op = string(data.op)
    const services = this.services
    if (!services) throw new MeshError(503, 'Mesh worker unavailable')
    if (op === 'start') {
      const target = parseTarget(data.target, this.nodeId)
      if (!peer.projects?.includes(target.workspace.projectId)) throw new MeshError(403, 'Project unavailable')
      let spec: TurnSpec
      try { spec = services.authorize(target) }
      catch { throw new MeshError(403, 'Delegation denied') }
      const scopedId = (id: string) => 'mesh-' + digest([peer.id, id])
      spec = {...spec, bindingId: scopedId(spec.bindingId), parentBindingId: spec.parentBindingId && scopedId(spec.parentBindingId)}
      const runKey = digest([peer.id, string(data.runId)])
      const text = string(data.text, 1_000_000)
      const allowed = names(data.tools)
      const definitions = services.definitionsFor(spec.layer).filter(d => allowed.includes(d.name))
      if (allowed.length !== definitions.length) throw new MeshError(403, 'Invalid tool delegation')
      const fingerprint = digest([target, text, allowed])
      const current = this.turns.get(runKey)
      if (current && current.fingerprint !== fingerprint) throw new MeshError(409, 'Conflicting turn')
      if (!current) {
        this.bind(spec, runKey)
        this.turns.set(runKey, new WorkerTurn(fingerprint, services.runner, spec, text, definitions))
      }
      return {accepted: true}
    }

    const turn = this.turns.get(digest([peer.id, string(data.runId)]))
    if (!turn) throw new MeshError(404, 'Turn unavailable')
    turn.touched = Date.now()
    if (op === 'poll') return turn.poll(data.sessionId)
    if (op === 'reply') {
      if (typeof data.success !== 'boolean') throw new MeshError(400, 'Invalid tool reply')
      turn.reply(string(data.callId), data.success, data.value)
    } else if (op === 'cancel') {
      turn.cancel()
      await turn.done
    } else { throw new MeshError(400, 'Unknown operation') }
    return {accepted: true}
  }
}
