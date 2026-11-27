import { createHash, randomUUID } from 'node:crypto'
import { chmodSync, mkdirSync } from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import { join } from 'node:path'
import type { Layer, ProjectMetadata, SessionRunner, ToolDefinition } from '@dsh-prism/dsh-orchestrator/contracts'
import { assertParticipants, MeshError, names, parseTarget, peerInboxMessage, peerMessage, projectMetadata, record, string } from './protocol.js'
import type { MeshPeer, MeshTurnSpec, PeerInboxMessage, PeerMessage } from './protocol.js'

export interface WorkerServices {
  runner: Pick<SessionRunner, 'run'>
  authorize(spec: MeshTurnSpec): MeshTurnSpec
  definitionsFor(layer: Layer): ToolDefinition[]
  queryProjects?(owner: string, search?: string): ProjectMetadata[] | Promise<ProjectMetadata[]>
  invokePeerTool?(spec: MeshTurnSpec, args: unknown, signal?: AbortSignal): Promise<unknown>
  receivePeerMessage?(fromNodeId: string, message: PeerMessage, signal?: AbortSignal): Promise<void>
  acceptPeerInbox?(fromTargetNodeId: string, message: PeerInboxMessage, signal?: AbortSignal): Promise<void>
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

  constructor(readonly peerId: string, readonly fingerprint: string, runner: Pick<SessionRunner, 'run'>, spec: MeshTurnSpec, text: string,
    definitions: ToolDefinition[], direct?: (args: unknown, signal: AbortSignal) => Promise<unknown>) {
    const invoke = async (name: string, args: unknown) => {
      this.controller.signal.throwIfAborted()
      if (!definitions.some(d => d.name === name)) throw new MeshError(403, 'Tool unavailable')
      if (name === 'peer_send') {
        if (!direct || spec.layer !== 'L2' || !spec.room) {
          throw new MeshError(403, 'Mesh Room tool unavailable')
        }
        return direct(args, this.controller.signal)
      }
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

  revoke(peerId: string) {
    for (const [id, turn] of this.turns) {
      if (turn.peerId === peerId) {
        turn.cancel()
        // 关闭插件时仍需等待已撤权的执行结束。
        void turn.done.then(() => { this.turns.delete(id) })
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
        CREATE TABLE IF NOT EXISTS starts (run TEXT PRIMARY KEY, at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS depths (id TEXT PRIMARY KEY, depth INTEGER NOT NULL, ceiling INTEGER NOT NULL)`)
      this.database = db
    }
    return this.database
  }

  private bind(spec: MeshTurnSpec, runKey: string): void {
    const db = this.db()
    const select = db.prepare('SELECT * FROM lineage WHERE id=?')
    const selectDepth = db.prepare('SELECT * FROM depths WHERE id=?')
    const parentId = spec.parentBindingId ?? null
    const {projectId, cwd} = spec.workspace
    const grant = spec.layer === 'L2' ? spec.delegationCeiling ?? [] : spec.allowedTools
    const permitted = (row: Record<string, unknown>) => {
      const list: string[] = JSON.parse(String(row.ceiling))
      return grant.every(name => list.includes(name))
    }
    db.exec('BEGIN IMMEDIATE')
    try {
      const now = Date.now()
      if (now - this.lastPrune >= 3_600_000) {
        db.prepare('DELETE FROM starts WHERE at < ?').run(now - 86_400_000)
        this.lastPrune = now
      }
      // 丢失启动确认后的重试与进程重启仍指向同一次执行。
      if (!db.prepare('INSERT OR IGNORE INTO starts VALUES(?,?)').run(runKey, now).changes) {
        throw new MeshError(409, 'Turn already admitted on a prior worker')
      }
      if (spec.layer === 'L3') {
        const parent = parentId ? select.get(parentId) : undefined
        if (!parent || parent.layer !== 'L2' || parent.owner !== spec.owner ||
            parent.project !== projectId || parent.cwd !== cwd || !permitted(parent)) {
          throw new MeshError(403, 'Invalid parent delegation')
        }
        const limit = selectDepth.get(parentId!)
        if (limit && (spec.depth !== Number(limit.depth) + 1 || spec.maxDepth === undefined || spec.maxDepth > Number(limit.ceiling))) {
          throw new MeshError(403, 'Invalid parent delegation depth')
        }
      }
      const current = select.get(spec.bindingId)
      if (!current) {
        db.prepare('INSERT INTO lineage VALUES(?,?,?,?,?,?,?)')
          .run(spec.bindingId, spec.owner, spec.layer, projectId, cwd, parentId, JSON.stringify(grant))
      } else {
        if (current.owner !== spec.owner || current.layer !== spec.layer ||
            current.project !== projectId || current.cwd !== cwd || current.parent !== parentId || !permitted(current)) {
          throw new MeshError(403, 'Session binding unavailable')
        }
        db.prepare('UPDATE lineage SET ceiling=? WHERE id=?').run(JSON.stringify(grant), spec.bindingId)
      }
      const oldDepth = selectDepth.get(spec.bindingId)
      if (oldDepth && (spec.depth !== Number(oldDepth.depth) || spec.maxDepth === undefined || spec.maxDepth > Number(oldDepth.ceiling))) {
        throw new MeshError(403, 'Mesh delegation depth cannot increase')
      }
      if (spec.depth !== undefined && spec.maxDepth !== undefined) {
        db.prepare('INSERT INTO depths VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET ceiling=excluded.ceiling')
          .run(spec.bindingId, spec.depth, spec.maxDepth)
      }
      db.exec('COMMIT')
    } catch (err) {
      db.exec('ROLLBACK')
      throw err
    }
  }

  async handle(peer: Pick<MeshPeer, 'id' | 'projects'>, input: unknown, signal?: AbortSignal,
    address = this.nodeId): Promise<unknown> {
    const data = record(input)
    const op = string(data.op)
    const services = this.services
    if (!services) throw new MeshError(503, 'Mesh worker unavailable')
    if (op === 'peer_send') {
      const message = peerMessage(data.message)
      assertParticipants(message, peer.id, address)
      if (!services.receivePeerMessage) {
        throw new MeshError(403, 'Mesh Room receiver unavailable')
      }
      await services.receivePeerMessage(peer.id, message, signal)
      return { accepted: true }
    }
    if (op === 'peer_inbox') {
      const message = peerInboxMessage(data.message)
      if (message.room.coordinatorNode !== address || message.targetNodeId !== peer.id || !services.acceptPeerInbox) {
        throw new MeshError(403, 'Mesh Room coordinator unavailable')
      }
      assertParticipants(message, message.sourceNodeId, peer.id)
      await services.acceptPeerInbox(peer.id, message, signal)
      return { accepted: true }
    }
    if (op === 'projects') {
      const owner = string(data.owner, 2_048)
      const search = data.search === undefined ? undefined : string(data.search, 1_024)
      if (!services.queryProjects || !peer.projects?.length) {
        return []
      }
      const shared = new Set(peer.projects)
      return (await services.queryProjects(owner, search))
        .filter(project => project.nodeId === this.nodeId && shared.has(project.id))
        .map(project => projectMetadata({ ...project, nodeId: address }, address))
    }
    if (op === 'start') {
      const target = parseTarget(data.target, address)
      if (!peer.projects?.includes(target.workspace.projectId)) throw new MeshError(403, 'Project unavailable')
      if (target.room && target.room.coordinatorNode !== peer.id) {
        throw new MeshError(403, 'Mesh Room coordinator must be the delegating peer')
      }
      let logical: MeshTurnSpec
      try { logical = services.authorize(target) }
      catch { throw new MeshError(403, 'Delegation denied') }
      if ((logical.depth === undefined) !== (logical.maxDepth === undefined)
          || (logical.depth !== undefined && logical.maxDepth !== undefined && logical.depth > logical.maxDepth)) {
        throw new MeshError(403, 'Invalid Mesh delegation depth')
      }
      const scopedId = (id: string) => 'mesh-' + digest([peer.id, id])
      const spec = {...logical, bindingId: scopedId(logical.bindingId), parentBindingId: logical.parentBindingId && scopedId(logical.parentBindingId)}
      const runKey = digest([peer.id, string(data.runId)])
      const text = string(data.text, 1_000_000)
      const allowed = names(data.tools)
      const requested = services.definitionsFor(spec.layer).filter(d => allowed.includes(d.name))
      if (allowed.length !== requested.length) throw new MeshError(403, 'Invalid tool delegation')
      const definitions = spec.layer === 'L2' && spec.maxDepth === 1
        ? requested.filter(tool => tool.name !== 'dispatch_executor')
        : requested
      const fingerprint = digest([target, text, allowed])
      const current = this.turns.get(runKey)
      if (current && current.fingerprint !== fingerprint) throw new MeshError(409, 'Conflicting turn')
      if (!current) {
        this.bind(spec, runKey)
        const invoke = services.invokePeerTool
        this.turns.set(runKey, new WorkerTurn(peer.id, fingerprint, services.runner, spec, text, definitions,
          invoke && ((args, signal) => invoke(logical, args, signal))))
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
