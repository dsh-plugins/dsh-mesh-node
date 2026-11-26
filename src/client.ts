import { messages } from './messages.js'
import { randomUUID } from 'node:crypto'
import type { AgentTools, SessionRunner, TraceEntry, TurnSpec } from '@dsh-prism/dsh-orchestrator/contracts'
import { maxBody, MeshError, peerUrl, record, string, wireTarget, type OutboundPeer } from './protocol.js'

/** Coordinator side. The same logical run and call IDs are reused on transport retries. */
export class MeshRunner implements SessionRunner {
  private readonly endpoint: URL

  constructor(private readonly from: string, private readonly peer: OutboundPeer, private readonly token: string) {
    this.endpoint = peerUrl(peer.url)
  }

  private async rpc(payload: Record<string, unknown>, signal?: AbortSignal): Promise<unknown> {
    const body = JSON.stringify(payload)
    if (Buffer.byteLength(body) > maxBody) throw new Error(messages.tooLarge)
    for (let attempt = 0; ; attempt++) {
      const deadline = AbortSignal.timeout(25_000)
      try {
        const response = await fetch(this.endpoint, {
          method: 'POST', redirect: 'error', body, signal: signal ? AbortSignal.any([deadline, signal]) : deadline,
          headers: {'content-type': 'application/json', authorization: 'Bearer ' + this.token, 'x-prism-node': this.from},
        })
        if (!response.ok) {
          await response.body?.cancel()
          throw new MeshError(response.status, 'Mesh node rejected ' + payload.op + ' (' + response.status + ')')
        }
        const reader = response.body!.getReader()
        const chunks = []
        let length = 0
        while (true) {
          const {value, done} = await reader.read()
          if (done) break
          length += value.byteLength
          if (length > maxBody) {
            await reader.cancel()
            throw new MeshError(413, 'Mesh response too large')
          }
          chunks.push(value)
        }
        return JSON.parse(Buffer.concat(chunks).toString())
      } catch (err) {
        signal?.throwIfAborted()
        if (attempt >= 1 || (err instanceof MeshError && err.status < 500)) throw err
      }
    }
  }

  private target(spec: TurnSpec) {
    if (spec.workspace.nodeId !== this.peer.id) throw new Error(messages.destination)
    return wireTarget(spec)
  }

  async run(spec: TurnSpec, text: string, tools: AgentTools, signal?: AbortSignal, onReady?: (sessionId: string) => void) {
    const target = this.target(spec)
    const runId = randomUUID()
    const allowed = tools.definitions.map(d => d.name)
    let sessionId: string | undefined
    signal?.throwIfAborted()
    try {
      await this.rpc({op: 'start', runId, target, text, tools: allowed}, signal)
      while (true) {
        const state = record(await this.rpc({op: 'poll', runId, sessionId}, signal))
        if (state.sessionId && !sessionId) {
          sessionId = string(state.sessionId)
          onReady?.(sessionId)
        }
        if (state.phase === 'done') return
        if (state.phase !== 'running' || !Array.isArray(state.calls)) throw new Error(messages.remoteFailed)
        await Promise.all(state.calls.map(async raw => {
          const call = record(raw)
          const name = string(call.name)
          const callId = string(call.id)
          let value: unknown
          let success = false
          try {
            if (!allowed.includes(name)) throw new Error('Unregistered tool')
            signal?.throwIfAborted()
            value = await tools.invoke(name, call.args)
            success = true
          } catch {
            // The remote model receives a generic error; keep local diagnostics on the coordinator.
          }
          await this.rpc({op: 'reply', runId, callId, success, value}, signal)
        }))
      }
    } catch (err) {
      // This also reaps an admitted turn when the start response was lost.
      await this.rpc({op: 'cancel', runId}).catch(() => {})
      throw err
    }
  }

  async transcript(spec: TurnSpec): Promise<TraceEntry[]> {
    const data = await this.rpc({op: 'transcript', target: this.target(spec)})
    if (!Array.isArray(data)) throw new Error('Invalid Mesh transcript')
    return data.map(raw => {
      const row = record(raw)
      if (typeof row.role !== 'string' || typeof row.text !== 'string') throw new Error('Invalid transcript entry')
      return {role: row.role, text: row.text, ...(typeof row.at === 'string' ? {at: row.at} : {})}
    })
  }
}
