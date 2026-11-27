import { randomUUID } from 'node:crypto'
import type { AgentTools, SessionRunner, TurnSpec } from '@dsh-prism/dsh-orchestrator/contracts'
import { messages } from './messages.js'
import { record, string, wireTarget } from './protocol.js'

/** 同一轮次及编排工具调用在重连后沿用原 ID。 */
export class MeshRunner implements Pick<SessionRunner, 'run'> {
  constructor(private readonly nodeId: string,
    private readonly rpc: (payload: Record<string, unknown>, signal?: AbortSignal) => Promise<unknown>) {}

  async run(spec: TurnSpec, text: string, tools: AgentTools, signal?: AbortSignal, onReady?: (sessionId: string) => void) {
    if (spec.workspace.nodeId !== this.nodeId) {
      throw new Error(messages.destination)
    }
    const runId = randomUUID()
    const allowed = tools.definitions.map(definition => definition.name)
    const handled = new Map<string, Promise<{ success: boolean; value?: unknown }>>()
    const invoke = async (name: string, args: unknown) => {
      try {
        if (!allowed.includes(name)) {
          throw new Error('Unregistered tool')
        }
        signal?.throwIfAborted()
        return { success: true, value: await tools.invoke(name, args) }
      } catch {
        return { success: false }
      }
    }
    let sessionId: string | undefined
    signal?.throwIfAborted()
    try {
      await this.rpc({ op: 'start', runId, target: wireTarget(spec), text, tools: allowed }, signal)
      for (;;) {
        const state = record(await this.rpc({ op: 'poll', runId, sessionId }, signal))
        if (state.sessionId && !sessionId) {
          sessionId = string(state.sessionId)
          onReady?.(sessionId)
        }
        if (state.phase === 'done') {
          return
        }
        if (state.phase !== 'running' || !Array.isArray(state.calls)) {
          throw new Error(messages.remoteFailed)
        }
        await Promise.all(state.calls.map(async raw => {
          const call = record(raw)
          const callId = string(call.id)
          let result = handled.get(callId)
          if (!result) {
            result = invoke(string(call.name), call.args)
            handled.set(callId, result)
          }
          await this.rpc({ op: 'reply', runId, callId, ...await result }, signal)
        }))
      }
    } catch (error) {
      await this.rpc({ op: 'cancel', runId }, AbortSignal.timeout(5_000)).catch(() => undefined)
      throw error
    }
  }
}
