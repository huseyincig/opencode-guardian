/** Bounded assistant-only stream inspection shared by both host adapters. */
import { detectDegenerativeLoop } from "./degeneration.js";
import type { GuardConfig } from "./types.js";
import { recordGuardianEvent, sessionFingerprint } from "./telemetry.js";
import type { GuardianToastNotifier } from "./toast.js";

type Part = { tail: string; length: number; checked: number; closed: boolean };
type Response = { messageID: string; active: boolean; pending: boolean; stopped: boolean; warned: boolean; attempts: number; parts: Map<string, Part> };
type Settings = { config: GuardConfig; directory: string };
const TAIL = 2048;

function cancellable<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => reject(new Error("Stream inspection cancelled"));
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
    operation.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}

export class StreamLoopWatcher {
  private sessions = new Map<string, Response>();
  private tasks = new Set<Promise<void>>();
  constructor(private options: {
    signal: AbortSignal;
    directory: string;
    settings: (sessionID: string) => Promise<Settings>;
    interrupt: (sessionID: string, directory: string, signal: AbortSignal) => Promise<unknown>;
    notifier: GuardianToastNotifier;
  }) {}

  clear(): void { this.sessions.clear(); }
  dispatch(raw: unknown, version: "v1" | "v2"): void {
    // event() consumes ownership/lifecycle synchronously before its first await.
    // Never let slow host I/O stop ingestion of a completion or deletion event.
    const task = this.event(raw, version).catch(() => {});
    this.tasks.add(task);
    void task.finally(() => this.tasks.delete(task));
  }
  async drain(): Promise<void> { await Promise.allSettled(this.tasks); }
  forget(sessionID: string): void { this.sessions.delete(sessionID); }
  private response(sessionID: string, messageID: string): Response {
    let state = this.sessions.get(sessionID);
    if (state?.messageID === messageID) return state;
    state = { messageID, active: true, pending: false, stopped: false, warned: false, attempts: 0, parts: new Map() };
    this.sessions.set(sessionID, state);
    while (this.sessions.size > 512) {
      const oldest = this.sessions.keys().next().value;
      if (oldest === undefined) break;
      this.sessions.delete(oldest);
    }
    return state;
  }

  async event(raw: unknown, version: "v1" | "v2"): Promise<void> {
    if (this.options.signal.aborted || !raw || typeof raw !== "object") return;
    const event = raw as { type?: string; properties?: Record<string, unknown>; data?: Record<string, unknown> };
    const data = version === "v1" ? event.properties ?? event.data : event.data;
    if (!data) return;
    const info = data.info as { id?: string; sessionID?: string; role?: string; time?: { completed?: number } } | undefined;
    const sid = typeof data.sessionID === "string" ? data.sessionID
      : event.type?.startsWith("session.") ? info?.id : info?.sessionID;
    if (sid && (event.type === "session.deleted" || event.type === "session.moved")) { this.forget(sid); return; }
    if (sid && (event.type === "session.idle" || event.type === "session.execution.interrupted" || event.type === "session.execution.succeeded" || event.type === "session.execution.failed" || (event.type === "session.status" && (data.status as { type?: string } | undefined)?.type === "idle"))) {
      const state = this.sessions.get(sid);
      if (state) state.active = false;
      return;
    }
    if (version === "v1" && event.type === "message.updated") {
      if (sid && info?.role === "user") {
        const state = this.sessions.get(sid);
        if (state) state.active = false;
      }
      if (sid && info?.id && info.role === "assistant") {
        const state = this.response(sid, info.id);
        if (info.time?.completed !== undefined) state.active = false;
      }
      return;
    }

    let sessionID: string, state: Response, key: string, text: string, delta = false;
    if (version === "v1" && event.type === "message.part.updated") {
      const part = data.part as { sessionID?: string; messageID?: string; id?: string; type?: string; text?: string; time?: { end?: number } } | undefined;
      if (!part?.sessionID || !part.id || !part.messageID || (part.type !== "text" && part.type !== "reasoning") || typeof part.text !== "string") return;
      const current = this.sessions.get(part.sessionID);
      if (!current || current.messageID !== part.messageID || !current.active) return;
      sessionID = part.sessionID; state = current; key = part.id; text = part.text;
      if (part.time?.end !== undefined) { state.parts.delete(key); return; }
    } else if (version === "v2" && /^session\.(text|reasoning)\.(started|delta|ended)$/.test(event.type ?? "")) {
      if (!sid || typeof data.assistantMessageID !== "string" || !Number.isSafeInteger(data.ordinal)) return;
      sessionID = sid; state = this.response(sid, data.assistantMessageID);
      key = `${event.type?.split(".")[1]}:${data.ordinal}`;
      if (event.type?.endsWith(".ended")) {
        state.parts.set(key, { tail: "", length: 0, checked: 0, closed: true });
        if (state.parts.size > 64) {
          const oldest = state.parts.keys().next().value;
          if (oldest !== undefined) state.parts.delete(oldest);
        }
        return;
      }
      if (!event.type?.endsWith(".delta") || typeof data.delta !== "string") return;
      text = data.delta; delta = true;
    } else return;
    if (!state.active || state.stopped || state.warned || state.attempts >= 3) return;
    let part = state.parts.get(key);
    if (!part) {
      part = { tail: "", length: 0, checked: 0, closed: false };
      state.parts.set(key, part);
      while (state.parts.size > 64) {
        const oldest = state.parts.keys().next().value;
        if (oldest === undefined) break;
        state.parts.delete(oldest);
      }
    }
    if (part.closed) return;
    part.tail = delta ? (part.tail + text.slice(-TAIL)).slice(-TAIL) : text.slice(-TAIL);
    part.length = delta ? part.length + text.length : text.length;
    if (part.length < part.checked) part.checked = 0;
    if (state.pending || part.length < 30 || (part.checked > 0 && part.length - part.checked < 40)) return;
    part.checked = part.length;
    if (!detectDegenerativeLoop(part.tail).detected) return;
    // Acquire before resolving project settings: simultaneous parts share this lock.
    state.pending = true;
    const current = () => !this.options.signal.aborted && this.sessions.get(sessionID) === state && state.active;
    try {
      const { config, directory } = await cancellable(this.options.settings(sessionID), AbortSignal.any([this.options.signal, AbortSignal.timeout(3000)]));
      if (!current()) return;
      const setting = config.rules?.["runtime/circuit-breaker"];
      const severity = typeof setting === "string" ? setting : setting?.severity ?? "error";
      if (config.enabled === false || severity === "off") return;
      if (severity === "warn") {
        state.warned = true;
        recordGuardianEvent({ kind: "post-warning", session: sessionFingerprint(sessionID), rules: ["runtime/circuit-breaker"] }, directory);
        this.options.notifier.notify({ kind: "warning", ruleId: "runtime/circuit-breaker", sessionID });
        return;
      }
      state.attempts++;
      const signal = AbortSignal.any([this.options.signal, AbortSignal.timeout(3000)]);
      try {
        const result = await cancellable(this.options.interrupt(sessionID, directory, signal), signal);
        if (result === false || (result && typeof result === "object" && ((result as { error?: unknown }).error !== undefined || (result as { data?: unknown }).data === false))) throw new Error("Stream interrupt rejected");
        if (!current()) return;
        state.stopped = true;
        // API acceptance alone cannot prove how many tokens, if any, were saved.
        recordGuardianEvent({ kind: "stream-interrupt-requested", session: sessionFingerprint(sessionID), rules: ["runtime/circuit-breaker"] }, directory);
        this.options.notifier.notify({ kind: "stream-interrupt-requested", ruleId: "runtime/circuit-breaker", sessionID });
      } catch {
        // A timed-out host call may still be running (V2 has no cancellation
        // option). Do not issue overlapping retries after an ambiguous timeout.
        if (signal.aborted) state.stopped = true;
        if (current()) recordGuardianEvent({ kind: "inspection-error", session: sessionFingerprint(sessionID), rules: ["runtime/circuit-breaker"] }, directory);
      }
    } catch {
      if (current()) recordGuardianEvent({ kind: "inspection-error", session: sessionFingerprint(sessionID), rules: ["runtime/circuit-breaker"] }, this.options.directory);
    } finally { state.pending = false; }
  }
}
