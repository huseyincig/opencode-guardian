/** Bounded assistant-only stream inspection for OpenCode V2. */
import { detectDegenerativeLoop } from "./degeneration.js";
import { recordGuardianEvent, sessionFingerprint } from "./telemetry.js";
const TAIL = 2048;
const DEFAULT_VERIFY_WINDOW_MS = 4000;
function verifyWindowMs() {
    const raw = Number(process.env.OPENCODE_GUARDIAN_STREAM_VERIFY_MS);
    return Number.isFinite(raw) && raw > 0 ? Math.min(60_000, Math.floor(raw)) : DEFAULT_VERIFY_WINDOW_MS;
}
function cancellable(operation, signal) {
    return new Promise((resolve, reject) => {
        const abort = () => reject(new Error("Stream inspection cancelled"));
        if (signal.aborted)
            abort();
        else
            signal.addEventListener("abort", abort, { once: true });
        operation.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
    });
}
export class StreamLoopWatcher {
    options;
    sessions = new Map();
    tasks = new Set();
    constructor(options) {
        this.options = options;
    }
    clear() {
        for (const state of this.sessions.values())
            this.endVerification(state);
        this.sessions.clear();
    }
    endVerification(state) {
        if (!state.verify)
            return;
        clearTimeout(state.verify.timer);
        delete state.verify;
    }
    /**
     * An accepted interrupt only proves the host took the request. Watch the host's own
     * events afterwards: a terminal execution event proves the stream stopped, whereas
     * deltas still arriving when the window closes prove it did not.
     */
    beginVerification(sessionID, state, directory) {
        this.endVerification(state);
        const timer = setTimeout(() => {
            const verify = state.verify;
            if (!verify)
                return;
            delete state.verify;
            if (this.options.signal.aborted || this.sessions.get(sessionID) !== state || !state.active)
                return;
            if (verify.deltas > 0) {
                state.stopped = false;
                delete state.stopUnconfirmed;
                recordGuardianEvent({ kind: "stream-interrupt-ineffective", session: sessionFingerprint(sessionID), rules: ["runtime/circuit-breaker"] }, verify.directory);
            }
            else {
                // No terminal host event arrived during the verification window; if delayed
                // deltas resume later for the same response, reopen loop detection.
                state.stopUnconfirmed = { directory: verify.directory };
            }
        }, verifyWindowMs());
        timer.unref?.();
        state.verify = { deltas: 0, directory, timer };
    }
    dispatch(raw) {
        // event() consumes ownership/lifecycle synchronously before its first await.
        // Never let slow host I/O stop ingestion of a completion or deletion event.
        const task = this.event(raw).catch(() => { });
        this.tasks.add(task);
        void task.finally(() => this.tasks.delete(task));
    }
    async drain() { await Promise.allSettled(this.tasks); }
    forget(sessionID) {
        const state = this.sessions.get(sessionID);
        if (state)
            this.endVerification(state);
        this.sessions.delete(sessionID);
    }
    response(sessionID, messageID) {
        let state = this.sessions.get(sessionID);
        if (state?.messageID === messageID)
            return state;
        state = { messageID, active: true, pending: false, stopped: false, warned: false, attempts: 0, parts: new Map() };
        this.sessions.set(sessionID, state);
        while (this.sessions.size > 512) {
            const oldest = this.sessions.keys().next().value;
            if (oldest === undefined)
                break;
            this.sessions.delete(oldest);
        }
        return state;
    }
    async event(raw) {
        if (this.options.signal.aborted || !raw || typeof raw !== "object")
            return;
        const event = raw;
        const data = event.data;
        if (!data)
            return;
        const info = data.info;
        const sid = typeof data.sessionID === "string" ? data.sessionID
            : event.type?.startsWith("session.") ? info?.id : info?.sessionID;
        if (sid && (event.type === "session.deleted" || event.type === "session.moved")) {
            this.forget(sid);
            return;
        }
        if (sid && (event.type === "session.idle" || event.type === "session.execution.interrupted" || event.type === "session.execution.succeeded" || event.type === "session.execution.failed" || (event.type === "session.status" && data.status?.type === "idle"))) {
            const state = this.sessions.get(sid);
            if (state) {
                const verify = state.verify;
                const stoppedByHost = event.type === "session.execution.interrupted" || event.type === "session.idle" || event.type === "session.status";
                if (verify && stoppedByHost) {
                    recordGuardianEvent({ kind: "stream-interrupt-verified", session: sessionFingerprint(sid), rules: ["runtime/circuit-breaker"] }, verify.directory);
                }
                this.endVerification(state);
                delete state.stopUnconfirmed;
                state.active = false;
            }
            return;
        }
        let sessionID, state, key, text, delta = false;
        if (/^session\.(text|reasoning)\.(started|delta|ended)$/.test(event.type ?? "")) {
            if (!sid || typeof data.assistantMessageID !== "string" || !Number.isSafeInteger(data.ordinal))
                return;
            sessionID = sid;
            state = this.response(sid, data.assistantMessageID);
            key = `${event.type?.split(".")[1]}:${data.ordinal}`;
            if (event.type?.endsWith(".ended")) {
                state.parts.set(key, { tail: "", length: 0, checked: 0, closed: true });
                if (state.parts.size > 64) {
                    const oldest = state.parts.keys().next().value;
                    if (oldest !== undefined)
                        state.parts.delete(oldest);
                }
                return;
            }
            if (!event.type?.endsWith(".delta") || typeof data.delta !== "string")
                return;
            text = data.delta;
            delta = true;
        }
        else
            return;
        if (delta && state.verify)
            state.verify.deltas++;
        if (delta && state.stopped && state.stopUnconfirmed && state.active) {
            const unconfirmed = state.stopUnconfirmed;
            delete state.stopUnconfirmed;
            state.stopped = false;
            recordGuardianEvent({ kind: "stream-interrupt-ineffective", session: sessionFingerprint(sessionID), rules: ["runtime/circuit-breaker"] }, unconfirmed.directory);
        }
        if (!state.active || state.stopped || state.warned || state.attempts >= 3)
            return;
        let part = state.parts.get(key);
        if (!part) {
            part = { tail: "", length: 0, checked: 0, closed: false };
            state.parts.set(key, part);
            while (state.parts.size > 64) {
                const oldest = state.parts.keys().next().value;
                if (oldest === undefined)
                    break;
                state.parts.delete(oldest);
            }
        }
        if (part.closed)
            return;
        part.tail = delta ? (part.tail + text.slice(-TAIL)).slice(-TAIL) : text.slice(-TAIL);
        part.length = delta ? part.length + text.length : text.length;
        if (part.length < part.checked)
            part.checked = 0;
        if (state.pending || part.length < 30 || (part.checked > 0 && part.length - part.checked < 40))
            return;
        part.checked = part.length;
        if (!detectDegenerativeLoop(part.tail).detected)
            return;
        // Acquire before resolving project settings: simultaneous parts share this lock.
        state.pending = true;
        const current = () => !this.options.signal.aborted && this.sessions.get(sessionID) === state && state.active;
        try {
            const { config, directory } = await cancellable(this.options.settings(sessionID), AbortSignal.any([this.options.signal, AbortSignal.timeout(3000)]));
            if (!current())
                return;
            const setting = config.rules?.["runtime/circuit-breaker"];
            const severity = typeof setting === "string" ? setting : setting?.severity ?? "error";
            if (config.enabled === false || severity === "off")
                return;
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
                if (result === false || (result && typeof result === "object" && (result.error !== undefined || result.data === false || result.interrupted === false)))
                    throw new Error("Stream interrupt rejected");
                if (!current())
                    return;
                state.stopped = true;
                this.beginVerification(sessionID, state, directory);
                // API acceptance alone cannot prove how many tokens, if any, were saved.
                recordGuardianEvent({ kind: "stream-interrupt-requested", session: sessionFingerprint(sessionID), rules: ["runtime/circuit-breaker"] }, directory);
                this.options.notifier.notify({ kind: "stream-interrupt-requested", ruleId: "runtime/circuit-breaker", sessionID });
            }
            catch {
                // A timed-out host call may still be running (V2 has no cancellation
                // option). Do not issue overlapping retries after an ambiguous timeout.
                if (signal.aborted)
                    state.stopped = true;
                if (current())
                    recordGuardianEvent({ kind: "inspection-error", session: sessionFingerprint(sessionID), rules: ["runtime/circuit-breaker"] }, directory);
            }
        }
        catch {
            if (current())
                recordGuardianEvent({ kind: "inspection-error", session: sessionFingerprint(sessionID), rules: ["runtime/circuit-breaker"] }, this.options.directory);
        }
        finally {
            state.pending = false;
        }
    }
}
