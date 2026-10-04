import type { SessionMessage } from "./types.js";

export interface V1TurnWatcher {
  watch(sessionID: string): void;
  stop(sessionID: string): void;
  stopAll(): void;
}

/**
 * V1 host compatibility: some 1.x builds drop session.idle at the
 * location-filtered plugin bus. Poll only sessions with a new user prompt,
 * and only inspect a completed assistant response while the SDK reports
 * idle (or removes the session from its active-status map).
 *
 * Tool completion alone is never interpreted as turn completion. A long-running
 * busy/retry turn must not consume the idle completion timeout.
 */
export function createV1TurnWatcher(options: {
  status: (sessionID: string) => Promise<"idle" | "busy" | "retry" | undefined>;
  messages: (sessionID: string) => Promise<SessionMessage[]>;
  onIdle: (sessionID: string, messages: SessionMessage[]) => Promise<void>;
  onError: (sessionID: string, error: unknown) => void;
  intervalMs?: number;
  maxPolls?: number;
  maxBusyPolls?: number;
}): V1TurnWatcher {
  const intervalMs = options.intervalMs ?? 750;
  const maxPolls = options.maxPolls ?? 2400;
  // An optional compatibility probe should never live forever if the host
  // loses the session while continuing to report it as busy/retry.
  const maxBusyPolls = options.maxBusyPolls ?? maxPolls * 48;
  const pending = new Map<string, { cancelled: boolean; wake?: () => void }>();

  const stop = (sessionID: string) => {
    const current = pending.get(sessionID);
    if (!current) return;
    pending.delete(sessionID);
    current.cancelled = true;
    current.wake?.();
  };

  const pause = (current: { cancelled: boolean; wake?: () => void }) =>
    new Promise<void>((resolve) => {
      if (current.cancelled) return resolve();
      const timer = setTimeout(() => {
        current.wake = undefined;
        resolve();
      }, intervalMs);
      current.wake = () => {
        clearTimeout(timer);
        current.wake = undefined;
        resolve();
      };
      // Do not keep OpenCode alive just for an optional compatibility probe.
      (timer as ReturnType<typeof setTimeout> & { unref?: () => void }).unref?.();
    });

  const watch = (sessionID: string) => {
    stop(sessionID);
    const current = { cancelled: false } as { cancelled: boolean; wake?: () => void };
    pending.set(sessionID, current);
    void (async () => {
      let stableID: string | undefined;
      let stableChecks = 0;
      let failures = 0;
      let idlePolls = 0;
      let busyPolls = 0;

      while (!current.cancelled) {
        await pause(current);
        if (current.cancelled) return;
        try {
          const state = await options.status(sessionID);
          if (current.cancelled) return;
          if (state === "busy" || state === "retry") {
            idlePolls = 0;
            stableID = undefined;
            stableChecks = 0;
            failures = 0;
            // Long tasks can exceed the idle timeout. Stop a truly orphaned
            // watcher quietly after a separate, much larger active budget.
            if (++busyPolls >= maxBusyPolls) stop(sessionID);
            continue;
          }
          busyPolls = 0;
          if (state !== "idle" && state !== undefined) {
            throw new Error("V1 session status has an unrecognized value.");
          }
          // Only idle observations count toward the completion timeout.
          if (++idlePolls > maxPolls) {
            stop(sessionID);
            options.onError(sessionID, new Error("V1 completion was not observed after the idle polling limit."));
            return;
          }

          const messages = await options.messages(sessionID);
          if (current.cancelled) return;
          const lastUser = messages.findLastIndex((item) => item.info.role === "user");
          const lastAssistant = messages.findLastIndex((item) => item.info.role === "assistant");
          const info = lastAssistant > lastUser ? messages[lastAssistant].info : undefined;
          const time = info?.time as { completed?: unknown } | undefined;
          if (!info || typeof time?.completed !== "number") {
            stableID = undefined;
            stableChecks = 0;
            failures = 0;
            continue;
          }

          const fingerprint = info.id + ":" + time.completed;
          stableChecks = stableID === fingerprint ? stableChecks + 1 : 1;
          stableID = fingerprint;
          failures = 0;
          if (stableChecks < 2) continue;

          if (pending.get(sessionID) !== current) return;
          pending.delete(sessionID);
          current.cancelled = true;
          try {
            await options.onIdle(sessionID, messages);
          } catch (error) {
            options.onError(sessionID, error);
          }
          return;
        } catch (error) {
          if (current.cancelled) return;
          stableID = undefined;
          stableChecks = 0;
          if (++failures >= 3) {
            stop(sessionID);
            options.onError(sessionID, error);
            return;
          }
        }
      }
    })();
  };

  return {
    watch,
    stop,
    stopAll: () => {
      for (const sessionID of pending.keys()) stop(sessionID);
    },
  };
}
