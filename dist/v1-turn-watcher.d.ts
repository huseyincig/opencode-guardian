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
export declare function createV1TurnWatcher(options: {
    status: (sessionID: string) => Promise<"idle" | "busy" | "retry" | undefined>;
    messages: (sessionID: string) => Promise<SessionMessage[]>;
    onIdle: (sessionID: string, messages: SessionMessage[]) => Promise<void>;
    onError: (sessionID: string, error: unknown) => void;
    intervalMs?: number;
    maxPolls?: number;
    maxBusyPolls?: number;
}): V1TurnWatcher;
