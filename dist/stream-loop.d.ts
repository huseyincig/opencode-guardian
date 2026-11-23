import type { GuardConfig } from "./types.js";
import type { GuardianToastNotifier } from "./toast.js";
type Settings = {
    config: GuardConfig;
    directory: string;
};
export declare class StreamLoopWatcher {
    private options;
    private sessions;
    private tasks;
    constructor(options: {
        signal: AbortSignal;
        directory: string;
        settings: (sessionID: string) => Promise<Settings>;
        interrupt: (sessionID: string, directory: string, signal: AbortSignal) => Promise<unknown>;
        notifier: GuardianToastNotifier;
    });
    clear(): void;
    private endVerification;
    /**
     * An accepted interrupt only proves the host took the request. Watch the host's own
     * events afterwards: a terminal execution event proves the stream stopped, whereas
     * deltas still arriving when the window closes prove it did not.
     */
    private beginVerification;
    dispatch(raw: unknown): void;
    drain(): Promise<void>;
    forget(sessionID: string): void;
    private response;
    event(raw: unknown): Promise<void>;
}
export {};
