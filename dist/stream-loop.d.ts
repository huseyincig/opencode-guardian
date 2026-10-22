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
    dispatch(raw: unknown, version: "v1" | "v2"): void;
    drain(): Promise<void>;
    forget(sessionID: string): void;
    private response;
    event(raw: unknown, version: "v1" | "v2"): Promise<void>;
}
export {};
