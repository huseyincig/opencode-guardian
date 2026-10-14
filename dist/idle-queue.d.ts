/** Bounded per-session coalescing for advisory idle notifications. */
export declare function createIdleQueue(signal: AbortSignal, onError: () => void): {
    enqueue(sessionID: string, job: (signal: AbortSignal) => Promise<void>): void;
    forget: (sessionID: string) => void;
    clear: () => void;
};
