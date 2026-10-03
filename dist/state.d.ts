interface SessionState {
    turnKey: string;
    remediationCount: number;
    fingerprints: Set<string>;
    continuationCount: number;
    continuationKeys: Set<string>;
}
export declare class SessionStateStore {
    private readonly sessions;
    beginTurn(sessionID: string, turnKey: string): SessionState;
    canRemediate(sessionID: string, turnKey: string, fingerprint: string, budget: number): boolean;
    recordRemediation(sessionID: string, turnKey: string, fingerprint: string): void;
    rollbackRemediation(sessionID: string, turnKey: string, fingerprint: string): void;
    canContinue(sessionID: string, turnKey: string, progressKey: string, budget: number): boolean;
    recordContinuation(sessionID: string, turnKey: string, progressKey: string): void;
    rollbackContinuation(sessionID: string, turnKey: string, progressKey: string): void;
    forget(sessionID: string): void;
}
export {};
