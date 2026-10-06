export interface HandoffTrackingState {
    handoffId: string;
    kind: "clarification" | "choice" | "approval";
    autoSelect: "allowed" | "forbidden";
    status: "handed_off" | "question_presented" | "resolved";
}
interface SessionState {
    turnKey: string;
    remediationCount: number;
    fingerprints: Set<string>;
    continuationCount: number;
    continuationKeys: Set<string>;
    pendingRemediationRules?: string[];
    pendingRemediationFiles?: string[];
    activeHandoff?: HandoffTrackingState;
    handoffSequence: number;
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
    setPendingRemediation(sessionID: string, turnKey: string, rules: string[], files?: string[]): void;
    getPendingRemediation(sessionID: string, turnKey?: string): string[] | undefined;
    getPendingRemediationFiles(sessionID: string, turnKey: string): string[];
    clearPendingRemediation(sessionID: string): void;
    setActiveHandoff(sessionID: string, handoff: HandoffTrackingState): void;
    getActiveHandoff(sessionID: string): HandoffTrackingState | undefined;
    clearActiveHandoff(sessionID: string): void;
    nextHandoffSequence(sessionID: string, turnKey: string): number;
    forget(sessionID: string): void;
}
export {};
