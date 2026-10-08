export type GuardianMessageKind = "remediation" | "visible";
export declare function createGuardianMessageMetadata(sessionID: string, kind: GuardianMessageKind, base?: Record<string, unknown>): Record<string, any>;
export declare function isTrustedGuardianMetadata(sessionID: string | undefined, metadata: unknown, kind?: GuardianMessageKind): boolean;
export declare function forgetGuardianProvenance(sessionID: string): void;
export declare function clearGuardianProvenance(): void;
