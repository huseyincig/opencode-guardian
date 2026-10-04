import { type AuditReason } from "./audit.js";
export type GuardianEventKind = "runtime-started" | "preflight-allowed" | "preflight-blocked" | "post-warning" | "post-remediation" | "remediation-verified" | "remediation-failed" | "remediation-unverified" | "verification-unavailable" | "inspection-error" | "statistics-reset";
export type PreflightState = "active" | "disabled" | "unavailable";
export type GuardianAction = "started" | "allowed" | "blocked-before-execution" | "warned" | "remediation-requested" | "remediation-checked" | "inspection-failed" | "statistics-reset";
export type GuardianOutcome = "started" | "allowed" | "prevented" | "reported" | "unverified" | "verified" | "error";
export interface GuardianEvent {
    at: string;
    id?: string;
    kind: GuardianEventKind;
    action?: GuardianAction;
    outcome?: GuardianOutcome;
    runtime?: "v1" | "v2";
    preflight?: PreflightState;
    /** Only a 16-character SHA-256 fingerprint, never the raw session ID. */
    session?: string;
    /** Known shell tool category, never raw arguments or a custom tool name. */
    tool?: string;
    rules?: string[];
    /** Fixed codebook values only: never a finding snippet, pattern or description. */
    reasons?: AuditReason[];
}
export type GuardianStatus = {
    preflight: PreflightState | "unknown";
    inspected: number;
    blocked: number;
    warnings: number;
    remediations: number;
    errors: number;
    verified: number;
    failed: number;
    unverified: number;
    truncated: boolean;
    lastEvent?: string;
    /** Most recent event kind; counters above cover retained history. */
    lastKind?: GuardianEventKind;
};
export declare const GUARDIAN_MAX_LOG_BYTES: number;
export declare function guardianStateDirectory(directory?: string): string;
export declare function guardianEventPath(directory?: string): string;
export declare function sessionFingerprint(value?: string): string | undefined;
export declare function recordGuardianEvent(event: Omit<GuardianEvent, "at">, directoryArg?: string): boolean;
/** Reads at most the newest 2 MiB across the current log and one archive. */
export declare function readGuardianStatus(directoryOrMaxBytes?: string | number, maxBytesArg?: number): GuardianStatus;
/** Reset displayed counters without deleting or rewriting the security event trail. */
export declare function resetGuardianStatistics(directory?: string): boolean;
/** Bounded, redacted activity. Never return arbitrary fields from the log. */
export declare function readGuardianActivity(directory?: string, limit?: number): GuardianEvent[];
