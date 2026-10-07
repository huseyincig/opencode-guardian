/**
 * Safe user-facing toast notifications for Guardian interventions.
 *
 * Dispatches visually distinct notifications (by variant/color and title)
 * at the exact moments Guardian intervenes:
 * - PREFLIGHT BLOCK (red / error): Dangerous tool / shell command blocked
 * - POST REMEDIATION (red / error): Remediation prompt sent to agent
 * - POST WARNING (yellow / warning): Advisory finding recorded
 *
 * Privacy requirement:
 * Raw snippets, source code, command strings, and secrets MUST NOT leak to toasts.
 * Only safe rule IDs, severity, and action taken are included.
 */
export type GuardianToastVariant = "error" | "warning" | "info";
export type GuardianInterventionKind = "preflight-blocked" | "remediation" | "warning";
export interface GuardianToastPayload {
    title: string;
    message: string;
    variant: GuardianToastVariant;
    duration: number;
}
export interface GuardianInterventionInput {
    kind: GuardianInterventionKind;
    ruleIds?: readonly string[] | undefined;
    ruleId?: string | undefined;
    tool?: string | undefined;
}
export type GuardianToastListener = (payload: GuardianToastPayload) => void | Promise<unknown>;
export interface GuardianToastNotifierOptions {
    client?: unknown;
    context?: unknown;
    directory?: string | undefined;
    enabled?: boolean | undefined;
}
export interface GuardianToastNotifier {
    notify(input: GuardianInterventionInput): void;
}
export declare function sanitizeToastRuleId(raw: unknown): string;
export declare function formatGuardianToast(input: GuardianInterventionInput): GuardianToastPayload;
export declare function registerToastListener(listener: GuardianToastListener): () => void;
export declare function clearToastListeners(): void;
export declare function dispatchGuardianToast(payload: GuardianToastPayload, options?: GuardianToastNotifierOptions): void;
export declare function createGuardianToastNotifier(options?: GuardianToastNotifierOptions): GuardianToastNotifier;
