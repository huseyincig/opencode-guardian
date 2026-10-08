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
    sessionID?: string | undefined;
}
export interface GuardianToastScope {
    directory?: string | undefined;
    sessionID?: string | undefined;
}
export type GuardianToastListener = (payload: GuardianToastPayload, scope: GuardianToastScope) => void | Promise<unknown>;
export interface GuardianToastNotifierOptions extends GuardianToastScope {
    client?: unknown;
    context?: unknown;
    enabled?: boolean | undefined;
}
export interface GuardianToastNotifier {
    notify(input: GuardianInterventionInput): void;
}
export declare function sanitizeToastRuleId(raw: unknown): string;
export declare function formatGuardianToast(input: GuardianInterventionInput): GuardianToastPayload;
export declare function registerToastListener(listener: GuardianToastListener, scope?: GuardianToastScope): () => void;
export declare function clearToastListeners(): void;
export declare function dispatchGuardianToast(payload: GuardianToastPayload, options?: GuardianToastNotifierOptions): void;
export declare function createGuardianToastNotifier(options?: GuardianToastNotifierOptions): GuardianToastNotifier;
