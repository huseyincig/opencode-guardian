import type { EvidenceKind } from "./types.js";
/**
 * Multilingual signals only; never a safety-policy decision by themselves.
 * Tasks, permissions, and verification outcomes are evaluated through the
 * same language-neutral contract/evidence engine regardless of locale.
 *
 * The terms here intentionally target explicit, high-confidence instructions.
 * An unknown dialect, paraphrase, or ambiguous request returns no new duty;
 * the original user request is still passed to the agent unmodified.
 */
export type VerificationKind = "test" | "build" | "typecheck" | "lint" | "audit";
/** Examples, code and quoted commands do not create new task duties. */
export declare function sanitizeUserInstruction(text: string): string;
export interface InternationalTaskSignals {
    locale: string;
    iterativeReview: boolean;
    requiresSourceReview: boolean;
    requiredVerifications: VerificationKind[];
    explicitAction: boolean;
    /** These are indicators, not a verified interpretation of arbitrary prose. */
    evidence: readonly string[];
}
/**
 * The output is locale-neutral; only the extraction of explicit signals is
 * localized. Unknown or conflicted wording does not create a mandatory task.
 */
export declare function extractInternationalSignals(input: string): InternationalTaskSignals | undefined;
export interface InternationalNegations {
    iteration: boolean;
    action: boolean;
    test: boolean;
}
export declare function extractInternationalNegations(input: string): InternationalNegations;
export declare const SUPPORTED_SIGNAL_LOCALES: readonly string[];
export type AgentReportState = "completed" | "blocked" | "unknown";
export declare function classifyInternationalAgentReport(input: string): AgentReportState;
export declare function detectInternationalHistoricalRefusal(userInstruction: string, assistantResponse: string): string | undefined;
export declare function classifyAgentReport(input: string): {
    state: AgentReportState;
    hasClearBlocker: boolean;
    isClosing: boolean;
};
export declare function isExploratoryPrompt(text: string): boolean;
export declare function deniedVerification(text: string, kind: VerificationKind): boolean;
export interface AdvisoryTaskSignals {
    explicitAction: boolean;
    iterativeReview: boolean;
    requiresSourceReview: boolean;
    requiredVerifications: VerificationKind[];
    negatedLoop: boolean;
    exploratory: boolean;
    signalLocale?: string;
}
export declare function extractAdvisoryTaskSignals(body: string): AdvisoryTaskSignals;
export interface InstructionFidelitySignals {
    hasViolation: boolean;
    type?: "historical-refusal" | "redundant-handoff";
    internationalLocale?: string;
}
export declare function detectInstructionFidelitySignals(instruction: string, prose: string, observableWork: boolean): InstructionFidelitySignals;
export interface AdvisoryClaimPattern {
    name: string;
    kind?: EvidenceKind;
    regex: RegExp;
    mode?: "verification";
}
export declare function isUncertaintyClaim(sentence: string): boolean;
export declare function getClaimPatterns(): AdvisoryClaimPattern[];
export declare function isAuthorizedGitClean(cleanRequest: string, command: string): boolean;
export declare function isImperativeExecutionRequest(request: string): boolean;
export declare function isDeleteTargetRequested(request: string): boolean;
export declare function isWholeWorkspaceDeleteRequested(request: string): boolean;
export declare function isExplicitlyAllowedSudo(request: string): boolean;
export declare function isSqlDestructionRequested(request: string): boolean;
export declare const SQL_TARGET_CONTEXT_REGEX: RegExp;
export declare function isAuthorizedTestEdit(text?: string): boolean;
export declare function isTestBypassProhibited(userInstruction: string): boolean;
export declare function isSpecificTestBypassAuthorized(userInstruction: string, pattern: string): boolean;
export declare function isAuthorizedStubOrPlaceholder(text?: string): boolean;
export declare function isPlaceholderProhibited(userInstruction: string): boolean;
export declare function isCodePlaceholderRequested(userInstruction: string): boolean;
export interface ApologyPattern {
    name: string;
    regex: RegExp;
}
export declare function getApologyPatterns(): ApologyPattern[];
