import type { RuleResult } from "./types.js";
export declare const OPENCODE_HANDOFF_HEADER = "[OPENCODE_HANDOFF:v1]";
export type HandoffKind = "clarification" | "choice" | "approval";
export type HandoffAutoSelect = "allowed" | "forbidden";
export interface OpenCodeHandoff {
    version: "v1";
    source: "guardian";
    action: "question_required";
    kind: HandoffKind;
    autoSelect: HandoffAutoSelect;
    handoffId: string;
}
export declare const COORDINATION_SYMBOL: unique symbol;
export interface OpenCodeCoordinationRegistry {
    guardian?: {
        version: number;
        supportsHandoff: boolean;
    };
    smartQuestions?: {
        version: number;
        mainAgentOnly?: boolean;
        supportsAutoSelect?: boolean;
    };
}
/**
 * Format an OpenCode handoff descriptor to the versioned text protocol block.
 */
export declare function formatOpenCodeHandoff(handoff: Omit<OpenCodeHandoff, "version" | "source">): string;
/**
 * Parse an OpenCode handoff block from remediation or message text.
 */
export declare function parseOpenCodeHandoff(text: string): OpenCodeHandoff | null;
/**
 * Analyze blocking rule results and produce an appropriate question handoff if user input/choice is required.
 * Relies strictly on rules explicitly requesting handoff through `result.handoff`.
 */
export declare function createHandoffForBlockingResults(results: readonly RuleResult[], sessionID: string, turnKey: string, sequence?: number): OpenCodeHandoff | null;
/**
 * Register Guardian capability in the global OpenCode coordination registry.
 * Returns an idempotent cleanup that restores the prior registration after the
 * last Guardian instance unloads.
 */
export declare function registerGuardianCapability(): () => void;
/**
 * Check if Smart Questions is registered in the in-process capability registry.
 */
export declare function getSmartQuestionsCapability(): OpenCodeCoordinationRegistry["smartQuestions"] | undefined;
