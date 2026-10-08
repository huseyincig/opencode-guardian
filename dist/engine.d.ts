import type { GuardConfig, GuardRule, RuleResult, SessionMessage } from "./types.js";
import { type VerificationSnapshot } from "./evidence.js";
import type { AgentMutationCapability } from "./agent-capability.js";
export declare const REMEDIATION_MARKER = "[opencode-guardian remediation]";
export declare const BUILTIN_RULES: Record<string, GuardRule>;
export declare const DEFAULT_CONFIG: GuardConfig;
export declare class GuardianConfigError extends Error {
    readonly configPath: string;
    constructor(configPath: string, cause?: unknown);
}
export declare function resolveEffectiveConfig(base: GuardConfig, rawOptions?: unknown): GuardConfig;
export declare function loadConfig(directory?: string): GuardConfig;
export declare const NATIVE_QUESTION_TOOLS: Set<string>;
export declare function extractCurrentTurn(messages: SessionMessage[], sessionID?: string): {
    isSubagent: boolean;
    isRemediationResponse: boolean;
    currentTurn: SessionMessage[];
    turnKey: string;
};
export interface EngineExecutionResult {
    decision: "pass" | "block";
    results: RuleResult[];
    combinedRemediationPrompt?: string;
    rollback?: () => void;
    remediationStatus?: "verified" | "failed" | "unverified";
    pendingRemediationRules?: string[];
}
export declare class GuardEngine {
    private config;
    private rules;
    private inspectedMessages;
    private sessionState;
    constructor(config?: GuardConfig);
    registerRule(rule: GuardRule): void;
    forgetSession(sessionID: string): void;
    rollbackInspection(sessionID: string): void;
    inspect(sessionID: string, directory: string, messages: SessionMessage[], snapshots?: ReadonlyMap<string, VerificationSnapshot>, options?: {
        isSubagent?: boolean;
        agentCapability?: AgentMutationCapability | undefined;
    }): Promise<EngineExecutionResult>;
}
