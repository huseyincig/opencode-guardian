import type { GuardConfig, GuardRule, RuleResult, SessionMessage } from "./types.js";
export declare const REMEDIATION_MARKER = "[opencode-guardian remediation]";
export declare const BUILTIN_RULES: Record<string, GuardRule>;
export declare class GuardianConfigError extends Error {
    readonly configPath: string;
    constructor(configPath: string, cause?: unknown);
}
export declare function loadConfig(directory?: string): GuardConfig;
export declare function extractCurrentTurn(messages: SessionMessage[]): {
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
    inspect(sessionID: string, directory: string, messages: SessionMessage[]): Promise<EngineExecutionResult>;
}
