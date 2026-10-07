import type { SessionMessage } from "./types.js";
export type AgentMutationCapability = "read-only" | "write-allowed" | "write-requires-approval" | "unknown";
export interface AgentMutationEvidence {
    agentName?: string | undefined;
    edit?: ("allow" | "deny" | "ask" | "disabled" | "unset") | undefined;
    bash?: ("allow" | "deny" | "ask" | "disabled" | "unset") | undefined;
    mutatingTools?: string[] | undefined;
    unknownTools?: string[] | undefined;
    reasons: string[];
}
export interface AgentMutationProfile {
    capability: AgentMutationCapability;
    evidence: AgentMutationEvidence;
}
export declare const KNOWN_READ_ONLY_TOOLS: Set<string>;
export declare function isKnownReadOnlyTool(toolName: string): boolean;
export interface NormalizedAgentInput {
    name?: string | undefined;
    tools?: Record<string, boolean> | undefined;
    permission?: unknown;
    permissions?: unknown;
    v1Permission?: {
        edit?: string | undefined;
        bash?: string | Record<string, string> | undefined;
        [key: string]: unknown;
    } | undefined;
    v2Permissions?: Array<{
        permission?: string | undefined;
        action?: string | undefined;
        pattern?: string | undefined;
        resource?: string | undefined;
        effect?: string | undefined;
    }> | undefined;
}
/**
 * Pure policy evaluation to classify mutation capability.
 */
export declare function evaluateAgentMutationProfile(input: NormalizedAgentInput): AgentMutationProfile;
export declare function canSubagentRemediate(profile: AgentMutationProfile): boolean;
export declare function isWriteCapableAgent(context: {
    isSubagent?: boolean;
    agentCapability?: AgentMutationCapability | undefined;
}): boolean;
export declare function getCachedAgentCapability(sessionID: string): AgentMutationProfile | undefined;
export declare function cacheAgentCapability(sessionID: string, profile: AgentMutationProfile): void;
export declare function clearAgentCapability(sessionID: string): void;
export declare function clearAllAgentCapabilities(): void;
/**
 * Resolves capability for a V1 agent via the V1 client.
 */
export declare function resolveV1AgentCapability(client: {
    app?: {
        agents?: (...args: any[]) => Promise<any>;
    } | undefined;
}, directory: string, agentName?: string | undefined, messageTools?: Record<string, boolean> | undefined): Promise<AgentMutationProfile>;
/**
 * Resolves capability for a V2 agent via the V2 context.
 */
export declare function resolveV2AgentCapability(context: {
    agent?: {
        list?: (...args: any[]) => Promise<any>;
    } | undefined;
    session?: {
        get?: (...args: any[]) => Promise<any>;
    } | undefined;
}, sessionID: string, agentName?: string | undefined, messageTools?: Record<string, boolean> | undefined): Promise<AgentMutationProfile>;
export declare function extractAgentNameFromMessages(messages: readonly SessionMessage[]): string | undefined;
