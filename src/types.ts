/**
 * opencode-guardian: Core Type Definitions
 */

import type { AgentMutationCapability } from "./agent-capability.js";

export type Severity = "error" | "warn" | "off";

export interface GuardRuleConfig {
  severity?: Severity;
  customPhrases?: string[];
  exceptions?: string[];
  [key: string]: unknown;
}

export interface GuardianSecretsConfig {
  enabled?: boolean;
  replacement?: string;
  customSensitiveKeys?: (string | RegExp)[];
  customSecretValues?: string[];
  includeRuntimeEnv?: boolean;
  safeKeyNames?: string[];
}

export interface GuardConfig {
  enabled?: boolean;
  remediationBudget?: number;
  /** Separate, bounded continuation budget for explicit iterative tasks (0..5). */
  iterationBudget?: number;
  /** Optional strict tool hook; disabled unless explicitly enabled. */
  preflight?: { enabled?: boolean; shellTools?: string[] };
  /** Passive startup update notice; enabled unless explicitly disabled. */
  updateNotice?: { enabled?: boolean };
  /** User-facing intervention toast notification configuration. Enabled by default. */
  notifications?: { enabled?: boolean };
  /** Post-execution tool output secret redaction & LLM context gatekeeper configuration. */
  secrets?: GuardianSecretsConfig | undefined;
  rules?: {
    "discipline/no-evasion"?: Severity | GuardRuleConfig;
    "discipline/no-apology"?: Severity | GuardRuleConfig;
    "quality/no-shortcuts"?: Severity | GuardRuleConfig;
    "integrity/no-stubs"?: Severity | GuardRuleConfig;
    "integrity/no-unverified-claims"?: Severity | GuardRuleConfig;
    "integrity/no-silent-failure"?: Severity | GuardRuleConfig;
    "safety/no-truncation"?: Severity | GuardRuleConfig;
    "safety/destructive-operations"?: Severity | GuardRuleConfig;
    "testing/no-cheat"?: Severity | GuardRuleConfig;
    "security/no-secrets"?: Severity | GuardRuleConfig;
    "manifest/no-ghost-deps"?: Severity | GuardRuleConfig;
    "runtime/circuit-breaker"?: Severity | GuardRuleConfig;
    "task/completion-gate"?: Severity | GuardRuleConfig;
    "task/instruction-fidelity"?: Severity | GuardRuleConfig;
    [ruleName: string]: Severity | GuardRuleConfig | undefined;
  };
}

export interface MessagePart {
  type: string;
  text?: string;
  synthetic?: boolean;
  state?: {
    status?: string;
    input?: Record<string, unknown>;
    output?: unknown;
    error?: unknown;
    raw?: unknown;
    patch?: string;
    patchText?: string;
    metadata?: Record<string, unknown>;
    exitCode?: unknown;
  };
  [key: string]: unknown;
}

export interface SessionMessage {
  info: {
    id: string;
    role: "user" | "assistant" | "system" | string;
    sessionID?: string;
    agent?: string;
    [key: string]: unknown;
  };
  parts: MessagePart[];
}

export type EvidenceKind =
  | "test"
  | "build"
  | "typecheck"
  | "lint"
  | "audit"
  | "git-push"
  | "git-status"
  | "baseline"
  | "install"
  | "file-mutation"
  | "destructive-operation"
  | "generic";

export type EvidenceStatus = "success" | "failure" | "unknown";

export interface EvidenceRecord {
  kind: EvidenceKind;
  status: EvidenceStatus;
  sequence: number;
  toolName: string;
  command?: string;
  signature: string;
  output?: string;
  error?: string;
  exitCode?: number;
  errorFingerprint?: string;
  ambiguousOutcome?: boolean;
  stateFingerprint?: string;
  snapshotFiles?: string[];
  filePath?: string;
}

export interface TurnEvidence {
  records: EvidenceRecord[];
  successfulVerifications: EvidenceRecord[];
  failures: EvidenceRecord[];
  fileMutations: EvidenceRecord[];
  mutatedFiles?: Set<string>;
}

export interface TurnInspectionContext {
  sessionID: string;
  directory: string;
  messages: SessionMessage[];
  currentTurn: SessionMessage[];
  isSubagent?: boolean;
  agentCapability?: AgentMutationCapability | undefined;
  ruleConfig: GuardRuleConfig;
  evidence?: TurnEvidence;
}

export interface RuleFinding {
  ruleId: string;
  pattern: string;
  messageSnippet: string;
  description: string;
  evidence?: string[];
  confidence?: "low" | "medium" | "high";
}

export interface RuleHandoffRequirement {
  required: true;
  kind: "clarification" | "choice" | "approval";
  autoSelect: "allowed" | "forbidden";
}

export interface RuleResult {
  ruleId: string;
  decision: "pass" | "block";
  findings: RuleFinding[];
  remediationPrompt?: string;
  handoff?: RuleHandoffRequirement;
}

export interface GuardRule {
  id: string;
  description: string;
  inspect: (context: TurnInspectionContext) => Promise<RuleResult> | RuleResult;
}
