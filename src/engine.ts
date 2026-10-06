import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type {
  GuardConfig,
  GuardRule,
  GuardRuleConfig,
  RuleResult,
  Severity,
  SessionMessage,
  TurnInspectionContext,
} from "./types.js";
import { noEvasionRule } from "./rules/no-evasion.js";
import { noShortcutsRule } from "./rules/no-shortcuts.js";
import { noStubsRule } from "./rules/no-stubs.js";
import { noTruncationRule } from "./rules/no-truncation.js";
import { noCheatRule } from "./rules/no-cheat.js";
import { noSecretsRule, findAllSecretsInCode } from "./rules/no-secrets.js";
import { noGhostDepsRule } from "./rules/no-ghost-deps.js";
import { circuitBreakerRule } from "./rules/circuit-breaker.js";
import { noApologyRule } from "./rules/no-apology.js";
import { noUnverifiedClaimsRule } from "./rules/no-unverified-claims.js";
import { noSilentFailureRule } from "./rules/no-silent-failure.js";
import { destructiveOperationsRule } from "./rules/destructive-operations.js";
import { collectTurnEvidence, type VerificationSnapshot } from "./evidence.js";
import { SessionStateStore } from "./state.js";
import { taskCompletionRule } from "./rules/task-completion.js";
import { instructionFidelityRule } from "./rules/instruction-fidelity.js";
import { extractTaskContract, latestMutationSequence } from "./task-contract.js";
import { createHandoffForBlockingResults, formatOpenCodeHandoff, type OpenCodeHandoff } from "./handoff.js";
import type { AgentMutationCapability } from "./agent-capability.js";

export const REMEDIATION_MARKER = "[opencode-guardian remediation]";

function composeCombinedRemediationPrompt(
  blockingPrompts: string[],
  handoff: OpenCodeHandoff | null
): string {
  if (!handoff) {
    return `${REMEDIATION_MARKER}\n${blockingPrompts.join("\n\n---\n\n")}`;
  }
  return `${REMEDIATION_MARKER}\n\n${formatOpenCodeHandoff(handoff)}\n\n${blockingPrompts.join("\n\n---\n\n")}`;
}

export const BUILTIN_RULES: Record<string, GuardRule> = {
  "discipline/no-evasion": noEvasionRule,
  "discipline/no-apology": noApologyRule,
  "quality/no-shortcuts": noShortcutsRule,
  "integrity/no-stubs": noStubsRule,
  "integrity/no-unverified-claims": noUnverifiedClaimsRule,
  "integrity/no-silent-failure": noSilentFailureRule,
  "safety/no-truncation": noTruncationRule,
  "safety/destructive-operations": destructiveOperationsRule,
  "testing/no-cheat": noCheatRule,
  "security/no-secrets": noSecretsRule,
  "manifest/no-ghost-deps": noGhostDepsRule,
  "runtime/circuit-breaker": circuitBreakerRule,
  "task/completion-gate": taskCompletionRule,
  "task/instruction-fidelity": instructionFidelityRule,
};

export const DEFAULT_CONFIG: GuardConfig = {
  enabled: true,
  remediationBudget: 1,
  iterationBudget: 3,
  rules: {
    "discipline/no-evasion": "error",
    "discipline/no-apology": "error",
    "quality/no-shortcuts": "error",
    "integrity/no-stubs": "error",
    "integrity/no-unverified-claims": "error",
    "integrity/no-silent-failure": "error",
    "safety/no-truncation": "error",
    "safety/destructive-operations": "warn",
    "testing/no-cheat": "error",
    "security/no-secrets": "error",
    "manifest/no-ghost-deps": "error",
    "runtime/circuit-breaker": "error",
    "task/completion-gate": "error",
    "task/instruction-fidelity": "error",
  },
};

export class GuardianConfigError extends Error {
  readonly configPath: string;
  constructor(configPath: string, cause?: unknown) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    super(`[opencode-guardian] Invalid configuration in ${configPath}: ${detail}. Fix or remove the file to prevent unintended security fallbacks.`);
    this.name = "GuardianConfigError";
    this.configPath = configPath;
  }
}

function validateConfig(value: Record<string, unknown>): GuardConfig {
  const fail = (name: string): never => { throw new Error("invalid configuration field: " + name); };
  if (value.enabled !== undefined && typeof value.enabled !== "boolean") fail("enabled");
  for (const name of ["remediationBudget", "iterationBudget"] as const) {
    if (value[name] !== undefined &&
        (typeof value[name] !== "number" || !Number.isInteger(value[name]) ||
         (value[name] as number) < 0 || (value[name] as number) > 5)) fail(name);
  }
  for (const name of ["preflight", "updateNotice"] as const) {
    const item = value[name];
    if (item !== undefined && (!item || typeof item !== "object" ||
        Array.isArray(item) || ((item as Record<string, unknown>).enabled !== undefined &&
        typeof (item as Record<string, unknown>).enabled !== "boolean"))) fail(name);
  }
  const shellTools = (value.preflight as Record<string, unknown> | undefined)?.shellTools;
  if (shellTools !== undefined &&
      (!Array.isArray(shellTools) ||
       !shellTools.every((tool) => typeof tool === "string" && tool.trim().length > 0))) {
    fail("preflight.shellTools");
  }
  if (value.rules !== undefined) {
    if (!value.rules || typeof value.rules !== "object" || Array.isArray(value.rules)) fail("rules");
    for (const [name, setting] of Object.entries(value.rules as Record<string, unknown>)) {
      if (typeof setting === "string") {
        if (!["error", "warn", "off"].includes(setting)) fail("rules." + name);
      } else if (setting && typeof setting === "object" && !Array.isArray(setting)) {
        const rule = setting as Record<string, unknown>;
        if (rule.severity !== undefined && !["error", "warn", "off"].includes(rule.severity as string)) fail("rules." + name + ".severity");
        for (const field of ["customPhrases", "exceptions"]) {
          if (rule[field] !== undefined && (!Array.isArray(rule[field]) ||
              !(rule[field] as unknown[]).every(item => typeof item === "string"))) fail("rules." + name + "." + field);
        }
      } else fail("rules." + name);
    }
  }
  return value as GuardConfig;
}

export function loadConfig(directory?: string): GuardConfig {
  const candidatePaths = [
    directory ? path.resolve(directory, "opencode-guardian.json") : null,
    directory ? path.resolve(directory, ".opencode/opencode-guardian.json") : null,
    path.resolve(os.homedir(), ".config/opencode/opencode-guardian.json"),
    directory ? path.resolve(directory, "opencode-guard.json") : null,
    directory ? path.resolve(directory, ".opencode/opencode-guard.json") : null,
    path.resolve(os.homedir(), ".config/opencode/opencode-guard.json"),
  ].filter(Boolean) as string[];

  for (const configPath of candidatePaths) {
    if (!fs.existsSync(configPath)) continue;

    try {
      const raw = fs.readFileSync(configPath, "utf8");
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("configuration root must be a JSON object");
      }
      return validateConfig(parsed as Record<string, unknown>);
    } catch (error) {
      throw new GuardianConfigError(configPath, error);
    }
  }

  return DEFAULT_CONFIG;
}

function isSyntheticUserMessage(message: SessionMessage): boolean {
  return (
    message.info.role === "user" &&
    Boolean(message.parts?.some((part) => part.synthetic === true))
  );
}

function isGuardianRemediationMessage(message: SessionMessage): boolean {
  if (message.info.role !== "user") return false;
  return Boolean(
    message.parts?.some(
      (part) =>
        part.type === "text" &&
        typeof part.text === "string" &&
        part.text.trimStart().startsWith(REMEDIATION_MARKER)
    )
  );
}

export const NATIVE_QUESTION_TOOLS = new Set([
  "ask_question",
  "question",
  "form",
  "form_create",
  "create_form",
  "session.form",
]);

function isNativeQuestionTool(toolRaw: string): boolean {
  if (!toolRaw) return false;
  const name = toolRaw.toLowerCase().trim();
  const baseName = name.includes(".") ? (name.split(".").pop() ?? name) : name;
  return NATIVE_QUESTION_TOOLS.has(name) || NATIVE_QUESTION_TOOLS.has(baseName);
}

export function extractCurrentTurn(messages: SessionMessage[]): {
  isSubagent: boolean;
  isRemediationResponse: boolean;
  currentTurn: SessionMessage[];
  turnKey: string;
} {
  const lastUserMessage = messages.findLast(
    (message) =>
      message.info.role === "user" &&
      (!isSyntheticUserMessage(message) || isGuardianRemediationMessage(message))
  );
  const isRemediationResponse = Boolean(
    lastUserMessage && isGuardianRemediationMessage(lastUserMessage)
  );

  const lastHumanUserIndex = messages.findLastIndex(
    (m) =>
      m.info.role === "user" &&
      !isGuardianRemediationMessage(m) &&
      !isSyntheticUserMessage(m)
  );
  const lastHumanUser =
    lastHumanUserIndex >= 0 ? messages[lastHumanUserIndex] : undefined;

  const currentTurn =
    lastHumanUserIndex < 0 ? messages : messages.slice(lastHumanUserIndex);

  const activeAgent = currentTurn.findLast(
    (m) => typeof m.info?.agent === "string" && m.info.agent.length > 0
  )?.info.agent ?? messages.findLast(
    (m) => typeof m.info?.agent === "string" && m.info.agent.length > 0
  )?.info.agent;
  const isSubagent = Boolean(activeAgent && activeAgent !== "orchestrator");

  return {
    isSubagent,
    isRemediationResponse,
    currentTurn,
    turnKey: lastHumanUser?.info.id ?? "no-human-user",
  };
}

function normalizeSeverity(value: unknown): Severity | undefined {
  return value === "error" || value === "warn" || value === "off"
    ? value
    : undefined;
}

function sanitizeRuleConfig(setting: unknown): GuardRuleConfig {
  if (!setting || typeof setting !== "object" || Array.isArray(setting)) {
    return {};
  }

  const config = { ...(setting as Record<string, unknown>) } as GuardRuleConfig;
  if (
    config.severity !== undefined &&
    !["error", "warn", "off"].includes(config.severity)
  ) {
    delete config.severity;
  }

  if (config.customPhrases !== undefined) {
    if (Array.isArray(config.customPhrases)) {
      config.customPhrases = config.customPhrases.filter(
        (value): value is string =>
          typeof value === "string" && value.trim().length > 0
      );
    } else {
      delete config.customPhrases;
    }
  }

  if (config.exceptions !== undefined) {
    if (Array.isArray(config.exceptions)) {
      config.exceptions = config.exceptions.filter(
        (value): value is string =>
          typeof value === "string" && value.trim().length > 0
      );
    } else {
      delete config.exceptions;
    }
  }

  return config;
}

export interface EngineExecutionResult {
  decision: "pass" | "block";
  results: RuleResult[];
  combinedRemediationPrompt?: string;
  rollback?: () => void;
  remediationStatus?: "verified" | "failed" | "unverified";
  pendingRemediationRules?: string[];
}

export class GuardEngine {
  private config: GuardConfig;
  private rules: Map<string, GuardRule> = new Map();
  private inspectedMessages: Map<string, string> = new Map();
  private sessionState = new SessionStateStore();

  constructor(config?: GuardConfig) {
    this.config = {
      ...DEFAULT_CONFIG,
      ...config,
      rules: {
        ...DEFAULT_CONFIG.rules,
        ...config?.rules,
      },
    };
    for (const rule of Object.values(BUILTIN_RULES)) {
      this.registerRule(rule);
    }
  }

  public registerRule(rule: GuardRule): void {
    this.rules.set(rule.id, rule);
  }

  public forgetSession(sessionID: string): void {
    this.inspectedMessages.delete(sessionID);
    this.sessionState.forget(sessionID);
  }

  public rollbackInspection(sessionID: string): void {
    this.inspectedMessages.delete(sessionID);
  }

  public async inspect(
    sessionID: string,
    directory: string,
    messages: SessionMessage[],
    snapshots?: ReadonlyMap<string, VerificationSnapshot>,
    options?: { isSubagent?: boolean; agentCapability?: AgentMutationCapability }
  ): Promise<EngineExecutionResult> {
    if (this.config.enabled === false || messages.length === 0) {
      return { decision: "pass", results: [] };
    }

    const lastAssistant = messages.findLast((m) => m.info.role === "assistant");
    const messageID = lastAssistant?.info.id;
    if (!messageID || this.inspectedMessages.get(sessionID) === messageID) {
      return { decision: "pass", results: [] };
    }

    const {
      isSubagent: inferredSubagent,
      isRemediationResponse,
      currentTurn,
      turnKey,
    } = extractCurrentTurn(messages);
    const isSubagent = options?.isSubagent ?? inferredSubagent;
    const firstCurrentMessage = currentTurn[0];
    if (!firstCurrentMessage) {
      return { decision: "pass", results: [] };
    }

    const activeHandoff = !isSubagent ? this.sessionState.getActiveHandoff(sessionID) : undefined;
    if (activeHandoff?.status === "question_presented") {
      const hasUserReply = currentTurn.some((msg) =>
        msg.info.role === "user" && !isGuardianRemediationMessage(msg)
      );
      if (hasUserReply) {
        this.sessionState.clearActiveHandoff(sessionID);
      }
    } else if (activeHandoff?.status === "handed_off") {
      const askedQuestion = currentTurn.some((msg) =>
        msg.info.role === "assistant" &&
        msg.parts?.some((part) => {
          const toolRaw =
            typeof part.tool === "string"
              ? part.tool
              : typeof part.name === "string"
              ? part.name
              : "";
          return isNativeQuestionTool(toolRaw);
        })
      );
      if (askedQuestion) {
        this.sessionState.setActiveHandoff(sessionID, {
          ...activeHandoff,
          status: "question_presented",
        });
        return { decision: "pass", results: [] };
      }
    }

    const contract = extractTaskContract(currentTurn);
    const evidence = collectTurnEvidence(currentTurn, directory, snapshots);
    const lastGuardianIndex = currentTurn.findLastIndex(isGuardianRemediationMessage);
    const freshTurn = isRemediationResponse && lastGuardianIndex >= 0
      ? [firstCurrentMessage, ...currentTurn.slice(lastGuardianIndex + 1)]
      : currentTurn;
    // Reinspect only new work for the other rules; the completion gate alone
    // needs the full human-turn history to evaluate progress across rounds.
    const freshEvidence = freshTurn === currentTurn
      ? evidence
      : collectTurnEvidence(freshTurn, directory, snapshots);
    const pendingRules = isRemediationResponse
      ? this.sessionState.getPendingRemediation(sessionID, turnKey) ?? []
      : [];
    const pendingFiles = isRemediationResponse
      ? this.sessionState.getPendingRemediationFiles(sessionID, turnKey)
      : [];
    const results: RuleResult[] = [];
    const blockingPrompts: string[] = [];
    const blockingResults: RuleResult[] = [];

    for (const [ruleId, rule] of this.rules.entries()) {
      const isCompletionGate = ruleId === "task/completion-gate";
      const ruleSetting = this.config.rules?.[ruleId];
      const ruleConfig = sanitizeRuleConfig(
        typeof ruleSetting === "object" ? ruleSetting : {}
      );
      const defaultSetting = DEFAULT_CONFIG.rules?.[ruleId];
      const configuredSeverity =
        typeof ruleSetting === "string"
          ? normalizeSeverity(ruleSetting)
          : normalizeSeverity(
              ruleSetting &&
                typeof ruleSetting === "object" &&
                !Array.isArray(ruleSetting)
                ? (ruleSetting as GuardRuleConfig).severity
                : undefined
            );
      const explicitlyInvalidSeverity =
        (typeof ruleSetting === "string" &&
          normalizeSeverity(ruleSetting) === undefined) ||
        (ruleSetting &&
          typeof ruleSetting === "object" &&
          !Array.isArray(ruleSetting) &&
          "severity" in ruleSetting &&
          (ruleSetting as GuardRuleConfig).severity !== undefined &&
          normalizeSeverity((ruleSetting as GuardRuleConfig).severity) ===
            undefined);
      const defaultSeverity =
        normalizeSeverity(defaultSetting) ??
        normalizeSeverity(
          defaultSetting && typeof defaultSetting === "object"
            ? defaultSetting.severity
            : undefined
        ) ??
        "error";
      // Invalid explicit severity is a config error. Fail open to warn instead
      // of unexpectedly turning a typo into a blocking rule.
      const severity = explicitlyInvalidSeverity
        ? "warn"
        : configuredSeverity ?? defaultSeverity;

      if (severity === "off") continue;

      const context: TurnInspectionContext = {
        sessionID,
        directory,
        messages,
        currentTurn: isCompletionGate ? currentTurn : freshTurn,
        isSubagent,
        ruleConfig,
        evidence: isCompletionGate ? evidence : freshEvidence,
      };

      const res = await rule.inspect(context);
      results.push(res);

      if (
        severity !== "warn" &&
        res.decision === "block" &&
        res.remediationPrompt
      ) {
        blockingPrompts.push(res.remediationPrompt);
        blockingResults.push(res);
      }
    }

    this.inspectedMessages.set(sessionID, messageID);

    const canSelfRemediate = !isSubagent || options?.agentCapability === "write-allowed";

    if (blockingPrompts.length > 0) {
      if (!canSelfRemediate) {
        return {
          decision: "block",
          results,
        };
      }
      const completion = blockingResults.find(
        (result) => result.ruleId === "task/completion-gate"
      );
      if (completion && contract?.iterativeReview) {
        const configured = this.config.iterationBudget;
        const budget = typeof configured === "number" && Number.isFinite(configured)
          ? Math.max(0, Math.min(5, Math.floor(configured)))
          : 3;
        // A second prompt requires observable progress. A repeated final
        // message without any new tool work cannot cause an infinite loop.
        const progressKey = `${latestMutationSequence(evidence)}:${evidence.records.length}`;
        if (!this.sessionState.canContinue(sessionID, turnKey, progressKey, budget)) {
          return { decision: "pass", results };
        }
        this.sessionState.recordContinuation(sessionID, turnKey, progressKey);
        const sequence = this.sessionState.nextHandoffSequence(sessionID, turnKey);
        const handoff = !isSubagent
          ? createHandoffForBlockingResults(blockingResults, sessionID, turnKey, sequence)
          : null;
        if (handoff) {
          this.sessionState.setActiveHandoff(sessionID, {
            handoffId: handoff.handoffId,
            kind: handoff.kind,
            autoSelect: handoff.autoSelect,
            status: "handed_off",
          });
        }
        return {
          decision: "block",
          results,
          combinedRemediationPrompt: composeCombinedRemediationPrompt(blockingPrompts, handoff),
          rollback: () => {
            this.inspectedMessages.delete(sessionID);
            this.sessionState.rollbackContinuation(sessionID, turnKey, progressKey);
            if (handoff) this.sessionState.clearActiveHandoff(sessionID);
          },
        };
      }

      const configuredBudget =
        typeof this.config.remediationBudget === "number" &&
        Number.isFinite(this.config.remediationBudget)
          ? Math.floor(this.config.remediationBudget)
          : 1;
      const budget = Math.max(0, Math.min(5, configuredBudget));
      const remediationMessagesCount = currentTurn.filter(isGuardianRemediationMessage).length;
      const fingerprint = blockingResults
        .map((result) => {
          const findingKey = result.findings
            .map((finding) => `${finding.pattern}:${finding.messageSnippet}`)
            .sort()
            .join("|");
          return `${result.ruleId}:${findingKey}`;
        })
        .sort()
        .join("||");

      if (
        (!contract?.iterativeReview && remediationMessagesCount >= budget) ||
        !this.sessionState.canRemediate(
          sessionID,
          turnKey,
          fingerprint,
          budget
        )
      ) {
        this.sessionState.clearPendingRemediation(sessionID);
        return {
          decision: "pass",
          results,
          ...(isRemediationResponse
            ? { remediationStatus: pendingRules.length ? "failed" as const : "unverified" as const,
                pendingRemediationRules: pendingRules }
            : {}),
        };
      }

      this.sessionState.recordRemediation(sessionID, turnKey, fingerprint);
      this.sessionState.setPendingRemediation(
        sessionID,
        turnKey,
        blockingResults.map((r) => r.ruleId),
        [...(evidence.mutatedFiles ?? [])]
      );
      const sequence = this.sessionState.nextHandoffSequence(sessionID, turnKey);
      const handoff = !isSubagent
        ? createHandoffForBlockingResults(blockingResults, sessionID, turnKey, sequence)
        : null;
      if (handoff) {
        this.sessionState.setActiveHandoff(sessionID, {
          handoffId: handoff.handoffId,
          kind: handoff.kind,
          autoSelect: handoff.autoSelect,
          status: "handed_off",
        });
      }
      return {
        decision: "block",
        results,
        combinedRemediationPrompt: composeCombinedRemediationPrompt(blockingPrompts, handoff),
        rollback: () => {
          this.inspectedMessages.delete(sessionID);
          this.sessionState.rollbackRemediation(sessionID, turnKey, fingerprint);
          this.sessionState.clearPendingRemediation(sessionID);
          if (handoff) this.sessionState.clearActiveHandoff(sessionID);
        },
      };
    }

    if (isRemediationResponse) {
      // Absence of new findings is not proof of correction. A synthetic reply
      // without any successful follow-up work must never close an obligation.
      const successfulFresh = freshEvidence.records.filter(
        (record) => record.status === "success"
      );
      const fixedPaths = new Set(
        successfulFresh.filter((record) => record.kind === "file-mutation")
          .map((record) => record.filePath).filter((file): file is string => !!file)
      );
      const hasProgress = successfulFresh.some((record) =>
        ["file-mutation", "test", "build", "typecheck", "lint", "audit"].includes(record.kind)
      );
      const originalFindingsRemain = results.some(
        (result) => pendingRules.includes(result.ruleId) && result.findings.length > 0
      );
      let verified = pendingRules.length > 0 && hasProgress && !originalFindingsRemain;
      if (verified && pendingRules.includes("security/no-secrets")) {
        // Check actual files, not only the proposed tool input. No file on
        // disk, an out-of-scope path or an unreadable file means unverified.
        verified = pendingFiles.length > 0 && pendingFiles.every((rel) => {
          if (!fixedPaths.has(rel)) return false;
          const full = path.resolve(directory, rel);
          const relative = path.relative(path.resolve(directory), full);
          if (relative === ".." || relative.startsWith(".." + path.sep) ||
              path.isAbsolute(relative)) return false;
          try {
            const realRoot = fs.realpathSync(path.resolve(directory));
            const realFile = fs.realpathSync(full);
            const realRelative = path.relative(realRoot, realFile);
            if (realRelative === ".." || realRelative.startsWith(".." + path.sep) ||
                path.isAbsolute(realRelative)) return false;
            const info = fs.lstatSync(full);
            return info.isFile() && info.size <= 2 * 1024 * 1024 &&
              findAllSecretsInCode(fs.readFileSync(full, "utf8"), rel).length === 0;
          } catch {
            return false;
          }
        });
      }
      // Recheck actual files: a clean new turn may leave the original TODO,
      // test bypass or incomplete stub unchanged on disk.
      const sourceRules = pendingRules.filter((rule) =>
        ["quality/no-shortcuts", "integrity/no-stubs", "testing/no-cheat"].includes(rule));
      if (verified && sourceRules.length) {
        verified = pendingFiles.length > 0;
        for (const rel of pendingFiles) {
          if (!verified || !fixedPaths.has(rel)) { verified = false; break; }
          const root = path.resolve(directory);
          const full = path.resolve(root, rel);
          const scoped = path.relative(root, full);
          if (scoped === ".." || scoped.startsWith(".." + path.sep) || path.isAbsolute(scoped)) {
            verified = false; break;
          }
          let content: string;
          try {
            const actual = path.relative(fs.realpathSync(root), fs.realpathSync(full));
            if (actual === ".." || actual.startsWith(".." + path.sep) || path.isAbsolute(actual)) {
              verified = false; break;
            }
            const info = fs.lstatSync(full);
            if (!info.isFile() || info.size > 2 * 1024 * 1024) {
              verified = false; break;
            }
            content = fs.readFileSync(full, "utf8");
          } catch { verified = false; break; }
          for (const ruleID of sourceRules) {
            const rule = this.rules.get(ruleID);
            if (!rule) { verified = false; break; }
            const configuredRule = this.config.rules?.[ruleID];
            const recheckRuleConfig = sanitizeRuleConfig(
              configuredRule && typeof configuredRule === "object" && !Array.isArray(configuredRule)
                ? configuredRule
                : {}
            );
            const checked = await rule.inspect({
              sessionID, directory, messages,
              currentTurn: [firstCurrentMessage, {
                info: { id: "guardian-current-file", role: "assistant" },
                parts: [{ type: "tool", tool: "write_to_file",
                  state: { status: "completed", input: { path: rel, content } } }],
              }],
              isSubagent, ruleConfig: recheckRuleConfig, evidence: freshEvidence,
            });
            if (checked.findings.length > 0) { verified = false; break; }
          }
        }
      }
      if (verified && pendingRules.some((rule) =>
        ["integrity/no-unverified-claims", "integrity/no-silent-failure"].includes(rule)) &&
        !successfulFresh.some((record) =>
          ["test", "build", "typecheck", "lint", "audit"].includes(record.kind))) {
        verified = false;
      }
      if (verified && pendingRules.some((rule) =>
        !["security/no-secrets", "quality/no-shortcuts", "integrity/no-stubs",
          "testing/no-cheat", "integrity/no-unverified-claims",
          "integrity/no-silent-failure", "task/completion-gate"].includes(rule))) {
        verified = false;
      }
      const remediationStatus = originalFindingsRemain
        ? "failed" as const
        : verified ? "verified" as const : "unverified" as const;
      this.sessionState.clearPendingRemediation(sessionID);
      return { decision: "pass", results, remediationStatus,
        pendingRemediationRules: pendingRules };
    }

    return {
      decision: "pass",
      results,
    };
  }
}
