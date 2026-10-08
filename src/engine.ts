import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import type {
  GuardConfig,
  GuardRule,
  GuardRuleConfig,
  RuleFinding,
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
import {
  extractTaskContract,
  isSourceReviewEvidence,
  latestMutationSequence,
} from "./task-contract.js";
import { createHandoffForBlockingResults, formatOpenCodeHandoff, type OpenCodeHandoff } from "./handoff.js";
import type { AgentMutationCapability } from "./agent-capability.js";
import { isTrustedGuardianMetadata } from "./provenance.js";

export const REMEDIATION_MARKER = "[opencode-guardian remediation]";

function findingIdentity(ruleId: string, finding: RuleFinding): string {
  const semantic = finding.fingerprint
    ? ["explicit", finding.filePath ?? "", finding.fingerprint]
    : ["fallback", finding.filePath ?? "", finding.pattern, finding.messageSnippet];
  const digest = createHash("sha256")
    .update(semantic.join("\u0000"))
    .digest("hex")
    .slice(0, 24);
  return `${ruleId}:${digest}`;
}

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
  secrets: {
    enabled: true,
    replacement: "[REDACTED]",
  },
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
    const configName = path.basename(configPath);
    const detail =
      cause instanceof Error &&
      cause.message.startsWith("invalid configuration value:")
        ? cause.message
        : "could not parse or validate configuration";
    super(`[opencode-guardian] Invalid configuration in ${configName}: ${detail}. Fix or remove the file to prevent unintended security fallbacks.`);
    this.name = "GuardianConfigError";
    this.configPath = configName;
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
  for (const name of ["preflight", "updateNotice", "notifications"] as const) {
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
  if (value.secrets !== undefined) {
    if (!value.secrets || typeof value.secrets !== "object" || Array.isArray(value.secrets)) fail("secrets");
    const sec = value.secrets as Record<string, unknown>;
    if (sec.enabled !== undefined && typeof sec.enabled !== "boolean") fail("secrets.enabled");
    if (sec.replacement !== undefined && typeof sec.replacement !== "string") fail("secrets.replacement");
    if (sec.includeRuntimeEnv !== undefined && typeof sec.includeRuntimeEnv !== "boolean") fail("secrets.includeRuntimeEnv");
    if (sec.customSensitiveKeys !== undefined && (!Array.isArray(sec.customSensitiveKeys) || !sec.customSensitiveKeys.every(k => typeof k === "string" || k instanceof RegExp))) {
      fail("secrets.customSensitiveKeys");
    }
    if (sec.customSecretValues !== undefined && (!Array.isArray(sec.customSecretValues) || !sec.customSecretValues.every(v => typeof v === "string"))) {
      fail("secrets.customSecretValues");
    }
    if (sec.safeKeyNames !== undefined && (!Array.isArray(sec.safeKeyNames) || !sec.safeKeyNames.every(k => typeof k === "string"))) {
      fail("secrets.safeKeyNames");
    }
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

export function resolveEffectiveConfig(
  base: GuardConfig,
  rawOptions?: unknown
): GuardConfig {
  const options =
    rawOptions && typeof rawOptions === "object" && !Array.isArray(rawOptions)
      ? { ...(rawOptions as Record<string, unknown>) }
      : {};

  const legacySecrets: Record<string, unknown> = {};
  if (typeof options.replacement === "string") {
    legacySecrets.replacement = options.replacement;
  }
  if (Array.isArray(options.customSensitiveKeys)) {
    legacySecrets.customSensitiveKeys = options.customSensitiveKeys;
  }
  if (Array.isArray(options.customSecretValues)) {
    legacySecrets.customSecretValues = options.customSecretValues;
  }

  const overlay: Record<string, unknown> = {};
  for (const key of [
    "enabled",
    "remediationBudget",
    "iterationBudget",
    "preflight",
    "updateNotice",
    "notifications",
    "secrets",
    "rules",
  ] as const) {
    if (options[key] !== undefined) overlay[key] = options[key];
  }
  if (Object.keys(legacySecrets).length > 0) {
    overlay.secrets = {
      ...(overlay.secrets && typeof overlay.secrets === "object" && !Array.isArray(overlay.secrets)
        ? overlay.secrets as Record<string, unknown>
        : {}),
      ...legacySecrets,
    };
  }

  const validated = validateConfig(overlay);
  const mergedRules: NonNullable<GuardConfig["rules"]> = {
    ...base.rules,
  };
  for (const [ruleID, next] of Object.entries(validated.rules ?? {})) {
    const previous = mergedRules[ruleID];
    if (next && typeof next === "object" && !Array.isArray(next)) {
      const previousObject =
        typeof previous === "string"
          ? { severity: previous }
          : previous && typeof previous === "object" && !Array.isArray(previous)
            ? previous
            : {};
      mergedRules[ruleID] = {
        ...previousObject,
        ...next,
      };
    } else {
      mergedRules[ruleID] = next;
    }
  }

  return {
    ...base,
    ...validated,
    preflight: {
      ...base.preflight,
      ...validated.preflight,
    },
    updateNotice: {
      ...base.updateNotice,
      ...validated.updateNotice,
    },
    notifications: {
      ...base.notifications,
      ...validated.notifications,
    },
    secrets: {
      ...base.secrets,
      ...validated.secrets,
    },
    rules: mergedRules,
  };
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

function isSyntheticUserMessage(
  message: SessionMessage,
  sessionID?: string
): boolean {
  return (
    message.info.role === "user" &&
    Boolean(
      message.parts?.some(
        (part) =>
          part.synthetic === true ||
          isTrustedGuardianMetadata(sessionID, part.metadata, "visible")
      )
    )
  );
}

function isGuardianRemediationMessage(
  message: SessionMessage,
  sessionID?: string
): boolean {
  if (message.info.role !== "user") return false;
  return Boolean(
    message.parts?.some((part) => {
      const marker =
        part.type === "text" &&
        part.synthetic === true &&
        typeof part.text === "string" &&
        part.text.trimStart().startsWith(REMEDIATION_MARKER);
      if (!marker) return false;
      // Provenance is session-scoped. Without a session identity there is no
      // safe way to prove that a synthetic marker came from Guardian.
      return Boolean(
        sessionID &&
        isTrustedGuardianMetadata(sessionID, part.metadata, "remediation")
      );
    })
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

export function extractCurrentTurn(
  messages: SessionMessage[],
  sessionID?: string
): {
  isSubagent: boolean;
  isRemediationResponse: boolean;
  currentTurn: SessionMessage[];
  turnKey: string;
} {
…[nc: wire response truncated]…
)
          );
          return keys.length > 0 ? keys : [`${result.ruleId}:block`];
        })
      )).sort();

      const blockingRuleIds = blockingResults.map((r) => r.ruleId);

      const maxTurnRemediations = contract?.iterativeReview
        ? Math.max(5, this.config.iterationBudget ?? 3)
        : Math.max(
            8,
            Math.min(32, this.rules.size * Math.max(1, budget))
          );

      if (
        !this.sessionState.canRemediate(
          sessionID,
          turnKey,
          findingFingerprints,
          blockingRuleIds,
          budget,
          maxTurnRemediations
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
      this.sessionState.recordRemediation(
        sessionID,
        turnKey,
        findingFingerprints,
        blockingRuleIds
      );
      const blockingFiles = Array.from(new Set(
        blockingResults.flatMap((result) =>
          result.findings.flatMap((finding) =>
            finding.filePath ? [finding.filePath] : []
          )
        )
      ));
      const blockingFindingKeys = Array.from(new Set(
        blockingResults.flatMap((result) =>
          result.findings.map((finding) =>
            findingIdentity(result.ruleId, finding)
          )
        )
      ));
      this.sessionState.setPendingRemediation(
        sessionID,
        turnKey,
        blockingRuleIds,
        blockingFiles,
        blockingFindingKeys
      );
      const sequence = this.sessionState.nextHandoffSequence(sessionID, turnKey);
      const handoff = !isSubagent
        ? createHandoffForBlockingResults(blockingResults, sessionID, turnKey, sequence)
        : null;
      if (handoff) {
        this.sessionState.setActiveHandoff(sessionID, {
          handoffId: handoff.handoffId,
          turnKey,
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
          this.sessionState.rollbackRemediation(
            sessionID,
            turnKey,
            findingFingerprints,
            blockingRuleIds
          );
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
      const pendingFindingSet = new Set(pendingFindingKeys);
      const originalFindingsRemain = results.some(
        (result) =>
          pendingRules.includes(result.ruleId) &&
          result.findings.some((finding) =>
            pendingFindingSet.has(findingIdentity(result.ruleId, finding))
          )
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
            const originalSourceFindingRemains = checked.findings.some(
              (finding) =>
                pendingFindingSet.has(findingIdentity(ruleID, finding))
            );
            if (originalSourceFindingRemains) { verified = false; break; }
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
