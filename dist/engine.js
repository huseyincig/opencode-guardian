import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { noEvasionRule } from "./rules/no-evasion.js";
import { noShortcutsRule } from "./rules/no-shortcuts.js";
import { noStubsRule } from "./rules/no-stubs.js";
import { noTruncationRule } from "./rules/no-truncation.js";
import { noCheatRule } from "./rules/no-cheat.js";
import { noSecretsRule } from "./rules/no-secrets.js";
import { noGhostDepsRule } from "./rules/no-ghost-deps.js";
import { circuitBreakerRule } from "./rules/circuit-breaker.js";
import { noApologyRule } from "./rules/no-apology.js";
import { noUnverifiedClaimsRule } from "./rules/no-unverified-claims.js";
import { noSilentFailureRule } from "./rules/no-silent-failure.js";
import { destructiveOperationsRule } from "./rules/destructive-operations.js";
import { collectTurnEvidence } from "./evidence.js";
import { SessionStateStore } from "./state.js";
import { taskCompletionRule } from "./rules/task-completion.js";
import { instructionFidelityRule } from "./rules/instruction-fidelity.js";
import { extractTaskContract, latestMutationSequence } from "./task-contract.js";
export const REMEDIATION_MARKER = "[opencode-guardian remediation]";
export const BUILTIN_RULES = {
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
const DEFAULT_CONFIG = {
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
    configPath;
    constructor(configPath, cause) {
        const detail = cause instanceof Error ? cause.message : String(cause);
        super(`[opencode-guardian] Invalid configuration in ${configPath}: ${detail}. Fix or remove the file to prevent unintended security fallbacks.`);
        this.name = "GuardianConfigError";
        this.configPath = configPath;
    }
}
export function loadConfig(directory) {
    const candidatePaths = [
        directory ? path.resolve(directory, "opencode-guardian.json") : null,
        directory ? path.resolve(directory, ".opencode/opencode-guardian.json") : null,
        path.resolve(os.homedir(), ".config/opencode/opencode-guardian.json"),
        directory ? path.resolve(directory, "opencode-guard.json") : null,
        directory ? path.resolve(directory, ".opencode/opencode-guard.json") : null,
        path.resolve(os.homedir(), ".config/opencode/opencode-guard.json"),
    ].filter(Boolean);
    for (const configPath of candidatePaths) {
        if (!fs.existsSync(configPath))
            continue;
        try {
            const raw = fs.readFileSync(configPath, "utf8");
            const parsed = JSON.parse(raw);
            if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
                throw new Error("configuration root must be a JSON object");
            }
            return parsed;
        }
        catch (error) {
            throw new GuardianConfigError(configPath, error);
        }
    }
    return DEFAULT_CONFIG;
}
function isSyntheticUserMessage(message) {
    return (message.info.role === "user" &&
        Boolean(message.parts?.some((part) => part.synthetic === true)));
}
function isGuardianRemediationMessage(message) {
    if (message.info.role !== "user")
        return false;
    return Boolean(message.parts?.some((part) => part.type === "text" &&
        typeof part.text === "string" &&
        part.text.trimStart().startsWith(REMEDIATION_MARKER)));
}
export function extractCurrentTurn(messages) {
    const lastUserMessage = messages.findLast((message) => message.info.role === "user" &&
        (!isSyntheticUserMessage(message) || isGuardianRemediationMessage(message)));
    const isRemediationResponse = Boolean(lastUserMessage && isGuardianRemediationMessage(lastUserMessage));
    const lastHumanUserIndex = messages.findLastIndex((m) => m.info.role === "user" &&
        !isGuardianRemediationMessage(m) &&
        !isSyntheticUserMessage(m));
    const lastHumanUser = lastHumanUserIndex >= 0 ? messages[lastHumanUserIndex] : undefined;
    const currentTurn = lastHumanUserIndex < 0 ? messages : messages.slice(lastHumanUserIndex);
    const activeAgent = currentTurn.findLast((m) => typeof m.info?.agent === "string" && m.info.agent.length > 0)?.info.agent ?? messages.findLast((m) => typeof m.info?.agent === "string" && m.info.agent.length > 0)?.info.agent;
    const isSubagent = Boolean(activeAgent && activeAgent !== "orchestrator");
    return {
        isSubagent,
        isRemediationResponse,
        currentTurn,
        turnKey: lastHumanUser?.info.id ?? "no-human-user",
    };
}
function normalizeSeverity(value) {
    return value === "error" || value === "warn" || value === "off"
        ? value
        : undefined;
}
function sanitizeRuleConfig(setting) {
    if (!setting || typeof setting !== "object" || Array.isArray(setting)) {
        return {};
    }
    const config = { ...setting };
    if (config.severity !== undefined &&
        !["error", "warn", "off"].includes(config.severity)) {
        delete config.severity;
    }
    if (config.customPhrases !== undefined) {
        config.customPhrases = Array.isArray(config.customPhrases)
            ? config.customPhrases.filter((value) => typeof value === "string" && value.trim().length > 0)
            : undefined;
    }
    if (config.exceptions !== undefined) {
        config.exceptions = Array.isArray(config.exceptions)
            ? config.exceptions.filter((value) => typeof value === "string" && value.trim().length > 0)
            : undefined;
    }
    return config;
}
export class GuardEngine {
    config;
    rules = new Map();
    inspectedMessages = new Map();
    sessionState = new SessionStateStore();
    constructor(config) {
        this.config = {
            ...DEFAULT_CONFIG,
            ...(config ?? {}),
            rules: {
                ...(DEFAULT_CONFIG.rules ?? {}),
                ...(config?.rules ?? {}),
            },
        };
        for (const rule of Object.values(BUILTIN_RULES)) {
            this.registerRule(rule);
        }
    }
    registerRule(rule) {
        this.rules.set(rule.id, rule);
    }
    forgetSession(sessionID) {
        this.inspectedMessages.delete(sessionID);
        this.sessionState.forget(sessionID);
    }
    rollbackInspection(sessionID) {
        this.inspectedMessages.delete(sessionID);
    }
    async inspect(sessionID, directory, messages) {
        if (this.config.enabled === false || messages.length === 0) {
            return { decision: "pass", results: [] };
        }
        const lastAssistant = messages.findLast((m) => m.info.role === "assistant");
        const messageID = lastAssistant?.info.id;
        if (!messageID || this.inspectedMessages.get(sessionID) === messageID) {
            return { decision: "pass", results: [] };
        }
        const { isSubagent, isRemediationResponse, currentTurn, turnKey, } = extractCurrentTurn(messages);
        const contract = extractTaskContract(currentTurn);
        // Ordinary remediation replies are not reinspected. Explicit iterative
        // tasks are the one exception: inspect only the completion gate, using an
        // independent bounded continuation budget, not the global repair budget.
        if (isRemediationResponse && !contract?.iterativeReview) {
            this.inspectedMessages.set(sessionID, messageID);
            return { decision: "pass", results: [] };
        }
        const evidence = collectTurnEvidence(currentTurn);
        const lastGuardianIndex = currentTurn.findLastIndex(isGuardianRemediationMessage);
        const freshTurn = isRemediationResponse && lastGuardianIndex >= 0
            ? [currentTurn[0], ...currentTurn.slice(lastGuardianIndex + 1)]
            : currentTurn;
        // Reinspect only new work for the other rules; the completion gate alone
        // needs the full human-turn history to evaluate progress across rounds.
        const freshEvidence = freshTurn === currentTurn
            ? evidence
            : collectTurnEvidence(freshTurn);
        const results = [];
        const blockingPrompts = [];
        const blockingResults = [];
        for (const [ruleId, rule] of this.rules.entries()) {
            const isCompletionGate = ruleId === "task/completion-gate";
            const ruleSetting = this.config.rules?.[ruleId];
            const ruleConfig = sanitizeRuleConfig(typeof ruleSetting === "object" ? ruleSetting : {});
            const defaultSetting = DEFAULT_CONFIG.rules?.[ruleId];
            const configuredSeverity = typeof ruleSetting === "string"
                ? normalizeSeverity(ruleSetting)
                : normalizeSeverity(ruleSetting &&
                    typeof ruleSetting === "object" &&
                    !Array.isArray(ruleSetting)
                    ? ruleSetting.severity
                    : undefined);
            const explicitlyInvalidSeverity = (typeof ruleSetting === "string" &&
                normalizeSeverity(ruleSetting) === undefined) ||
                (ruleSetting &&
                    typeof ruleSetting === "object" &&
                    !Array.isArray(ruleSetting) &&
                    "severity" in ruleSetting &&
                    ruleSetting.severity !== undefined &&
                    normalizeSeverity(ruleSetting.severity) ===
                        undefined);
            const defaultSeverity = normalizeSeverity(defaultSetting) ??
                normalizeSeverity(defaultSetting && typeof defaultSetting === "object"
                    ? defaultSetting.severity
                    : undefined) ??
                "error";
            // Invalid explicit severity is a config error. Fail open to warn instead
            // of unexpectedly turning a typo into a blocking rule.
            const severity = explicitlyInvalidSeverity
                ? "warn"
                : configuredSeverity ?? defaultSeverity;
            if (severity === "off")
                continue;
            const context = {
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
            if (severity !== "warn" &&
                res.decision === "block" &&
                res.remediationPrompt) {
                blockingPrompts.push(res.remediationPrompt);
                blockingResults.push(res);
            }
        }
        this.inspectedMessages.set(sessionID, messageID);
        if (blockingPrompts.length > 0) {
            const completion = blockingResults.find((result) => result.ruleId === "task/completion-gate");
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
                return {
                    decision: "block",
                    results,
                    combinedRemediationPrompt: `${REMEDIATION_MARKER}\n${blockingPrompts.join("\n\n---\n\n")}`,
                    rollback: () => {
                        this.inspectedMessages.delete(sessionID);
                        this.sessionState.rollbackContinuation(sessionID, turnKey, progressKey);
                    },
                };
            }
            const configuredBudget = typeof this.config.remediationBudget === "number" &&
                Number.isFinite(this.config.remediationBudget)
                ? Math.floor(this.config.remediationBudget)
                : 1;
            const budget = Math.max(0, Math.min(5, configuredBudget));
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
            if (!this.sessionState.canRemediate(sessionID, turnKey, fingerprint, budget)) {
                return { decision: "pass", results };
            }
            this.sessionState.recordRemediation(sessionID, turnKey, fingerprint);
            return {
                decision: "block",
                results,
                combinedRemediationPrompt: `${REMEDIATION_MARKER}\n${blockingPrompts.join("\n\n---\n\n")}`,
                rollback: () => {
                    this.inspectedMessages.delete(sessionID);
                    this.sessionState.rollbackRemediation(sessionID, turnKey, fingerprint);
                },
            };
        }
        return {
            decision: "pass",
            results,
        };
    }
}
