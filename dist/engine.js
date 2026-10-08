import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
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
import { collectTurnEvidence } from "./evidence.js";
import { SessionStateStore } from "./state.js";
import { taskCompletionRule } from "./rules/task-completion.js";
import { instructionFidelityRule } from "./rules/instruction-fidelity.js";
import { extractTaskContract, latestMutationSequence, } from "./task-contract.js";
import { createHandoffForBlockingResults, formatOpenCodeHandoff } from "./handoff.js";
import { isTrustedGuardianMetadata } from "./provenance.js";
export const REMEDIATION_MARKER = "[opencode-guardian remediation]";
function findingIdentity(ruleId, finding) {
    const semantic = finding.fingerprint
        ? ["explicit", finding.filePath ?? "", finding.fingerprint]
        : ["fallback", finding.filePath ?? "", finding.pattern ?? ""];
    const digest = createHash("sha256")
        .update(semantic.join("\u0000"))
        .digest("hex")
        .slice(0, 24);
    return `${ruleId}:${digest}`;
}
function composeCombinedRemediationPrompt(blockingPrompts, handoff) {
    if (!handoff) {
        return `${REMEDIATION_MARKER}\n${blockingPrompts.join("\n\n---\n\n")}`;
    }
    return `${REMEDIATION_MARKER}\n\n${formatOpenCodeHandoff(handoff)}\n\n${blockingPrompts.join("\n\n---\n\n")}`;
}
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
export const DEFAULT_CONFIG = {
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
    configPath;
    constructor(configPath, cause) {
        const configName = path.basename(configPath);
        const detail = cause instanceof Error
            ? cause.message
            : (cause ? String(cause) : "could not parse or validate configuration");
        super(`[opencode-guardian] Invalid configuration in ${configName}: ${detail}. Fix or remove the file to prevent unintended security fallbacks.`);
        this.name = "GuardianConfigError";
        this.configPath = configName;
    }
}
function validateConfig(value) {
    const fail = (name) => { throw new Error("invalid configuration field: " + name); };
    if (value.enabled !== undefined && typeof value.enabled !== "boolean")
        fail("enabled");
    for (const name of ["remediationBudget", "iterationBudget"]) {
        if (value[name] !== undefined &&
            (typeof value[name] !== "number" || !Number.isInteger(value[name]) ||
                value[name] < 0 || value[name] > 5))
            fail(name);
    }
    for (const name of ["preflight", "updateNotice", "notifications"]) {
        const item = value[name];
        if (item !== undefined && (!item || typeof item !== "object" ||
            Array.isArray(item) || (item.enabled !== undefined &&
            typeof item.enabled !== "boolean")))
            fail(name);
    }
    const shellTools = value.preflight?.shellTools;
    if (shellTools !== undefined &&
        (!Array.isArray(shellTools) ||
            !shellTools.every((tool) => typeof tool === "string" && tool.trim().length > 0))) {
        fail("preflight.shellTools");
    }
    if (value.secrets !== undefined) {
        if (!value.secrets || typeof value.secrets !== "object" || Array.isArray(value.secrets))
            fail("secrets");
        const sec = value.secrets;
        if (sec.enabled !== undefined && typeof sec.enabled !== "boolean")
            fail("secrets.enabled");
        if (sec.replacement !== undefined && typeof sec.replacement !== "string")
            fail("secrets.replacement");
        if (sec.includeRuntimeEnv !== undefined && typeof sec.includeRuntimeEnv !== "boolean")
            fail("secrets.includeRuntimeEnv");
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
        if (!value.rules || typeof value.rules !== "object" || Array.isArray(value.rules))
            fail("rules");
        for (const [name, setting] of Object.entries(value.rules)) {
            if (typeof setting === "string") {
                if (!["error", "warn", "off"].includes(setting))
                    fail("rules." + name);
            }
            else if (setting && typeof setting === "object" && !Array.isArray(setting)) {
                const rule = setting;
                if (rule.severity !== undefined && !["error", "warn", "off"].includes(rule.severity))
                    fail("rules." + name + ".severity");
                for (const field of ["customPhrases", "exceptions"]) {
                    if (rule[field] !== undefined && (!Array.isArray(rule[field]) ||
                        !rule[field].every(item => typeof item === "string")))
                        fail("rules." + name + "." + field);
                }
            }
            else
                fail("rules." + name);
        }
    }
    return value;
}
export function resolveEffectiveConfig(base, rawOptions) {
    const options = rawOptions && typeof rawOptions === "object" && !Array.isArray(rawOptions)
        ? { ...rawOptions }
        : {};
    const legacySecrets = {};
    if (typeof options.replacement === "string") {
        legacySecrets.replacement = options.replacement;
    }
    if (Array.isArray(options.customSensitiveKeys)) {
        legacySecrets.customSensitiveKeys = options.customSensitiveKeys;
    }
    if (Array.isArray(options.customSecretValues)) {
        legacySecrets.customSecretValues = options.customSecretValues;
    }
    const overlay = {};
    for (const key of [
        "enabled",
        "remediationBudget",
        "iterationBudget",
        "preflight",
        "updateNotice",
        "notifications",
        "secrets",
        "rules",
    ]) {
        if (options[key] !== undefined)
            overlay[key] = options[key];
    }
    if (Object.keys(legacySecrets).length > 0) {
        overlay.secrets = {
            ...(overlay.secrets && typeof overlay.secrets === "object" && !Array.isArray(overlay.secrets)
                ? overlay.secrets
                : {}),
            ...legacySecrets,
        };
    }
    const validated = validateConfig(overlay);
    const mergedRules = {
        ...base.rules,
    };
    for (const [ruleID, next] of Object.entries(validated.rules ?? {})) {
        const previous = mergedRules[ruleID];
        if (next && typeof next === "object" && !Array.isArray(next)) {
            const previousObject = typeof previous === "string"
                ? { severity: previous }
                : previous && typeof previous === "object" && !Array.isArray(previous)
                    ? previous
                    : {};
            mergedRules[ruleID] = {
                ...previousObject,
                ...next,
            };
        }
        else {
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
            return validateConfig(parsed);
        }
        catch (error) {
            throw new GuardianConfigError(configPath, error);
        }
    }
    return DEFAULT_CONFIG;
}
function isSyntheticUserMessage(message, sessionID) {
    return (message.info.role === "user" &&
        Boolean(message.parts?.some((part) => part.synthetic === true ||
            part.ignored === true ||
            (part.metadata &&
                typeof part.metadata === "object" &&
                (part.metadata["opencode-guardian-visible"] === true ||
                    part.metadata["opencode-guardian-kind"] === "visible")) ||
            isTrustedGuardianMetadata(sessionID, part.metadata, "visible"))));
}
function isGuardianRemediationMessage(message, sessionID) {
    if (message.info.role !== "user")
        return false;
    return Boolean(message.parts?.some((part) => {
        const marker = part.type === "text" &&
            typeof part.text === "string" &&
            part.text.trimStart().startsWith(REMEDIATION_MARKER);
        if (!marker)
            return false;
        return (part.synthetic === true ||
            Boolean(sessionID &&
                isTrustedGuardianMetadata(sessionID, part.metadata, "remediation")));
    }));
}
export const NATIVE_QUESTION_TOOLS = new Set([
    "ask_question",
    "question",
    "form",
    "form_create",
    "create_form",
    "session.form",
]);
function isNativeQuestionTool(toolRaw) {
    if (!toolRaw)
        return false;
    const name = toolRaw.toLowerCase().trim();
    const baseName = name.includes(".") ? (name.split(".").pop() ?? name) : name;
    return NATIVE_QUESTION_TOOLS.has(name) || NATIVE_QUESTION_TOOLS.has(baseName);
}
export function extractCurrentTurn(messages, sessionID) {
    const lastUserMessage = messages.findLast((message) => message.info.role === "user" &&
        (!isSyntheticUserMessage(message, sessionID) || isGuardianRemediationMessage(message, sessionID)));
    const isRemediationResponse = Boolean(lastUserMessage && isGuardianRemediationMessage(lastUserMessage, sessionID));
    const lastHumanUserIndex = messages.findLastIndex((m) => m.info.role === "user" &&
        !isGuardianRemediationMessage(m, sessionID) &&
        !isSyntheticUserMessage(m, sessionID));
    const lastHumanUser = lastHumanUserIndex >= 0 ? messages[lastHumanUserIndex] : undefined;
    const currentTurn = lastHumanUserIndex < 0 ? messages : messages.slice(lastHumanUserIndex);
    // Agent names are identity hints, not session topology. Runtime adapters
    // provide parent/child topology explicitly; direct engine callers default
    // to root semantics rather than guessing from arbitrary agent labels.
    const isSubagent = false;
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
        if (Array.isArray(config.customPhrases)) {
            config.customPhrases = config.customPhrases.filter((value) => typeof value === "string" && value.trim().length > 0);
        }
        else {
            delete config.customPhrases;
        }
    }
    if (config.exceptions !== undefined) {
        if (Array.isArray(config.exceptions)) {
            config.exceptions = config.exceptions.filter((value) => typeof value === "string" && value.trim().length > 0);
        }
        else {
            delete config.exceptions;
        }
    }
    return config;
}
export class GuardEngine {
    config;
    rules = new Map();
    inspectedMessages = new Map();
    sessionState = new SessionStateStore();
    constructor(config) {
        const secrets = config?.secrets !== undefined ? {
            ...DEFAULT_CONFIG.secrets,
            ...config.secrets,
        } : DEFAULT_CONFIG.secrets;
        this.config = {
            ...DEFAULT_CONFIG,
            ...config,
            ...(secrets ? { secrets } : {}),
            rules: {
                ...DEFAULT_CONFIG.rules,
                ...config?.rules,
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
    async inspect(sessionID, directory, messages, snapshots, options) {
        if (this.config.enabled === false || messages.length === 0) {
            return { decision: "pass", results: [] };
        }
        const lastAssistant = messages.findLast((m) => m.info.role === "assistant");
        const messageID = lastAssistant?.info.id;
        if (!messageID || this.inspectedMessages.get(sessionID) === messageID) {
            return { decision: "pass", results: [] };
        }
        const { isSubagent: inferredSubagent, isRemediationResponse, currentTurn, turnKey, } = extractCurrentTurn(messages, sessionID);
        const isSubagent = options?.isSubagent ?? inferredSubagent;
        const firstCurrentMessage = currentTurn[0];
        if (!firstCurrentMessage) {
            return { decision: "pass", results: [] };
        }
        const activeHandoff = !isSubagent ? this.sessionState.getActiveHandoff(sessionID) : undefined;
        if (activeHandoff?.status === "question_presented") {
            const hasUserReply = currentTurn.some((msg) => msg.info.role === "user" && !isGuardianRemediationMessage(msg, sessionID));
            if (hasUserReply) {
                this.sessionState.clearActiveHandoff(sessionID);
            }
        }
        else if (activeHandoff?.status === "handed_off") {
            const askedQuestion = currentTurn.some((msg) => msg.info.role === "assistant" &&
                msg.parts?.some((part) => {
                    const toolRaw = typeof part.tool === "string"
                        ? part.tool
                        : typeof part.name === "string"
                            ? part.name
                            : "";
                    return isNativeQuestionTool(toolRaw);
                }));
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
        const lastGuardianIndex = currentTurn.findLastIndex((m) => isGuardianRemediationMessage(m, sessionID));
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
        const pendingFindingKeys = isRemediationResponse
            ? this.sessionState.getPendingRemediationFindings(sessionID, turnKey)
            : [];
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
                agentCapability: options?.agentCapability,
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
        const canSelfRemediate = !isSubagent || options?.agentCapability === "write-allowed";
        if (blockingPrompts.length > 0) {
            if (!canSelfRemediate) {
                return {
                    decision: "block",
                    results,
                };
            }
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
                        this.sessionState.rollbackContinuation(sessionID, turnKey, progressKey);
                        if (handoff)
                            this.sessionState.clearActiveHandoff(sessionID);
                    },
                };
            }
            const configuredBudget = typeof this.config.remediationBudget === "number" &&
                Number.isFinite(this.config.remediationBudget)
                ? Math.floor(this.config.remediationBudget)
                : 1;
            const budget = Math.max(0, Math.min(5, configuredBudget));
            if (budget === 0) {
                return {
                    decision: "pass",
                    results,
                };
            }
            const findingFingerprints = Array.from(new Set(blockingResults.flatMap((result) => {
                const keys = result.findings.map((finding) => findingIdentity(result.ruleId, finding));
                return keys.length > 0 ? keys : [`${result.ruleId}:block`];
            }))).sort();
            const blockingRuleIds = blockingResults.map((r) => r.ruleId);
            const maxTurnRemediations = contract?.iterativeReview
                ? Math.max(5, this.config.iterationBudget ?? 3)
                : Math.max(8, Math.min(32, this.rules.size * Math.max(1, budget)));
            if (!this.sessionState.canRemediate(sessionID, turnKey, findingFingerprints, blockingRuleIds, budget, maxTurnRemediations)) {
                this.sessionState.clearPendingRemediation(sessionID);
                return {
                    decision: "pass",
                    results,
                    ...(isRemediationResponse
                        ? { remediationStatus: pendingRules.length ? "failed" : "unverified",
                            pendingRemediationRules: pendingRules }
                        : {}),
                };
            }
            this.sessionState.recordRemediation(sessionID, turnKey, findingFingerprints, blockingRuleIds);
            const blockingFiles = Array.from(new Set(blockingResults.flatMap((result) => result.findings.flatMap((finding) => finding.filePath ? [finding.filePath] : []))));
            const blockingFindingKeys = Array.from(new Set(blockingResults.flatMap((result) => result.findings.map((finding) => findingIdentity(result.ruleId, finding)))));
            this.sessionState.setPendingRemediation(sessionID, turnKey, blockingRuleIds, blockingFiles, blockingFindingKeys);
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
                    this.sessionState.rollbackRemediation(sessionID, turnKey, findingFingerprints, blockingRuleIds);
                    this.sessionState.clearPendingRemediation(sessionID);
                    if (handoff)
                        this.sessionState.clearActiveHandoff(sessionID);
                },
            };
        }
        if (isRemediationResponse) {
            // Absence of new findings is not proof of correction. A synthetic reply
            // without any successful follow-up work must never close an obligation.
            const successfulFresh = freshEvidence.records.filter((record) => record.status === "success");
            const fixedPaths = new Set(successfulFresh.filter((record) => record.kind === "file-mutation")
                .map((record) => record.filePath).filter((file) => !!file));
            const hasProgress = successfulFresh.some((record) => ["file-mutation", "test", "build", "typecheck", "lint", "audit"].includes(record.kind));
            const pendingFindingSet = new Set(pendingFindingKeys);
            const originalFindingsRemain = results.some((result) => pendingRules.includes(result.ruleId) &&
                result.findings.some((finding) => pendingFindingSet.has(findingIdentity(result.ruleId, finding))));
            let verified = pendingRules.length > 0 && hasProgress && !originalFindingsRemain;
            if (verified && pendingRules.includes("security/no-secrets")) {
                // Check actual files, not only the proposed tool input. No file on
                // disk, an out-of-scope path or an unreadable file means unverified.
                verified = pendingFiles.length > 0 && pendingFiles.every((rel) => {
                    if (!fixedPaths.has(rel))
                        return false;
                    const full = path.resolve(directory, rel);
                    const relative = path.relative(path.resolve(directory), full);
                    if (relative === ".." || relative.startsWith(".." + path.sep) ||
                        path.isAbsolute(relative))
                        return false;
                    try {
                        const realRoot = fs.realpathSync(path.resolve(directory));
                        const realFile = fs.realpathSync(full);
                        const realRelative = path.relative(realRoot, realFile);
                        if (realRelative === ".." || realRelative.startsWith(".." + path.sep) ||
                            path.isAbsolute(realRelative))
                            return false;
                        const info = fs.lstatSync(full);
                        return info.isFile() && info.size <= 2 * 1024 * 1024 &&
                            findAllSecretsInCode(fs.readFileSync(full, "utf8"), rel).length === 0;
                    }
                    catch {
                        return false;
                    }
                });
            }
            // Recheck actual files: a clean new turn may leave the original TODO,
            // test bypass or incomplete stub unchanged on disk.
            const sourceRules = pendingRules.filter((rule) => ["quality/no-shortcuts", "integrity/no-stubs", "testing/no-cheat"].includes(rule));
            if (verified && sourceRules.length) {
                verified = pendingFiles.length > 0;
                for (const rel of pendingFiles) {
                    if (!verified || !fixedPaths.has(rel)) {
                        verified = false;
                        break;
                    }
                    const root = path.resolve(directory);
                    const full = path.resolve(root, rel);
                    const scoped = path.relative(root, full);
                    if (scoped === ".." || scoped.startsWith(".." + path.sep) || path.isAbsolute(scoped)) {
                        verified = false;
                        break;
                    }
                    let content;
                    try {
                        const actual = path.relative(fs.realpathSync(root), fs.realpathSync(full));
                        if (actual === ".." || actual.startsWith(".." + path.sep) || path.isAbsolute(actual)) {
                            verified = false;
                            break;
                        }
                        const info = fs.lstatSync(full);
                        if (!info.isFile() || info.size > 2 * 1024 * 1024) {
                            verified = false;
                            break;
                        }
                        content = fs.readFileSync(full, "utf8");
                    }
                    catch {
                        verified = false;
                        break;
                    }
                    for (const ruleID of sourceRules) {
                        const rule = this.rules.get(ruleID);
                        if (!rule) {
                            verified = false;
                            break;
                        }
                        const configuredRule = this.config.rules?.[ruleID];
                        const recheckRuleConfig = sanitizeRuleConfig(configuredRule && typeof configuredRule === "object" && !Array.isArray(configuredRule)
                            ? configuredRule
                            : {});
                        const checked = await rule.inspect({
                            sessionID, directory, messages,
                            currentTurn: [firstCurrentMessage, {
                                    info: { id: "guardian-current-file", role: "assistant" },
                                    parts: [{ type: "tool", tool: "write_to_file",
                                            state: { status: "completed", input: { path: rel, content } } }],
                                }],
                            isSubagent, ruleConfig: recheckRuleConfig, evidence: freshEvidence,
                        });
                        const originalSourceFindingRemains = checked.findings.some((finding) => pendingFindingSet.has(findingIdentity(ruleID, finding)));
                        if (originalSourceFindingRemains) {
                            verified = false;
                            break;
                        }
                    }
                }
            }
            if (verified && pendingRules.some((rule) => ["integrity/no-unverified-claims", "integrity/no-silent-failure"].includes(rule)) &&
                !successfulFresh.some((record) => ["test", "build", "typecheck", "lint", "audit"].includes(record.kind))) {
                verified = false;
            }
            if (verified && pendingRules.some((rule) => !["security/no-secrets", "quality/no-shortcuts", "integrity/no-stubs",
                "testing/no-cheat", "integrity/no-unverified-claims",
                "integrity/no-silent-failure", "task/completion-gate"].includes(rule))) {
                verified = false;
            }
            const remediationStatus = originalFindingsRemain
                ? "failed"
                : verified ? "verified" : "unverified";
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
