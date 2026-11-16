import { GuardEngine, loadConfig, resolveEffectiveConfig } from "./engine.js";
import { extractTaskContract, taskGuidance } from "./task-contract.js";
import { evaluatePreflight, GuardianPreflightError, isShellExecutionTool, isFileMutationTool, isProcessStartTool } from "./preflight.js";
import { configureGuardianTelemetry, recordGuardianEvent, sessionFingerprint } from "./telemetry.js";
import { auditReasons } from "./audit.js";
import { VerificationSnapshotStore } from "./evidence.js";
import { createIdleQueue } from "./idle-queue.js";
import { registerGuardianCapability } from "./handoff.js";
import { resolveV2AgentCapability, getCachedAgentCapability, cacheAgentCapability, cacheV2SessionPermissions, clearAgentCapability, clearAllAgentCapabilities, extractAgentNameFromMessages, } from "./agent-capability.js";
import { resolveSanitizerOptions, sanitizeMessages, sanitizeObject, sanitizeString, sanitizeToolResult, } from "./secrets/index.js";
import { createGuardianToastNotifier, dispatchGuardianToastClear, formatGuardianToast, } from "./toast.js";
import { createGuardianMessageMetadata, forgetGuardianProvenance, isTrustedGuardianMetadata, } from "./provenance.js";
import { GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD, GUARDIAN_INTERVENTION_RPC_DEFINITION, GUARDIAN_INTERVENTION_RPC_METHOD, activeGuardianIntervention, inactiveGuardianIntervention, readGuardianInterventionSessionID, } from "./intervention-rpc.js";
import { StreamLoopWatcher } from "./stream-loop.js";
export * from "./types.js";
export * from "./engine.js";
export * from "./degeneration.js";
export * from "./rules/no-evasion.js";
export * from "./rules/no-shortcuts.js";
export * from "./rules/no-stubs.js";
export * from "./rules/no-truncation.js";
export * from "./rules/no-cheat.js";
export * from "./rules/no-secrets.js";
export * from "./rules/no-ghost-deps.js";
export * from "./rules/circuit-breaker.js";
export * from "./rules/no-apology.js";
export * from "./rules/no-unverified-claims.js";
export * from "./rules/no-silent-failure.js";
export * from "./rules/destructive-operations.js";
export * from "./evidence.js";
export * from "./verification-report.js";
export * from "./edit-integrity.js";
export * from "./state.js";
export * from "./task-contract.js";
export * from "./locale-intents.js";
export * from "./task-policy.js";
export * from "./rules/task-completion.js";
export * from "./rules/instruction-fidelity.js";
export * from "./prose.js";
export * from "./preflight.js";
export * from "./telemetry.js";
export * from "./audit.js";
export * from "./version-notice.js";
export * from "./handoff.js";
export * from "./agent-capability.js";
export * from "./secrets/index.js";
export * from "./toast.js";
export * from "./intervention.js";
export * from "./intervention-rpc.js";
export * from "./provenance.js";
function sanitizeV2ToolError(error, options) {
    const fallback = () => {
        const safe = new Error("[OUTPUT REDACTED: sanitization failure]");
        if (error && typeof error === "object") {
            try {
                Object.setPrototypeOf(safe, Object.getPrototypeOf(error));
            }
            catch { }
        }
        return safe;
    };
    try {
        if (!error || typeof error !== "object") {
            return sanitizeToolResult(error, options);
        }
        const source = error;
        const snapshot = { ...source };
        if (typeof source.message === "string")
            snapshot.message = source.message;
        if (typeof source.stack === "string")
            snapshot.stack = source.stack;
        if (typeof source.name === "string")
            snapshot.name = source.name;
        const sanitized = sanitizeObject(snapshot, options).sanitized;
        if (!sanitized || typeof sanitized !== "object" || Array.isArray(sanitized)) {
            return fallback();
        }
        return Object.assign(Object.create(Object.getPrototypeOf(error)), sanitized);
    }
    catch {
        return fallback();
    }
}
function stringifyV2ToolContent(content) {
    if (!Array.isArray(content))
        return "";
    return content
        .map((item) => {
        if (item &&
            typeof item === "object" &&
            "type" in item &&
            item.type === "text" &&
            "text" in item &&
            typeof item.text === "string") {
            return item.text;
        }
        try {
            return JSON.stringify(item);
        }
        catch {
            return String(item);
        }
    })
        .filter(Boolean)
        .join("\n");
}
function normalizeV2AssistantPart(part) {
    if (!part || typeof part !== "object")
        return null;
    const value = part;
    if ((value.type === "text" || value.type === "reasoning") && typeof value.text === "string") {
        return { type: value.type, text: value.text };
    }
    if (value.type !== "tool" || !value.state || typeof value.state !== "object") {
        return null;
    }
    const state = value.state;
    const normalizedState = {};
    if (typeof state.status === "string")
        normalizedState.status = state.status;
    if (state.input && typeof state.input === "object") {
        normalizedState.input = state.input;
    }
    if (state.error !== undefined)
        normalizedState.error = state.error;
    if (state.metadata && typeof state.metadata === "object") {
        normalizedState.metadata = state.metadata;
    }
    if (state.exitCode !== undefined)
        normalizedState.exitCode = state.exitCode;
    if (state.raw !== undefined)
        normalizedState.raw = state.raw;
    const output = typeof state.output === "string"
        ? state.output
        : stringifyV2ToolContent(state.content);
    if (output)
        normalizedState.output = output;
    return {
        type: "tool",
        tool: typeof value.name === "string" ? value.name : undefined,
        name: typeof value.name === "string" ? value.name : undefined,
        callID: typeof value.id === "string" ? value.id :
            typeof value.callID === "string" ? value.callID : undefined,
        state: normalizedState,
    };
}
/**
 * Converts OpenCode v2 session.context() records into the stable internal
 * message shape consumed by the rules and engine.
 */
export function normalizeV2Messages(messages, sessionID) {
    const normalized = [];
    for (const raw of messages) {
        if (!raw || typeof raw !== "object")
            continue;
        const msg = raw;
        const id = typeof msg.id === "string" ? msg.id : undefined;
        const type = typeof msg.type === "string" ? msg.type : undefined;
        if (!id || !type)
            continue;
        if (isTrustedGuardianMetadata(sessionID, msg.metadata, "visible"))
            continue;
        if (type === "user" && typeof msg.text === "string") {
            normalized.push({
                info: { id, role: "user" },
                parts: [{
                        type: "text",
                        text: msg.text,
                        ...(msg.metadata && typeof msg.metadata === "object"
                            ? { metadata: msg.metadata }
                            : {}),
                    }],
            });
            continue;
        }
        if (type === "synthetic" && typeof msg.text === "string") {
            normalized.push({
                info: { id, role: "user" },
                parts: [{
                        type: "text",
                        text: msg.text,
                        synthetic: true,
                        ...(msg.metadata && typeof msg.metadata === "object"
                            ? { metadata: msg.metadata }
                            : {}),
                    }],
            });
            continue;
        }
        if (type === "system" && typeof msg.text === "string") {
            normalized.push({
                info: { id, role: "system" },
                parts: [{ type: "text", text: msg.text }],
            });
            continue;
        }
        if (type === "assistant" && Array.isArray(msg.content)) {
            const parts = msg.content
                .map(normalizeV2AssistantPart)
                .filter((part) => part !== null);
            normalized.push({
                info: {
                    id,
                    role: "assistant",
                    ...(typeof msg.agent === "string" ? { agent: msg.agent } : {}),
                },
                parts,
            });
            continue;
        }
        if (type === "shell" && typeof msg.command === "string") {
            const shellOutput = msg.output && typeof msg.output === "object"
                ? msg.output.output
                : undefined;
            const exitedOk = msg.status === "exited" && (msg.exit === 0 || msg.exit === undefined);
            normalized.push({
                info: { id, role: "assistant" },
                parts: [{
                        type: "tool",
                        tool: "shell",
                        name: "shell",
                        callID: id,
                        state: {
                            status: exitedOk ? "completed" : "error",
                            input: { command: msg.command },
                            ...(typeof shellOutput === "string" ? { output: shellOutput } : {}),
                            ...(msg.exit !== undefined ? { exitCode: msg.exit } : {}),
                        },
                    }],
            });
            continue;
        }
        if (type === "agent-switched" && typeof msg.agent === "string") {
            normalized.push({
                info: { id, role: "assistant", agent: msg.agent },
                parts: [],
            });
        }
    }
    return normalized;
}
const MAX_SUBAGENT_HANDOFF_ROUNDS = 6;
function markForegroundHandoff(handoffs, sessionID, callID) {
    const active = handoffs.get(sessionID) ?? new Set();
    active.add(callID);
    handoffs.set(sessionID, active);
}
function clearForegroundHandoff(handoffs, sessionID, callID) {
    const active = handoffs.get(sessionID);
    if (!active)
        return;
    active.delete(callID);
    if (active.size === 0)
        handoffs.delete(sessionID);
}
function hasForegroundHandoff(handoffs, sessionID) {
    return Boolean(sessionID && handoffs.get(sessionID)?.size);
}
function latestAssistantText(messages) {
    const assistant = messages.findLast((message) => message.info.role === "assistant");
    if (!assistant)
        return undefined;
    const text = (assistant.parts ?? [])
        .filter((part) => part.type === "text" && typeof part.text === "string")
        .map((part) => part.text ?? "")
        .join("\n")
        .trim();
    return text || undefined;
}
const INTERVENTION_TRACKER = Symbol("opencode-guardian.intervention-tracker");
function createTrackedToastNotifier(base) {
    const remainingCleanTurns = new Map();
    const tracker = {
        noteHumanPrompt(sessionID) {
            const remaining = remainingCleanTurns.get(sessionID);
            if (remaining !== undefined && remaining > 1) {
                remainingCleanTurns.set(sessionID, 1);
            }
        },
        recordOutcome(sessionID, result, findingsCount, toastNotifier) {
            if (result.remediationStatus === "verified") {
                remainingCleanTurns.delete(sessionID);
                return;
            }
            if (findingsCount > 0 ||
                result.decision === "block" ||
                result.remediationStatus === "failed" ||
                result.remediationStatus === "unverified") {
                if (remainingCleanTurns.has(sessionID) && (remainingCleanTurns.get(sessionID) ?? 0) < 1) {
                    remainingCleanTurns.set(sessionID, 1);
                }
                return;
            }
            if (result.results.length === 0)
                return;
            const remaining = remainingCleanTurns.get(sessionID);
            if (remaining === undefined)
                return;
            if (remaining <= 1) {
                remainingCleanTurns.delete(sessionID);
                toastNotifier?.clear?.(sessionID);
            }
            else {
                remainingCleanTurns.set(sessionID, remaining - 1);
            }
        },
        forget(sessionID) {
            remainingCleanTurns.delete(sessionID);
        },
    };
    return {
        notify(input) {
            if (typeof input.sessionID === "string" && input.sessionID.length > 0) {
                const requiredCleanTurns = input.kind === "stream-interrupt-requested" || input.kind === "preflight-blocked"
                    ? 2
                    : 1;
                remainingCleanTurns.delete(input.sessionID);
                remainingCleanTurns.set(input.sessionID, requiredCleanTurns);
                while (remainingCleanTurns.size > 512) {
                    const oldest = remainingCleanTurns.keys().next().value;
                    if (oldest === undefined)
                        break;
                    remainingCleanTurns.delete(oldest);
                }
            }
            base.notify(input);
        },
        clear(sessionID) {
            remainingCleanTurns.delete(sessionID);
            base.clear?.(sessionID);
        },
        [INTERVENTION_TRACKER]: tracker,
    };
}
function recordInspectionOutcome(result, sessionID, directory, toastNotifier) {
    const findings = result.results.filter((item) => item.findings.length > 0);
    // Only completed, non-duplicate rule evaluations count toward Inspected.
    if (result.results.length > 0) {
        recordGuardianEvent({
            kind: "post-inspected",
            session: sessionFingerprint(sessionID),
        }, directory);
    }
    if (result.remediationStatus === "verified") {
        toastNotifier?.clear?.(sessionID);
        const verifiedRules = result.pendingRemediationRules?.length
            ? result.pendingRemediationRules
            : ["remediation-verified"];
        recordGuardianEvent({
            kind: "remediation-verified",
            session: sessionFingerprint(sessionID),
            rules: verifiedRules,
            reasons: verifiedRules.map((rule) => ({ rule, code: "remediation-verified" })),
        }, directory);
    }
    else if (result.remediationStatus === "unverified") {
        recordGuardianEvent({
            kind: "remediation-unverified",
            session: sessionFingerprint(sessionID),
            rules: result.pendingRemediationRules ?? [],
        }, directory);
    }
    else if (result.remediationStatus === "failed") {
        const failedRules = result.pendingRemediationRules?.length
            ? result.pendingRemediationRules
            : ["remediation-failed"];
        recordGuardianEvent({
            kind: "remediation-failed",
            session: sessionFingerprint(sessionID),
            rules: failedRules,
            reasons: failedRules.map((rule) => ({ rule, code: "remediation-failed" })),
        }, directory);
    }
    if (findings.length && !(result.decision === "block" && result.combinedRemediationPrompt)) {
        recordGuardianEvent({
            kind: "post-warning",
            session: sessionFingerprint(sessionID),
            rules: findings.map((item) => item.ruleId),
            reasons: auditReasons(findings),
        }, directory);
        toastNotifier?.notify({
            kind: "warning",
            ruleIds: findings.map((item) => item.ruleId),
            sessionID,
        });
    }
    toastNotifier?.[INTERVENTION_TRACKER]?.recordOutcome(sessionID, result, findings.length, toastNotifier);
    return findings;
}
async function finalizeSubagentHandoff(input) {
    let remediated = false;
    let resolvedCapability;
    if (input.resolveCapability) {
        try {
            resolvedCapability = await input.resolveCapability();
        }
        catch {
            resolvedCapability = {
                capability: "unknown",
                evidence: { agentName: input.agentName, reasons: ["capability resolution failed"] },
            };
        }
    }
    const agentCapability = resolvedCapability?.capability ?? "unknown";
    for (let round = 0; round < MAX_SUBAGENT_HANDOFF_ROUNDS; round++) {
        if (input.signal?.aborted) {
            throw new Error("[opencode-guardian handoff] plugin teardown interrupted subagent finalization.");
        }
        let messages;
        try {
            messages = await input.fetchMessages();
        }
        catch {
            recordGuardianEvent({
                kind: "inspection-error",
                session: sessionFingerprint(input.sessionID),
                rules: ["message-fetch-failed"],
                reasons: [{ rule: "message-fetch-failed", code: "message-fetch-failed" }],
            }, input.directory);
            throw new Error("[opencode-guardian handoff] could not read the subagent result.");
        }
        let result;
        try {
            result = await input.engine.inspect(input.sessionID, input.directory, messages, input.snapshots?.(), { isSubagent: true, agentCapability });
        }
        catch {
            recordGuardianEvent({
                kind: "inspection-error",
                session: sessionFingerprint(input.sessionID),
                rules: ["engine-inspection-failed"],
                reasons: [{ rule: "engine-inspection-failed", code: "engine-inspection-failed" }],
            }, input.directory);
            throw new Error("[opencode-guardian handoff] subagent inspection failed.");
        }
        const findings = recordInspectionOutcome(result, input.sessionID, input.directory, input.toastNotifier);
        if (result.decision === "block" && result.combinedRemediationPrompt) {
            if (agentCapability !== "write-allowed") {
                return latestAssistantText(messages);
            }
            if (round === MAX_SUBAGENT_HANDOFF_ROUNDS - 1) {
                result.rollback?.();
                throw new Error("[opencode-guardian handoff] remediation did not converge before the safety limit.");
            }
            try {
                await input.sendAndWait(result.combinedRemediationPrompt);
                remediated = true;
                recordGuardianEvent({
                    kind: "post-remediation",
                    session: sessionFingerprint(input.sessionID),
                    rules: findings.map((item) => item.ruleId),
                    reasons: auditReasons(findings),
                }, input.directory);
                input.toastNotifier?.notify({
                    kind: "remediation",
                    ruleIds: findings.map((item) => item.ruleId),
                    sessionID: input.sessionID,
                });
            }
            catch {
                result.rollback?.();
                recordGuardianEvent({
                    kind: "inspection-error",
                    session: sessionFingerprint(input.sessionID),
                    rules: ["prompt-delivery-failed"],
                    reasons: [{ rule: "prompt-delivery-failed", code: "prompt-delivery-failed" }],
                }, input.directory);
                throw new Error("[opencode-guardian handoff] could not complete subagent remediation.");
            }
            continue;
        }
        if (result.remediationStatus === "failed") {
            throw new Error("[opencode-guardian handoff] unresolved Guardian findings; subagent result withheld.");
        }
        const latest = latestAssistantText(messages);
        if (remediated && !latest) {
            throw new Error("[opencode-guardian handoff] remediated subagent produced no final text result.");
        }
        return latest;
    }
    throw new Error("[opencode-guardian handoff] subagent finalization exceeded its bounded loop.");
}
/**
 * Common handler to process session.idle events in OpenCode V2.
 */
async function handleSessionIdle(sessionID, directory, fetchMessages, sendPrompt, engine, snapshots, signal, isSubagent, resolveCapability, toastNotifier) {
    let stage = "message-fetch";
    try {
        if (signal?.aborted)
            return;
        const messages = await fetchMessages();
        if (signal?.aborted)
            return;
        stage = "engine-inspect";
        // Unknown topology is not permission to treat a session as root. Fail safe
        // as a non-self-remediating child until the host proves parent/root state.
        const effectiveIsSubagent = isSubagent ?? true;
        let resolvedCapability;
        if (effectiveIsSubagent && resolveCapability) {
            try {
                resolvedCapability = await resolveCapability();
            }
            catch {
                resolvedCapability = {
                    capability: "unknown",
                    evidence: { reasons: ["capability resolution failed"] },
                };
            }
        }
        if (signal?.aborted)
            return;
        const agentCapability = resolvedCapability?.capability ?? (effectiveIsSubagent ? "unknown" : undefined);
        const result = await engine.inspect(sessionID, directory, messages, snapshots, { isSubagent: effectiveIsSubagent, ...(agentCapability ? { agentCapability } : {}) });
        if (signal?.aborted) {
            result.rollback?.();
            return;
        }
        const findings = recordInspectionOutcome(result, sessionID, directory, toastNotifier);
        if (result.decision === "block" && result.combinedRemediationPrompt) {
            if (effectiveIsSubagent && agentCapability !== "write-allowed") {
                return;
            }
            stage = "prompt-send";
            try {
                if (signal?.aborted) {
                    result.rollback?.();
                    return;
                }
                await sendPrompt(result.combinedRemediationPrompt);
                if (signal?.aborted)
                    return;
                recordGuardianEvent({ kind: "post-remediation", session: sessionFingerprint(sessionID), rules: findings.map((item) => item.ruleId), reasons: auditReasons(findings) }, directory);
                toastNotifier?.notify({
                    kind: "remediation",
                    ruleIds: findings.map((item) => item.ruleId),
                    sessionID,
                });
            }
            catch (promptError) {
                result.rollback?.();
                throw promptError;
            }
        }
    }
    catch {
        if (signal?.aborted)
            return;
        const errorCode = stage === "message-fetch"
            ? "message-fetch-failed"
            : stage === "prompt-send"
                ? "prompt-delivery-failed"
                : "engine-inspection-failed";
        recordGuardianEvent({
            kind: "inspection-error",
            session: sessionFingerprint(sessionID),
            rules: [errorCode],
            reasons: [{ rule: errorCode, code: errorCode }],
        }, directory);
        // Error objects may contain private paths and disrupt the interactive TUI.
        // The redacted inspection-error event above is the only diagnostic.
    }
}
/** Records only recognized shell/file calls and a rule code, never raw commands. */
function inspectPreflight(tool, args, sessionID, directory, additionalTools = [], toastNotifier) {
    if (!isShellExecutionTool(tool, additionalTools) && !isFileMutationTool(tool) && !isProcessStartTool(tool))
        return;
    const finding = evaluatePreflight(tool, args, additionalTools);
    const session = sessionFingerprint(sessionID);
    const safeTool = tool.toLowerCase().replace(/^mcp__[a-z0-9_]+__/, "").split(/[.:/]/).at(-1);
    recordGuardianEvent({
        kind: finding ? "preflight-blocked" : "preflight-allowed",
        ...(session ? { session } : {}),
        ...(safeTool ? { tool: safeTool } : {}),
        ...(finding ? { rules: [finding] } : {}),
    }, directory);
    if (finding) {
        toastNotifier?.notify({
            kind: "preflight-blocked",
            ruleId: finding,
            ...(safeTool ? { tool: safeTool } : {}),
            ...(sessionID ? { sessionID } : {}),
        });
        throw new GuardianPreflightError(finding);
    }
}
const setup = async (context) => {
    // Transition builds may call setup() with a partial v2 context.
    // Resolve the explicit security setting first: strict preflight must never
    // silently disappear merely because another v2 capability is unavailable.
    const directory = context?.location?.directory ?? process.cwd();
    const mergedConfig = resolveEffectiveConfig(loadConfig(directory), context.options);
    configureGuardianTelemetry(directory, mergedConfig.telemetry);
    if (mergedConfig.enabled === false) {
        recordGuardianEvent({ kind: "runtime-started", runtime: "v2", preflight: "disabled" }, directory);
        return;
    }
    const sanitizerOpts = resolveSanitizerOptions(mergedConfig);
    const strictPreflight = mergedConfig.preflight?.enabled === true;
    if (!context ||
        typeof context !== "object" ||
        typeof context.event?.subscribe !== "function" ||
        typeof context.session?.context !== "function" ||
        typeof context.session?.synthetic !== "function") {
        configureGuardianTelemetry(directory, undefined);
        if (strictPreflight) {
            throw new Error("[opencode-guardian preflight] V2 host context is unavailable; strict preflight cannot be enabled.");
        }
        if (sanitizerOpts) {
            throw new Error("[opencode-guardian secrets] V2 host context is unavailable; secret protection cannot be enabled safely.");
        }
        return;
    }
    const runtimeByDirectory = new Map();
    const controller = new AbortController();
    controller.signal.addEventListener("abort", () => {
        configureGuardianTelemetry(directory, undefined);
        for (const key of runtimeByDirectory.keys()) {
            configureGuardianTelemetry(key, undefined);
        }
    });
    const provenanceSessions = new Set();
    const v2GuardianMetadata = (sessionID, kind, base = {}) => {
        provenanceSessions.delete(sessionID);
        provenanceSessions.add(sessionID);
        while (provenanceSessions.size > 512) {
            const oldest = provenanceSessions.values().next().value;
            if (oldest === undefined)
                break;
            provenanceSessions.delete(oldest);
        }
        return createGuardianMessageMetadata(sessionID, kind, base);
    };
    let events;
    try {
        const candidate = context.event.subscribe({
            signal: controller.signal,
        });
        if (!candidate ||
            typeof candidate[Symbol.asyncIterator] !==
                "function") {
            throw new Error("V2 event subscriber did not return an async iterable");
        }
        events = candidate;
    }
    catch (error) {
        controller.abort();
        if (strictPreflight) {
            throw new Error("[opencode-guardian preflight] V2 event subscription failed; strict preflight cannot be enabled.", { cause: error });
        }
        if (sanitizerOpts) {
            throw new Error("[opencode-guardian secrets] V2 event subscription failed; secret protection cannot be enabled safely.", { cause: error });
        }
        return;
    }
    let toolOutputProtectionReady = false;
    let modelRequestProtectionReady = false;
    const runtimeForDirectory = (runtimeDirectory) => {
        const key = runtimeDirectory || directory;
        const cached = runtimeByDirectory.get(key);
        const config = cached?.config ?? resolveEffectiveConfig(loadConfig(key), context.options);
        configureGuardianTelemetry(key, config.telemetry);
        const runtime = cached ?? {
            config,
            sanitizer: resolveSanitizerOptions(config),
            engine: new GuardEngine(config),
        };
        if (config.enabled !== false && runtime.sanitizer &&
            (!toolOutputProtectionReady || !modelRequestProtectionReady)) {
            throw new Error("[opencode-guardian secrets] Required V2 security hooks are unavailable for this project; secret protection cannot be enabled safely.");
        }
        runtimeByDirectory.set(key, runtime);
        return runtime;
    };
    runtimeByDirectory.set(directory, {
        config: mergedConfig,
        sanitizer: sanitizerOpts,
        engine: new GuardEngine(mergedConfig),
    });
    const sessionDirectories = new Map();
    const rememberSessionDirectory = (sessionID, value) => {
        const resolved = typeof value === "string" && value.trim().length > 0
            ? value
            : sessionDirectories.get(sessionID) ?? directory;
        sessionDirectories.delete(sessionID);
        sessionDirectories.set(sessionID, resolved);
        while (sessionDirectories.size > 512) {
            const oldest = sessionDirectories.keys().next().value;
            if (oldest === undefined)
                break;
            sessionDirectories.delete(oldest);
        }
        return resolved;
    };
    const resolveSessionDirectory = async (sessionID) => {
        const cached = sessionDirectories.get(sessionID);
        if (cached)
            return cached;
        try {
            if (typeof context.session.get === "function") {
                const session = await context.session.get({ sessionID });
                const sessionDirectory = session.location?.directory;
                if (typeof sessionDirectory === "string" && sessionDirectory.trim()) {
                    return rememberSessionDirectory(sessionID, sessionDirectory);
                }
            }
        }
        catch { }
        // Retry failed location lookups instead of caching the startup project.
        return directory;
    };
    const forgetSessionRuntime = (sessionID) => {
        for (const runtime of runtimeByDirectory.values()) {
            runtime.engine.forgetSession(sessionID);
        }
        sessionDirectories.delete(sessionID);
    };
    const verificationStore = new VerificationSnapshotStore();
    const contracts = new Map();
    const setSessionContract = (sessionID, contract) => {
        contracts.delete(sessionID);
        contracts.set(sessionID, contract);
        while (contracts.size > 512) {
            const oldest = contracts.keys().next().value;
            if (oldest === undefined)
                break;
            contracts.delete(oldest);
        }
    };
    const foregroundHandoffs = new Map();
    const registrations = [];
    const interventionSnapshots = new Map();
    const toastNotifiersByDirectory = new Map();
    const idleQueue = createIdleQueue(controller.signal, () => {
        recordGuardianEvent({ kind: "inspection-error", rules: ["engine-inspection-failed"] }, directory);
    });
    if (typeof context.rpc?.register === "function") {
        try {
            const rpcRegistration = await context.rpc.register(GUARDIAN_INTERVENTION_RPC_DEFINITION, {
                [GUARDIAN_INTERVENTION_RPC_METHOD]: async (input) => {
                    const sessionID = readGuardianInterventionSessionID(input);
                    if (!sessionID)
                        return inactiveGuardianIntervention();
                    const payload = interventionSnapshots.get(sessionID);
                    return payload
                        ? activeGuardianIntervention(payload)
                        : inactiveGuardianIntervention();
                },
                [GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD]: async (input) => {
                    const sessionID = readGuardianInterventionSessionID(input);
                    if (sessionID) {
                        toastNotifier.clear?.(sessionID);
                        return { cleared: true };
                    }
                    for (const activeSessionID of Array.from(interventionSnapshots.keys())) {
                        const sessionDir = sessionDirectories.get(activeSessionID) ?? directory;
                        if (sessionDir === directory) {
                            toastNotifier.clear?.(activeSessionID);
                        }
                    }
                    dispatchGuardianToastClear({ directory });
                    return { cleared: true };
                },
            });
            if (rpcRegistration && typeof rpcRegistration.dispose === "function") {
                registrations.push(rpcRegistration);
            }
        }
        catch {
            // Visibility bridge is additive; core policy/security must keep running
            // even when this host build does not expose plugin RPC.
        }
    }
    const baseToastForDirectory = (runtimeDirectory) => {
        const key = runtimeDirectory || directory;
        const cached = toastNotifiersByDirectory.get(key);
        if (cached)
            return cached;
        const runtime = runtimeForDirectory(key);
        const notifier = createGuardianToastNotifier({
            context,
            directory: key,
            enabled: runtime.config.enabled !== false &&
                runtime.config.notifications?.enabled !== false,
        });
        toastNotifiersByDirectory.set(key, notifier);
        return notifier;
    };
    const toastNotifier = createTrackedToastNotifier({
        notify(input) {
            if (typeof input.sessionID === "string" &&
                input.sessionID.length > 0) {
                try {
                    interventionSnapshots.set(input.sessionID, formatGuardianToast(input));
                    while (interventionSnapshots.size > 64) {
                        const oldest = interventionSnapshots.keys().next().value;
                        if (typeof oldest !== "string")
                            break;
                        interventionSnapshots.delete(oldest);
                    }
                }
                catch { }
            }
            const runtimeDirectory = typeof input.sessionID === "string"
                ? sessionDirectories.get(input.sessionID) ?? directory
                : directory;
            baseToastForDirectory(runtimeDirectory).notify(input);
        },
        clear(sessionID) {
            interventionSnapshots.delete(sessionID);
            const runtimeDirectory = sessionDirectories.get(sessionID) ?? directory;
            baseToastForDirectory(runtimeDirectory).clear?.(sessionID);
        },
    });
    const streamWatcher = new StreamLoopWatcher({
        signal: controller.signal,
        directory,
        settings: async (sessionID) => {
            const targetDirectory = await resolveSessionDirectory(sessionID);
            return { config: runtimeForDirectory(targetDirectory).config, directory: targetDirectory };
        },
        interrupt: async (sessionID) => {
            if (typeof context.session.interrupt !== "function")
                throw new Error("Session interrupt unavailable");
            return context.session.interrupt({ sessionID, resume: false });
        },
        notifier: toastNotifier,
    });
    if (strictPreflight && typeof context.tool?.hook !== "function") {
        controller.abort();
        for (const registration of registrations.splice(0).reverse()) {
            try {
                await registration.dispose();
            }
            catch { }
        }
        throw new Error("[opencode-guardian preflight] V2 tool.execute.before hook is unavailable; strict preflight cannot be enabled.");
    }
    // Verification and foreground subagent finalization share one atomic
    // registration group. If either hook cannot be installed, dispose the other
    // immediately so a stale foreground marker can never suppress idle handling.
    if (sanitizerOpts && typeof context.tool?.hook !== "function") {
        controller.abort();
        for (const registration of registrations.splice(0).reverse()) {
            try {
                await registration.dispose();
            }
            catch { }
        }
        throw new Error("[opencode-guardian secrets] V2 execute.after hook is unavailable; POST redaction cannot be enabled safely.");
    }
    if (typeof context.tool?.hook === "function") {
        const toolRegistrations = [];
        const canFinalizeSubagent = typeof context.session.get === "function" &&
            typeof context.session.context === "function" &&
            typeof context.session.synthetic === "function" &&
            typeof context.session.wait === "function";
        {
            try {
                const before = await context.tool.hook("execute.before", async (event) => {
                    if (controller.signal.aborted)
                        return;
                    const runtimeDirectory = await resolveSessionDirectory(event.sessionID);
                    if (controller.signal.aborted)
                        return;
                    const runtime = runtimeForDirectory(runtimeDirectory);
                    if (runtime.config.enabled === false)
                        return;
                    if (event.input && typeof event.input === "object" && !Array.isArray(event.input)) {
                        verificationStore.observeBefore(event.sessionID, event.id, event.tool, event.input, runtimeDirectory);
                    }
                    if (runtime.config.preflight?.enabled === true) {
                        inspectPreflight(event.tool, event.input, event.sessionID, runtimeDirectory, runtime.config.preflight?.shellTools, toastNotifier);
                    }
                    if (canFinalizeSubagent && event.tool === "subagent") {
                        const input = event.input && typeof event.input === "object" && !Array.isArray(event.input)
                            ? event.input
                            : {};
                        if (input.background !== true) {
                            markForegroundHandoff(foregroundHandoffs, event.sessionID, event.id);
                        }
                    }
                });
                if (!before || typeof before.dispose !== "function") {
                    throw new Error("V2 tool.execute.before hook did not return a valid registration.");
                }
                toolRegistrations.push(before);
            }
            catch (error) {
                if (strictPreflight) {
                    controller.abort();
                    for (const registration of registrations.splice(0).reverse()) {
                        try {
                            await registration.dispose();
                        }
                        catch { }
                    }
                    throw new Error("[opencode-guardian preflight] V2 tool hook registration failed; strict preflight cannot be enabled.", { cause: error });
                }
            }
        }
        try {
            const after = await context.tool.hook("execute.after", async (event) => {
                if (controller.signal.aborted)
                    return;
                const input = event.input && typeof event.input === "object" && !Array.isArray(event.input)
                    ? event.input
                    : {};
                const tracked = canFinalizeSubagent &&
                    event.tool === "subagent" &&
                    input.background !== true &&
                    Boolean(foregroundHandoffs.get(event.sessionID)?.has(event.id));
                try {
                    const observedDirectory = await resolveSessionDirectory(event.sessionID);
                    const runtime = runtimeForDirectory(observedDirectory);
                    if (runtime.config.enabled === false)
                        return;
                    if (runtime.sanitizer && event.status === "error") {
                        event.error = sanitizeV2ToolError(event.error, runtime.sanitizer);
                    }
                    if (controller.signal.aborted)
                        return;
                    if (tracked && event.status === "completed") {
                        const current = event.result;
                        const structured = current.output && typeof current.output === "object" && !Array.isArray(current.output)
                            ? current.output
                            : undefined;
                        const childID = typeof current.metadata?.sessionID === "string"
                            ? current.metadata.sessionID
                            : typeof current.metadata?.sessionId === "string"
                                ? current.metadata.sessionId
                                : typeof structured?.sessionID === "string"
                                    ? structured.sessionID
                                    : typeof structured?.sessionId === "string"
                                        ? structured.sessionId
                                        : undefined;
                        const isBackground = input.background === true ||
                            current.metadata?.background === true ||
                            structured?.background === true;
                        // The completed tool event is authoritative when child status is omitted.
                        // Explicit failed/incomplete child states and background subagents must be ignored.
                        const childStatus = current.metadata?.status ?? structured?.status;
                        const completed = !isBackground && (childStatus === undefined || childStatus === "completed");
                        if (childID && completed) {
                            const child = await context.session.get({ sessionID: childID });
                            if (child.parentID !== event.sessionID) {
                                throw new Error("[opencode-guardian handoff] child session ownership mismatch.");
                            }
                            const childDirectory = rememberSessionDirectory(childID, typeof child.location?.directory === "string" && child.location.directory.trim()
                                ? child.location.directory
                                : observedDirectory);
                            const childRuntime = runtimeForDirectory(childDirectory);
                            const childAgent = typeof input.agent === "string" ? input.agent : undefined;
                            const revised = childRuntime.config.enabled === false
                                ? undefined
                                : await finalizeSubagentHandoff({
                                    sessionID: childID,
                                    directory: childDirectory,
                                    engine: childRuntime.engine,
                                    agentName: childAgent,
                                    resolveCapability: async () => {
                                        const cached = getCachedAgentCapability(childID);
                                        if (cached)
                                            return cached;
                                        let resolvedName = childAgent;
                                        if (!resolvedName) {
                                            try {
                                                const ctxMsgs = normalizeV2Messages(await context.session.context({ sessionID: childID }), childID);
                                                resolvedName = extractAgentNameFromMessages(ctxMsgs);
                                            }
                                            catch { }
                                        }
                                        const p = await resolveV2AgentCapability(context, childID, resolvedName, undefined, childDirectory);
                                        cacheAgentCapability(childID, p);
                                        return p;
                                    },
                                    fetchMessages: async () => normalizeV2Messages(await context.session.context({ sessionID: childID }), childID),
                                    sendAndWait: async (text) => {
                                        const remediationText = childRuntime.sanitizer
                                            ? sanitizeString(text, childRuntime.sanitizer).sanitized
                                            : text;
                                        await context.session.synthetic({
                                            sessionID: childID,
                                            text: remediationText,
                                            description: "OpenCode Guardian remediation",
                                            metadata: v2GuardianMetadata(childID, "remediation"),
                                            delivery: "queue",
                                            resume: true,
                                        });
                                        await context.session.wait({ sessionID: childID });
                                    },
                                    snapshots: () => verificationStore.snapshots(childID),
                                    signal: controller.signal,
                                    toastNotifier,
                                });
                            if (revised !== undefined) {
                                event.result = {
                                    ...event.result,
                                    output: {
                                        ...structured,
                                        sessionID: childID,
                                        status: "completed",
                                        output: revised,
                                    },
                                    content: `<subagent sessionID="${childID}" state="completed">\n${revised}\n</subagent>`,
                                    metadata: {
                                        ...current.metadata,
                                        sessionID: childID,
                                        status: "completed",
                                    },
                                };
                            }
                        }
                    }
                    // Foreground child finalization can replace the tool result with new
                    // text. Sanitize only after that rewrite so the parent never receives
                    // an unsanitized revised child result.
                    if (runtime.sanitizer && event.status === "completed") {
                        event.result = sanitizeToolResult(event.result, runtime.sanitizer);
                    }
                    const result = event.status === "completed" ? event.result : undefined;
                    verificationStore.observe(event.sessionID, event.id, event.tool, input, result?.output ?? result?.content ?? "", result?.metadata ?? {}, observedDirectory, event.status);
                }
                finally {
                    if (tracked) {
                        clearForegroundHandoff(foregroundHandoffs, event.sessionID, event.id);
                    }
                }
            });
            if (!after || typeof after.dispose !== "function") {
                throw new Error("V2 execute.after registration has no disposer");
            }
            toolRegistrations.push(after);
            toolOutputProtectionReady = true;
        }
        catch {
            recordGuardianEvent({ kind: "verification-unavailable",
                rules: ["verification-snapshot-unavailable"] }, directory);
            if (sanitizerOpts) {
                controller.abort();
                for (const registration of toolRegistrations.splice(0).reverse()) {
                    try {
                        await registration.dispose();
                    }
                    catch { }
                }
                for (const registration of registrations.splice(0).reverse()) {
                    try {
                        await registration.dispose();
                    }
                    catch { }
                }
                throw new Error("[opencode-guardian secrets] V2 execute.after security hook registration failed; POST redaction cannot be enabled safely.");
            }
        }
        registrations.push(...toolRegistrations);
    }
    if (typeof context.shell?.hook === "function") {
        try {
            const shellBefore = await context.shell.hook("create.before", async (event) => {
                if (controller.signal.aborted)
                    return;
                const eventRecord = event;
                const sid = typeof eventRecord.sessionID === "string" ? eventRecord.sessionID : undefined;
                const runtimeDirectory = sid
                    ? await resolveSessionDirectory(sid)
                    : (typeof eventRecord.location?.directory === "string" && eventRecord.location.directory.trim()
                        ? eventRecord.location.directory
                        : directory);
                if (controller.signal.aborted)
                    return;
                const runtime = runtimeForDirectory(runtimeDirectory);
                if (runtime.config.enabled === false)
                    return;
                if (runtime.config.preflight?.enabled === true) {
                    inspectPreflight("shell", { command: eventRecord.command }, sid, runtimeDirectory, runtime.config.preflight?.shellTools, toastNotifier);
                }
            });
            if (!shellBefore || typeof shellBefore.dispose !== "function") {
                throw new Error("V2 shell.create.before hook did not return a valid registration.");
            }
            registrations.push(shellBefore);
        }
        catch (error) {
            if (strictPreflight) {
                controller.abort();
                for (const registration of registrations.splice(0).reverse()) {
                    try {
                        await registration.dispose();
                    }
                    catch { }
                }
                throw new Error("[opencode-guardian preflight] V2 shell hook registration failed; strict preflight cannot be enabled.", { cause: error });
            }
        }
    }
    if (sanitizerOpts && typeof context.session.hook !== "function") {
        controller.abort();
        for (const registration of registrations.splice(0).reverse()) {
            try {
                await registration.dispose();
            }
            catch { }
        }
        throw new Error("[opencode-guardian secrets] V2 session.context hook is unavailable; FINAL context redaction cannot be enabled safely.");
    }
    if (typeof context.session.hook === "function") {
        const taskRegistrations = [];
        let auxiliaryRegistrationStarted = false;
        try {
            const promptRegistration = await context.session.hook("prompt", async (event) => {
                if (isTrustedGuardianMetadata(event.sessionID, event.metadata, "visible") ||
                    isTrustedGuardianMetadata(event.sessionID, event.metadata, "remediation")) {
                    return;
                }
                idleQueue.forget(event.sessionID);
                contracts.delete(event.sessionID);
                const runtimeDirectory = await resolveSessionDirectory(event.sessionID);
                const runtime = runtimeForDirectory(runtimeDirectory);
                if (runtime.config.enabled === false) {
                    return;
                }
                toastNotifier[INTERVENTION_TRACKER]?.noteHumanPrompt(event.sessionID);
                const text = typeof event.prompt?.text === "string" ? event.prompt.text : "";
                if (!text)
                    return;
                verificationStore.beginTurn(event.sessionID);
                const contract = extractTaskContract([{
                        info: { id: event.messageID, role: "user" },
                        parts: [{ type: "text", text }],
                    }]);
                if (contract)
                    setSessionContract(event.sessionID, contract);
            });
            if (!promptRegistration || typeof promptRegistration.dispose !== "function") {
                throw new Error("V2 prompt hook did not return a valid registration.");
            }
            taskRegistrations.push(promptRegistration);
            const sanitizeV2ModelRequest = async (event) => {
                if (Array.isArray(event.messages)) {
                    event.messages = event.messages.filter((message) => !isTrustedGuardianMetadata(event.sessionID, message.metadata, "visible"));
                }
                const runtimeDirectory = await resolveSessionDirectory(event.sessionID);
                const runtime = runtimeForDirectory(runtimeDirectory);
                if (runtime.config.enabled === false || !runtime.sanitizer)
                    return runtime;
                if (Array.isArray(event.messages)) {
                    event.messages = sanitizeMessages(event.messages, runtime.sanitizer);
                }
                if (Array.isArray(event.system)) {
                    const sanitizedSystem = sanitizeObject(event.system, runtime.sanitizer).sanitized;
                    event.system = Array.isArray(sanitizedSystem)
                        ? sanitizedSystem
                        : [{
                                type: "text",
                                text: "[OUTPUT REDACTED: sanitization failure]",
                                metadata: { "opencode-guardian": true },
                            }];
                }
                return runtime;
            };
            const contextRegistration = await context.session.hook("context", async (event) => {
                const runtime = await sanitizeV2ModelRequest(event);
                if (runtime.config.enabled === false)
                    return;
                const contract = contracts.get(event.sessionID);
                if (!contract)
                    return;
                const guidance = taskGuidance(contract);
                if (guidance && Array.isArray(event.system) && !event.system.some((part) => part.text === guidance)) {
                    event.system.push({ type: "text", text: guidance, metadata: { "opencode-guardian": true } });
                }
            });
            if (!contextRegistration || typeof contextRegistration.dispose !== "function") {
                throw new Error("V2 context hook did not return a valid registration.");
            }
            taskRegistrations.push(contextRegistration);
            // The next request may belong to a different project, or follow a
            // configuration update. Register every model boundary up front and
            // consult the active request's settings inside the callback.
            auxiliaryRegistrationStarted = true;
            for (const kind of ["compaction", "generate", "title"]) {
                const registration = await context.session.hook(kind, async (event) => {
                    await sanitizeV2ModelRequest(event);
                });
                if (!registration || typeof registration.dispose !== "function") {
                    throw new Error("V2 auxiliary model hook did not return a valid registration.");
                }
                taskRegistrations.push(registration);
            }
            registrations.push(...taskRegistrations);
            modelRequestProtectionReady = true;
        }
        catch {
            // Never leave a partial task/security hook group installed.
            await Promise.allSettled(taskRegistrations.map((registration) => Promise.resolve().then(() => registration.dispose())));
            contracts.clear();
            recordGuardianEvent({ kind: "inspection-error" }, directory);
            if (sanitizerOpts || auxiliaryRegistrationStarted) {
                controller.abort();
                for (const registration of registrations.splice(0).reverse()) {
                    try {
                        await registration.dispose();
                    }
                    catch { }
                }
                throw new Error("[opencode-guardian secrets] V2 session context security hook registration failed; FINAL context redaction cannot be enabled safely.");
            }
        }
    }
    const eventLoop = async () => {
        if (!events)
            return;
        let activeEvents = events;
        // A terminated stream must never disable session inspection silently.
        // Retry a bounded number of times and keep strict tool hooks registered.
        for (let attempt = 0; attempt < 3 && !controller.signal.aborted; attempt++) {
            try {
                for await (const event of activeEvents) {
                    const eventData = event;
                    streamWatcher.dispatch(event);
                    if (eventData.type === "session.created" || eventData.type === "session.forked") {
                        const createdSessionID = eventData.data?.sessionID ?? eventData.data?.info?.id;
                        if (createdSessionID) {
                            const createdDirectory = eventData.data?.location?.directory ?? eventData.location?.directory;
                            if (typeof createdDirectory === "string" && createdDirectory.trim()) {
                                rememberSessionDirectory(createdSessionID, createdDirectory);
                            }
                        }
                    }
                    if (eventData.type === "session.deleted") {
                        const deletedSessionID = eventData.data?.sessionID ?? eventData.data?.info?.id;
                        if (deletedSessionID) {
                            idleQueue.forget(deletedSessionID);
                            forgetSessionRuntime(deletedSessionID);
                            verificationStore.forget(deletedSessionID);
                            contracts.delete(deletedSessionID);
                            foregroundHandoffs.delete(deletedSessionID);
                            toastNotifier.clear?.(deletedSessionID);
                            interventionSnapshots.delete(deletedSessionID);
                            clearAgentCapability(deletedSessionID);
                            forgetGuardianProvenance(deletedSessionID);
                            provenanceSessions.delete(deletedSessionID);
                        }
                        continue;
                    }
                    if (eventData.type === "session.permissions") {
                        const permissionSessionID = eventData.data?.sessionID;
                        if (permissionSessionID) {
                            clearAgentCapability(permissionSessionID);
                            if (Array.isArray(eventData.data?.permissions)) {
                                cacheV2SessionPermissions(permissionSessionID, eventData.data.permissions);
                            }
                        }
                        continue;
                    }
                    if (eventData.type === "session.agent.selected") {
                        if (eventData.data?.sessionID) {
                            clearAgentCapability(eventData.data.sessionID);
                        }
                        continue;
                    }
                    if (eventData.type === "session.moved") {
                        const movedSessionID = eventData.data?.sessionID;
                        if (movedSessionID) {
                            idleQueue.forget(movedSessionID);
                            forgetSessionRuntime(movedSessionID);
                            const movedDirectory = eventData.data?.location?.directory ?? eventData.location?.directory;
                            if (typeof movedDirectory === "string" && movedDirectory.trim()) {
                                rememberSessionDirectory(movedSessionID, movedDirectory);
                            }
                            verificationStore.forget(movedSessionID);
                            contracts.delete(movedSessionID);
                            foregroundHandoffs.delete(movedSessionID);
                            toastNotifier.clear?.(movedSessionID);
                            interventionSnapshots.delete(movedSessionID);
                            clearAgentCapability(movedSessionID);
                            forgetGuardianProvenance(movedSessionID);
                            provenanceSessions.delete(movedSessionID);
                        }
                        continue;
                    }
                    if (eventData.type === "agent.updated") {
                        clearAllAgentCapabilities();
                        continue;
                    }
                    if (eventData.type === "config.updated") {
                        clearAllAgentCapabilities();
                        runtimeByDirectory.clear();
                        toastNotifiersByDirectory.clear();
                        continue;
                    }
                    const idleEvent = eventData.type === "session.idle" ||
                        (eventData.type === "session.status" &&
                            eventData.data?.status?.type === "idle");
                    if (!idleEvent)
                        continue;
                    const sessionID = eventData.data?.sessionID;
                    if (!sessionID)
                        continue;
                    idleQueue.enqueue(sessionID, async (idleSignal) => {
                        let activeDirectory = await resolveSessionDirectory(sessionID);
                        let sessionIsSubagent;
                        let sessionParentID;
                        try {
                            if (typeof context.session.get === "function") {
                                const session = await context.session.get({ sessionID });
                                activeDirectory = rememberSessionDirectory(sessionID, session.location?.directory);
                                sessionParentID =
                                    typeof session.parentID === "string" && session.parentID.length > 0
                                        ? session.parentID
                                        : undefined;
                                const isForkedSession = Boolean(session.fork && typeof session.fork === "object");
                                sessionIsSubagent = Boolean(sessionParentID) && !isForkedSession;
                            }
                        }
                        catch {
                            // A transient/partial host must not disable the existing idle path.
                        }
                        if (sessionParentID && sessionIsSubagent !== false && hasForegroundHandoff(foregroundHandoffs, sessionParentID)) {
                            return;
                        }
                        const runtime = runtimeForDirectory(activeDirectory);
                        if (runtime.config.enabled === false || idleSignal.aborted)
                            return;
                        await handleSessionIdle(sessionID, activeDirectory, async () => {
                            const messages = await context.session.context({ sessionID });
                            const normalized = normalizeV2Messages(messages, sessionID);
                            const contract = extractTaskContract(normalized);
                            if (contract)
                                setSessionContract(sessionID, contract);
                            return normalized;
                        }, async (text) => {
                            if (idleSignal.aborted)
                                return;
                            const remediationText = runtime.sanitizer
                                ? sanitizeString(text, runtime.sanitizer).sanitized
                                : text;
                            await context.session.synthetic({
                                sessionID,
                                text: remediationText,
                                description: "OpenCode Guardian remediation",
                                metadata: v2GuardianMetadata(sessionID, "remediation"),
                                delivery: "queue",
                                resume: true,
                            });
                        }, runtime.engine, verificationStore.snapshots(sessionID), idleSignal, sessionIsSubagent, sessionIsSubagent
                            ? async () => {
                                const cached = getCachedAgentCapability(sessionID);
                                if (cached)
                                    return cached;
                                let agentName;
                                try {
                                    const msgs = await context.session.context({ sessionID });
                                    const normalized = normalizeV2Messages(msgs, sessionID);
                                    agentName = extractAgentNameFromMessages(normalized);
                                }
                                catch { }
                                const p = await resolveV2AgentCapability(context, sessionID, agentName, undefined, activeDirectory);
                                if (!idleSignal.aborted)
                                    cacheAgentCapability(sessionID, p);
                                return p;
                            }
                            : undefined, toastNotifier);
                    });
                }
                if (controller.signal.aborted)
                    return;
                throw new Error("V2 event stream ended before plugin teardown.");
            }
            catch {
                if (controller.signal.aborted)
                    return;
                recordGuardianEvent({ kind: "inspection-error",
                    rules: ["v2-event-stream-error"],
                    reasons: [{ rule: "v2-event-stream-error", code: "v2-event-stream-error" }],
                }, directory);
                // Record only the redacted error; never write host exceptions to the TUI.
            }
            if (attempt === 2) {
                // Final inspection-error remains visible in the status panel.
                return;
            }
            await new Promise((resolve) => {
                const onAbort = () => {
                    clearTimeout(timer);
                    controller.signal.removeEventListener("abort", onAbort);
                    resolve();
                };
                const timer = setTimeout(() => {
                    controller.signal.removeEventListener("abort", onAbort);
                    resolve();
                }, 200 * (attempt + 1));
                if (controller.signal.aborted)
                    onAbort();
                else
                    controller.signal.addEventListener("abort", onAbort, { once: true });
            });
            if (controller.signal.aborted)
                return;
            try {
                const next = context.event.subscribe({ signal: controller.signal });
                if (!next || typeof next[Symbol.asyncIterator] !== "function") {
                    throw new Error("V2 event resubscription did not return an async iterable.");
                }
                activeEvents = next;
            }
            catch {
                if (!controller.signal.aborted) {
                    recordGuardianEvent({ kind: "inspection-error",
                        rules: ["v2-event-stream-error"],
                        reasons: [{ rule: "v2-event-stream-error", code: "v2-event-stream-error" }],
                    }, directory);
                    // The failure has been recorded without exposing exception data.
                }
                return;
            }
        }
    };
    const unregisterGuardianCapability = registerGuardianCapability();
    recordGuardianEvent({ kind: "runtime-started", runtime: "v2", preflight: strictPreflight ? "active" : "disabled" }, directory);
    if (events) {
        void eventLoop();
    }
    else {
        recordGuardianEvent({
            kind: "inspection-error",
            rules: ["v2-event-stream-unavailable"],
            reasons: [{
                    rule: "v2-event-stream-unavailable",
                    code: "v2-event-stream-unavailable",
                }],
        }, directory);
    }
    return async () => {
        controller.abort();
        streamWatcher.clear();
        await streamWatcher.drain();
        contracts.clear();
        verificationStore.clear();
        foregroundHandoffs.clear();
        interventionSnapshots.clear();
        for (const sessionID of sessionDirectories.keys()) {
            clearAgentCapability(sessionID);
        }
        sessionDirectories.clear();
        for (const sessionID of provenanceSessions) {
            forgetGuardianProvenance(sessionID);
            clearAgentCapability(sessionID);
        }
        provenanceSessions.clear();
        unregisterGuardianCapability();
        for (const registration of registrations.splice(0).reverse()) {
            try {
                await registration.dispose();
            }
            catch {
                // An optional disposer failing must not prevent remaining cleanup.
            }
        }
    };
};
/**
 * OpenCode V2 Plugin Definition.
 */
export const OpencodeGuardian = {
    id: "opencode-guardian",
    setup,
};
export const OpencodeGuard = OpencodeGuardian;
export default OpencodeGuardian;
