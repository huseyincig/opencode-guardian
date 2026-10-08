import { GuardEngine, loadConfig } from "./engine.js";
import { extractTaskContract, taskGuidance } from "./task-contract.js";
import { evaluatePreflight, GuardianPreflightError, isShellExecutionTool, isFileMutationTool, isProcessStartTool } from "./preflight.js";
import { recordGuardianEvent, sessionFingerprint } from "./telemetry.js";
import { auditReasons } from "./audit.js";
import { VerificationSnapshotStore } from "./evidence.js";
import { announceGuardianUpdate } from "./version-notice.js";
import { createV1TurnWatcher } from "./v1-turn-watcher.js";
import { registerGuardianCapability } from "./handoff.js";
import { resolveV1AgentCapability, resolveV2AgentCapability, getCachedAgentCapability, cacheAgentCapability, clearAgentCapability, clearAllAgentCapabilities, extractAgentNameFromMessages, } from "./agent-capability.js";
import { assessCommandPreflight, resolveSanitizerOptions, sanitizeMessages, sanitizeObject, sanitizeString, sanitizeToolResult, } from "./secrets/index.js";
import { createGuardianToastNotifier, formatGuardianToast, } from "./toast.js";
import { formatGuardianTranscriptMessage, GUARDIAN_VISIBLE_INTERVENTION_KEY, isGuardianVisibleInterventionMetadata, } from "./intervention.js";
import { GUARDIAN_INTERVENTION_RPC_DEFINITION, GUARDIAN_INTERVENTION_RPC_METHOD, activeGuardianIntervention, inactiveGuardianIntervention, readGuardianInterventionSessionID, } from "./intervention-rpc.js";
export * from "./types.js";
export * from "./engine.js";
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
export * from "./v1-turn-watcher.js";
export * from "./handoff.js";
export * from "./agent-capability.js";
export * from "./secrets/index.js";
export * from "./toast.js";
export * from "./intervention.js";
export * from "./intervention-rpc.js";
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
    if (value.type === "text" && typeof value.text === "string") {
        return { type: "text", text: value.text };
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
export function normalizeV2Messages(messages) {
    const normalized = [];
    for (const raw of messages) {
        if (!raw || typeof raw !== "object")
            continue;
        const msg = raw;
        const id = typeof msg.id === "string" ? msg.id : undefined;
        const type = typeof msg.type === "string" ? msg.type : undefined;
        if (!id || !type)
            continue;
        if (isGuardianVisibleInterventionMetadata(msg.metadata))
            continue;
        if (type === "user" && typeof msg.text === "string") {
            normalized.push({
                info: { id, role: "user" },
                parts: [{ type: "text", text: msg.text }],
            });
            continue;
        }
        if (type === "synthetic" && typeof msg.text === "string") {
            normalized.push({
                info: { id, role: "user" },
                parts: [{ type: "text", text: msg.text, synthetic: true }],
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
function renderV1TaskResult(sessionID, text) {
    return [
        `<task id="${sessionID}" state="completed">`,
        "<task_result>",
        text,
        "</task_result>",
        "</task>",
    ].join("\n");
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
function recordInspectionOutcome(result, sessionID, directory, toastNotifier) {
    const findings = result.results.filter((item) => item.findings.length > 0);
    if (result.remediationStatus === "verified") {
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
 * Common handler to process session.idle events across v1 and v2.
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
                await sendPrompt(result.combinedRemediationPrompt, findings.map((item) => item.ruleId));
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
const server = async ({ client, directory }, pluginOptions) => {
    registerGuardianCapability();
    const config = loadConfig(directory);
    if (config.enabled === false) {
        recordGuardianEvent({ kind: "runtime-started", runtime: "v1", preflight: "disabled" }, directory);
        // Preserve the V1 hook shape without inspecting turns or injecting context.
        return {
            "chat.message": async () => { },
            "experimental.chat.system.transform": async () => { },
            event: async () => { },
        };
    }
    const rawOptions = (pluginOptions && typeof pluginOptions === "object" ? pluginOptions : {});
    const mergedConfig = {
        ...config,
        ...(typeof rawOptions.enabled === "boolean" ? { enabled: rawOptions.enabled } : {}),
        ...(rawOptions.notifications && typeof rawOptions.notifications === "object"
            ? { notifications: rawOptions.notifications }
            : {}),
        secrets: {
            ...config.secrets,
            ...(rawOptions.secrets && typeof rawOptions.secrets === "object" ? rawOptions.secrets : {}),
            ...(typeof rawOptions.replacement === "string" ? { replacement: rawOptions.replacement } : {}),
            ...(Array.isArray(rawOptions.customSensitiveKeys) ? { customSensitiveKeys: rawOptions.customSensitiveKeys } : {}),
            ...(Array.isArray(rawOptions.customSecretValues) ? { customSecretValues: rawOptions.customSecretValues } : {}),
        },
    };
    const sanitizerOpts = resolveSanitizerOptions(mergedConfig);
    const toastNotifier = createGuardianToastNotifier({
        client,
        directory,
        enabled: mergedConfig.notifications?.enabled !== false,
    });
    const engine = new GuardEngine(mergedConfig);
    const verificationStore = new VerificationSnapshotStore();
    const contracts = new Map();
    let promptSequence = 0;
    let updateChecked = false;
    const strictPreflight = config.preflight?.enabled === true;
    const foregroundHandoffs = new Map();
    const sendV1Remediation = async (sessionID, text, ruleIds) => {
        const response = await client.session.promptAsync({
            path: { id: sessionID },
            query: { directory },
            body: {
                parts: [{
                        type: "text",
                        text,
                        synthetic: true,
                        metadata: { "opencode-guardian": true },
                    }],
            },
        });
        if (response.error) {
            throw new Error("V1 host rejected the Guardian remediation request.");
        }
        // The remediation above is intentionally synthetic and hidden by OpenCode.
        // Add a second, display-only transcript row without triggering a model turn.
        try {
            const visible = await client.session.promptAsync({
                path: { id: sessionID },
                query: { directory },
                body: {
                    noReply: true,
                    parts: [{
                            type: "text",
                            text: formatGuardianTranscriptMessage({
                                kind: "remediation",
                                ruleIds,
                            }),
                            ignored: true,
                            metadata: {
                                "opencode-guardian": true,
                                [GUARDIAN_VISIBLE_INTERVENTION_KEY]: true,
                            },
                        }],
                },
            });
            if (visible.error) {
                return;
            }
        }
        catch {
            // Transcript visibility is secondary to the already-delivered
            // remediation. Native toast remains the fallback UI channel.
        }
    };
    const hostSessionRelation = async (sessionID) => {
        const getSession = client.session.get;
        if (typeof getSession !== "function")
            return { known: false };
        try {
            const response = await getSession.call(client.session, {
                path: { id: sessionID },
                query: { directory },
            });
            if (response.error || !response.data)
                return { known: false };
            const parentID = typeof response.data.parentID === "string" && response.data.parentID.length > 0
                ? response.data.parentID
                : undefined;
            return { known: true, ...(parentID ? { parentID } : {}) };
        }
        catch {
            return { known: false };
        }
    };
    // Only active, newly prompted V1 sessions are probed. No global session
    // scanning and no inspection before the SDK confirms a completed response.
    const watcher = typeof client.session.status === "function"
        ? createV1TurnWatcher({
            status: async (sessionID) => {
                const response = await client.session.status({ query: { directory } });
                if (response.error || !response.data || typeof response.data !== "object") {
                    throw new Error("V1 session.status() did not return a status map.");
                }
                return response.data[sessionID]?.type;
            },
            messages: async (sessionID) => {
                const response = await client.session.messages({
                    path: { id: sessionID }, query: { directory },
                });
                if (response.error || !Array.isArray(response.data)) {
                    throw new Error("V1 session.messages() did not return messages.");
                }
                return response.data;
            },
            onIdle: async (sessionID, messages) => {
                const relation = await hostSessionRelation(sessionID);
                if (relation.parentID && hasForegroundHandoff(foregroundHandoffs, relation.parentID)) {
                    return;
                }
                const contract = extractTaskContract(messages);
                if (contract)
                    contracts.set(sessionID, contract);
                await handleSessionIdle(sessionID, directory, async () => messages, async (text, ruleIds) => sendV1Remediation(sessionID, text, ruleIds), engine, verificationStore.snapshots(sessionID), undefined, relation.known ? Boolean(relation.parentID) : undefined, relation.known && relation.parentID
                    ? async () => {
                        const cached = getCachedAgentCapability(sessionID);
                        if (cached)
                            return cached;
                        const agentName = extractAgentNameFromMessages(messages);
                        const p = await resolveV1AgentCapability(client, directory, agentName);
                        cacheAgentCapability(sessionID, p);
                        return p;
                    }
                    : undefined, toastNotifier);
            },
            onError: (sessionID, _error) => {
                // The V1 host can render console output over its interactive prompt.
                // Surface probe failures through the redacted local event log / TUI
                // error counter instead of printing a stack into the terminal.
                recordGuardianEvent({
                    kind: "inspection-error",
                    session: sessionFingerprint(sessionID),
                    rules: ["v1-completion-probe"],
                }, directory);
            },
        })
        : undefined;
    recordGuardianEvent({ kind: "runtime-started", runtime: "v1", preflight: strictPreflight ? "active" : "disabled" }, directory);
    return {
        dispose: async () => {
            watcher?.stopAll();
            verificationStore.clear();
            contracts.clear();
            foregroundHandoffs.clear();
            clearAllAgentCapabilities();
        },
        "tool.execute.before": async (input, output) => {
            const args = output.args && typeof output.args === "object" && !Array.isArray(output.args)
                ? output.args
                : {};
            const cmd = args.command ?? args.cmd;
            if (cmd) {
                assessCommandPreflight(cmd);
            }
            if (input.tool === "task" &&
                typeof input.sessionID === "string" &&
                typeof input.callID === "string" &&
                args.background !== true) {
                markForegroundHandoff(foregroundHandoffs, input.sessionID, input.callID);
            }
            if (strictPreflight) {
                inspectPreflight(input.tool, output.args, input.sessionID, directory, config.preflight?.shellTools, toastNotifier);
            }
        },
        "tool.execute.after": async (input, output) => {
            const args = input.args && typeof input.args === "object" && !Array.isArray(input.args)
                ? input.args
                : {};
            const tracked = input.tool === "task" &&
                typeof input.sessionID === "string" &&
                typeof input.callID === "string" &&
                args.background !== true &&
                Boolean(foregroundHandoffs.get(input.sessionID)?.has(input.callID));
            try {
                if (tracked &&
                    output.metadata &&
                    typeof output.metadata === "object" &&
                    !Array.isArray(output.metadata)) {
                    const metadata = output.metadata;
                    const childID = typeof metadata.sessionId === "string" ? metadata.sessionId : undefined;
                    const background = metadata.background === true;
                    if (childID && !background) {
                        const relation = await hostSessionRelation(childID);
                        if (relation.known && relation.parentID !== input.sessionID) {
                            throw new Error("[opencode-guardian handoff] child session ownership mismatch.");
                        }
                        if (relation.known) {
                            const childAgent = typeof args.agent === "string" ? args.agent : undefined;
                            const revised = await finalizeSubagentHandoff({
                                sessionID: childID,
                                directory,
                                engine,
                                agentName: childAgent,
                                resolveCapability: async () => {
                                    const cached = getCachedAgentCapability(childID);
                                    if (cached)
                                        return cached;
                                    let resolvedName = childAgent;
                                    if (!resolvedName) {
                                        try {
                                            const res = await client.session.messages({
                                                path: { id: childID },
                                                query: { directory },
                                            });
                                            if (Array.isArray(res?.data)) {
                                                resolvedName = extractAgentNameFromMessages(res.data);
                                            }
                                        }
                                        catch { }
                                    }
                                    const p = await resolveV1AgentCapability(client, directory, resolvedName);
                                    cacheAgentCapability(childID, p);
                                    return p;
                                },
                                fetchMessages: async () => {
                                    const response = await client.session.messages({
                                        path: { id: childID },
                                        query: { directory },
                                    });
                                    if (response.error || !Array.isArray(response.data)) {
                                        throw new Error("V1 child messages unavailable.");
                                    }
                                    return response.data;
                                },
                                sendAndWait: async (text) => {
                                    const response = await client.session.prompt({
                                        path: { id: childID },
                                        query: { directory },
                                        body: { parts: [{ type: "text", text }] },
                                    });
                                    if (response.error) {
                                        throw new Error("V1 child remediation failed.");
                                    }
                                },
                                snapshots: () => verificationStore.snapshots(childID),
                                toastNotifier,
                            });
                            if (revised !== undefined) {
                                output.output = renderV1TaskResult(childID, revised);
                            }
                        }
                    }
                }
                if (sanitizerOpts && output) {
                    if (typeof output.output === "string") {
                        const sanitized = sanitizeString(output.output, sanitizerOpts);
                        output.output = sanitized.sanitized;
                    }
                    else if (output.output && typeof output.output === "object") {
                        output.output = sanitizeToolResult(output.output, sanitizerOpts);
                    }
                    if (output.metadata && typeof output.metadata === "object") {
                        const sanitizedMeta = sanitizeObject(output.metadata, sanitizerOpts);
                        output.metadata = sanitizedMeta.sanitized;
                    }
                }
                verificationStore.observe(input.sessionID, input.callID, input.tool, args, output.output, output.metadata && typeof output.metadata === "object"
                    ? output.metadata
                    : {}, directory);
            }
            finally {
                if (tracked) {
                    clearForegroundHandoff(foregroundHandoffs, input.sessionID, input.callID);
                }
            }
        },
        "chat.message": async (input, output) => {
            if (output.parts.some((part) => part.type === "text" &&
                isGuardianVisibleInterventionMetadata(part.metadata))) {
                return;
            }
            const text = output.parts
                .map((part) => part.type === "text" ? part.text : "")
                .join("\n");
            if (!text)
                return;
            if (!text.trimStart().startsWith("[opencode-guardian remediation]")) {
                const contract = extractTaskContract([{
                        info: { id: input.messageID ?? ("v1-prompt-" + (++promptSequence)), role: "user" },
                        parts: [{ type: "text", text }],
                    }]);
                if (contract)
                    contracts.set(input.sessionID, contract);
            }
            watcher?.watch(input.sessionID);
        },
        "experimental.chat.system.transform": async (input, output) => {
            if (sanitizerOpts && Array.isArray(output.system)) {
                output.system = output.system.map((part) => sanitizeString(part, sanitizerOpts).sanitized);
            }
            if (!input.sessionID)
                return;
            const contract = contracts.get(input.sessionID);
            if (!contract)
                return;
            const guidance = taskGuidance(contract);
            if (guidance && !output.system.includes(guidance)) {
                output.system.push(guidance);
            }
        },
        "experimental.chat.messages.transform": async (_input, output) => {
            if (sanitizerOpts && output && Array.isArray(output.messages)) {
                output.messages = sanitizeMessages(output.messages, sanitizerOpts);
            }
        },
        event: async ({ event }) => {
            const eventData = event;
            if (eventData.type === "session.created" && !updateChecked && config.updateNotice?.enabled !== false) {
                updateChecked = true;
                const tui = client.tui;
                if (typeof tui?.showToast === "function") {
                    const showToast = tui.showToast;
                    void announceGuardianUpdate((current, latest) => showToast({
                        body: { title: "OpenCode Guardian — New version", message: `v${current} → v${latest} (update manually)`, variant: "info", duration: 5000 },
                    }));
                }
            }
            if (eventData.type === "session.deleted") {
                const deletedSessionID = eventData.properties?.sessionID ??
                    eventData.data?.sessionID ??
                    eventData.data?.info?.id;
                if (deletedSessionID) {
                    watcher?.stop(deletedSessionID);
                    engine.forgetSession(deletedSessionID);
                    verificationStore.forget(deletedSessionID);
                    contracts.delete(deletedSessionID);
                    foregroundHandoffs.delete(deletedSessionID);
                    clearAgentCapability(deletedSessionID);
                }
                return;
            }
            if (eventData.type !== "session.idle")
                return;
            const sessionID = eventData.properties?.sessionID ?? eventData.data?.sessionID;
            if (!sessionID)
                return;
            watcher?.stop(sessionID);
            const relation = await hostSessionRelation(sessionID);
            if (relation.parentID && hasForegroundHandoff(foregroundHandoffs, relation.parentID)) {
                return;
            }
            const isSubagent = relation.known ? Boolean(relation.parentID) : undefined;
            await handleSessionIdle(sessionID, directory, async () => {
                const res = await client.session.messages({
                    path: { id: sessionID },
                    query: { directory },
                });
                if (res?.error || !Array.isArray(res?.data)) {
                    throw new Error("V1 session.messages() failed during idle inspection.");
                }
                const messages = res.data;
                const contract = extractTaskContract(messages);
                if (contract)
                    contracts.set(sessionID, contract);
                return messages;
            }, async (text, ruleIds) => sendV1Remediation(sessionID, text, ruleIds), engine, verificationStore.snapshots(sessionID), undefined, isSubagent, isSubagent
                ? async () => {
                    const cached = getCachedAgentCapability(sessionID);
                    if (cached)
                        return cached;
                    const res = await client.session.messages({
                        path: { id: sessionID },
                        query: { directory },
                    });
                    const msgs = Array.isArray(res?.data) ? res.data : [];
                    const agentName = extractAgentNameFromMessages(msgs);
                    const p = await resolveV1AgentCapability(client, directory, agentName);
                    cacheAgentCapability(sessionID, p);
                    return p;
                }
                : undefined, toastNotifier);
        },
    };
};
const setup = async (context) => {
    registerGuardianCapability();
    // Transition builds may call setup() with a partial v2 context.
    // Resolve the explicit security setting first: strict preflight must never
    // silently disappear merely because another v2 capability is unavailable.
    const directory = context?.location?.directory ?? process.cwd();
    const config = loadConfig(directory);
    if (config.enabled === false) {
        recordGuardianEvent({ kind: "runtime-started", runtime: "v2", preflight: "disabled" }, directory);
        return;
    }
    const rawOptions = context?.options;
    const mergedConfig = {
        ...config,
        ...(rawOptions && typeof rawOptions.enabled === "boolean" ? { enabled: rawOptions.enabled } : {}),
        ...(rawOptions?.notifications && typeof rawOptions.notifications === "object"
            ? { notifications: rawOptions.notifications }
            : {}),
        secrets: {
            ...config.secrets,
            ...(rawOptions?.secrets && typeof rawOptions.secrets === "object" ? rawOptions.secrets : {}),
            ...(typeof rawOptions?.replacement === "string" ? { replacement: rawOptions.replacement } : {}),
            ...(Array.isArray(rawOptions?.customSensitiveKeys) ? { customSensitiveKeys: rawOptions.customSensitiveKeys } : {}),
            ...(Array.isArray(rawOptions?.customSecretValues) ? { customSecretValues: rawOptions.customSecretValues } : {}),
        },
    };
    const sanitizerOpts = resolveSanitizerOptions(mergedConfig);
    const strictPreflight = config.preflight?.enabled === true;
    if (!context ||
        typeof context !== "object" ||
        typeof context.event?.subscribe !== "function" ||
        typeof context.session?.context !== "function" ||
        typeof context.session?.synthetic !== "function") {
        if (strictPreflight) {
            throw new Error("[opencode-guardian preflight] V2 host context is unavailable; strict preflight cannot be enabled.");
        }
        if (sanitizerOpts) {
            throw new Error("[opencode-guardian secrets] V2 host context is unavailable; secret protection cannot be enabled safely.");
        }
        return;
    }
    const controller = new AbortController();
    let events;
    try {
        const candidate = context.event.subscribe({
            signal: controller.signal,
        });
        if (!candidate ||
            typeof candidate[Symbol.asyncIterator] !==
                "function") {
            controller.abort();
            if (strictPreflight) {
                throw new Error("[opencode-guardian preflight] V2 event subscription is unavailable; strict preflight cannot be enabled.");
            }
            if (sanitizerOpts) {
                throw new Error("[opencode-guardian secrets] V2 event subscription is unavailable; secret protection cannot be enabled safely.");
            }
            return;
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
    const engine = new GuardEngine(mergedConfig);
    const verificationStore = new VerificationSnapshotStore();
    const contracts = new Map();
    const foregroundHandoffs = new Map();
    const registrations = [];
    const interventionSnapshots = new Map();
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
    const baseToastNotifier = createGuardianToastNotifier({
        context,
        directory,
        enabled: mergedConfig.notifications?.enabled !== false,
    });
    const toastNotifier = {
        notify(input) {
            if (mergedConfig.notifications?.enabled !== false &&
                typeof input.sessionID === "string" &&
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
            baseToastNotifier.notify(input);
        },
    };
    if (strictPreflight) {
        // An explicitly requested security hook must never be silently skipped.
        if (typeof context.tool?.hook !== "function") {
            controller.abort();
            throw new Error("[opencode-guardian preflight] V2 tool.execute.before hook is unavailable; strict preflight cannot be enabled.");
        }
        try {
            const registration = await context.tool.hook("execute.before", (event) => {
                const input = event.input && typeof event.input === "object" && !Array.isArray(event.input)
                    ? event.input
                    : {};
                const cmd = input.command ?? input.cmd;
                if (cmd) {
                    assessCommandPreflight(cmd);
                }
                inspectPreflight(event.tool, event.input, event.sessionID, directory, config.preflight?.shellTools, toastNotifier);
            });
            if (!registration || typeof registration.dispose !== "function") {
                throw new Error("V2 tool hook did not return a valid registration.");
            }
            registrations.push(registration);
        }
        catch (error) {
            controller.abort();
            throw new Error("[opencode-guardian preflight] V2 tool hook registration failed; strict preflight cannot be enabled.", { cause: error });
        }
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
        try {
            if (canFinalizeSubagent) {
                const before = await context.tool.hook("execute.before", (event) => {
                    if (controller.signal.aborted)
                        return;
                    const input = event.input && typeof event.input === "object" && !Array.isArray(event.input)
                        ? event.input
                        : {};
                    if (!strictPreflight) {
                        const cmd = input.command ?? input.cmd;
                        if (cmd) {
                            assessCommandPreflight(cmd);
                        }
                    }
                    if (event.tool !== "subagent")
                        return;
                    if (input.background === true)
                        return;
                    markForegroundHandoff(foregroundHandoffs, event.sessionID, event.id);
                });
                if (!before || typeof before.dispose !== "function") {
                    throw new Error("V2 foreground handoff hook has no disposer");
                }
                toolRegistrations.push(before);
            }
            const after = await context.tool.hook("execute.after", async (event) => {
                if (controller.signal.aborted)
                    return;
                if (sanitizerOpts) {
                    if (event.status === "completed") {
                        event.result = sanitizeToolResult(event.result, sanitizerOpts);
                    }
                    else if (event.status === "error") {
                        event.error = sanitizeV2ToolError(event.error, sanitizerOpts);
                    }
                }
                if (typeof context.session.get !== "function")
                    return;
                const input = event.input && typeof event.input === "object" && !Array.isArray(event.input)
                    ? event.input
                    : {};
                const tracked = canFinalizeSubagent &&
                    event.tool === "subagent" &&
                    input.background !== true &&
                    Boolean(foregroundHandoffs.get(event.sessionID)?.has(event.id));
                try {
                    // The plugin load directory is not a reliable session root.
                    let observedDirectory;
                    try {
                        const session = await context.session.get({ sessionID: event.sessionID });
                        if (typeof session.location?.directory !== "string" ||
                            !session.location.directory.trim())
                            return;
                        observedDirectory = session.location.directory;
                    }
                    catch {
                        return;
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
                            : typeof structured?.sessionID === "string"
                                ? structured.sessionID
                                : undefined;
                        const completed = current.metadata?.status === "completed" ||
                            structured?.status === "completed";
                        if (childID && completed) {
                            const child = await context.session.get({ sessionID: childID });
                            if (child.parentID !== event.sessionID) {
                                throw new Error("[opencode-guardian handoff] child session ownership mismatch.");
                            }
                            const childDirectory = typeof child.location?.directory === "string" && child.location.directory.trim()
                                ? child.location.directory
                                : observedDirectory;
                            const childAgent = typeof input.agent === "string" ? input.agent : undefined;
                            const revised = await finalizeSubagentHandoff({
                                sessionID: childID,
                                directory: childDirectory,
                                engine,
                                agentName: childAgent,
                                resolveCapability: async () => {
                                    const cached = getCachedAgentCapability(childID);
                                    if (cached)
                                        return cached;
                                    let resolvedName = childAgent;
                                    if (!resolvedName) {
                                        try {
                                            const ctxMsgs = normalizeV2Messages(await context.session.context({ sessionID: childID }));
                                            resolvedName = extractAgentNameFromMessages(ctxMsgs);
                                        }
                                        catch { }
                                    }
                                    const p = await resolveV2AgentCapability(context, childID, resolvedName);
                                    cacheAgentCapability(childID, p);
                                    return p;
                                },
                                fetchMessages: async () => normalizeV2Messages(await context.session.context({ sessionID: childID })),
                                sendAndWait: async (text) => {
                                    await context.session.synthetic({
                                        sessionID: childID,
                                        text,
                                        description: "OpenCode Guardian remediation",
                                        metadata: { "opencode-guardian": true },
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
            registrations.push(...toolRegistrations);
        }
        catch (error) {
            foregroundHandoffs.clear();
            await Promise.allSettled(toolRegistrations.map((registration) => Promise.resolve().then(() => registration.dispose())));
            recordGuardianEvent({ kind: "verification-unavailable",
                rules: ["verification-snapshot-unavailable"] }, directory);
            if (sanitizerOpts) {
                controller.abort();
                for (const registration of registrations.splice(0).reverse()) {
                    try {
                        await registration.dispose();
                    }
                    catch { }
                }
                throw new Error("[opencode-guardian secrets] V2 execute.after security hook registration failed; POST redaction cannot be enabled safely.", { cause: error });
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
        try {
            const promptRegistration = await context.session.hook("prompt", (event) => {
                if (isGuardianVisibleInterventionMetadata(event.metadata)) {
                    return;
                }
                const text = event.prompt.text;
                if (!text || text.trimStart().startsWith("[opencode-guardian remediation]")) {
                    return;
                }
                const contract = extractTaskContract([{
                        info: { id: event.messageID, role: "user" },
                        parts: [{ type: "text", text }],
                    }]);
                if (contract)
                    contracts.set(event.sessionID, contract);
            });
            if (!promptRegistration || typeof promptRegistration.dispose !== "function") {
                throw new Error("V2 prompt hook did not return a valid registration.");
            }
            taskRegistrations.push(promptRegistration);
            const contextRegistration = await context.session.hook("context", (event) => {
                if (Array.isArray(event.messages)) {
                    event.messages = event.messages.filter((message) => !isGuardianVisibleInterventionMetadata(message.metadata));
                }
                if (sanitizerOpts) {
                    if (Array.isArray(event.messages)) {
                        event.messages = sanitizeMessages(event.messages, sanitizerOpts);
                    }
                    if (Array.isArray(event.system)) {
                        const sanitizedSystem = sanitizeObject(event.system, sanitizerOpts).sanitized;
                        event.system = Array.isArray(sanitizedSystem)
                            ? sanitizedSystem
                            : [{
                                    type: "text",
                                    text: "[OUTPUT REDACTED: sanitization failure]",
                                    metadata: { "opencode-guardian": true },
                                }];
                    }
                }
                const contract = contracts.get(event.sessionID);
                if (!contract)
                    return;
                const guidance = taskGuidance(contract);
                if (guidance && !event.system.some((part) => part.text === guidance)) {
                    event.system.push({ type: "text", text: guidance, metadata: { "opencode-guardian": true } });
                }
            });
            if (!contextRegistration || typeof contextRegistration.dispose !== "function") {
                throw new Error("V2 context hook did not return a valid registration.");
            }
            taskRegistrations.push(contextRegistration);
            registrations.push(...taskRegistrations);
        }
        catch (error) {
            // Never leave a partial task/security hook group installed.
            await Promise.allSettled(taskRegistrations.map((registration) => Promise.resolve().then(() => registration.dispose())));
            contracts.clear();
            recordGuardianEvent({ kind: "inspection-error" }, directory);
            if (sanitizerOpts) {
                controller.abort();
                for (const registration of registrations.splice(0).reverse()) {
                    try {
                        await registration.dispose();
                    }
                    catch { }
                }
                throw new Error("[opencode-guardian secrets] V2 session context security hook registration failed; FINAL context redaction cannot be enabled safely.", { cause: error });
            }
        }
    }
    const eventLoop = async () => {
        let activeEvents = events;
        // A terminated stream must never disable session inspection silently.
        // Retry a bounded number of times and keep strict tool hooks registered.
        for (let attempt = 0; attempt < 3 && !controller.signal.aborted; attempt++) {
            try {
                for await (const event of activeEvents) {
                    const eventData = event;
                    if (eventData.type === "session.deleted") {
                        const deletedSessionID = eventData.data?.sessionID ?? eventData.data?.info?.id;
                        if (deletedSessionID) {
                            engine.forgetSession(deletedSessionID);
                            verificationStore.forget(deletedSessionID);
                            contracts.delete(deletedSessionID);
                            foregroundHandoffs.delete(deletedSessionID);
                            interventionSnapshots.delete(deletedSessionID);
                            clearAgentCapability(deletedSessionID);
                        }
                        continue;
                    }
                    if (eventData.type !== "session.idle")
                        continue;
                    const sessionID = eventData.data?.sessionID;
                    if (!sessionID)
                        continue;
                    let sessionDirectory = directory;
                    let sessionIsSubagent;
                    let sessionParentID;
                    try {
                        if (typeof context.session.get === "function") {
                            const session = await context.session.get({ sessionID });
                            sessionDirectory = session.location?.directory ?? directory;
                            sessionParentID =
                                typeof session.parentID === "string" && session.parentID.length > 0
                                    ? session.parentID
                                    : undefined;
                            sessionIsSubagent = Boolean(sessionParentID);
                        }
                    }
                    catch {
                        // A transient/partial host must not disable the existing idle path.
                    }
                    if (sessionParentID && hasForegroundHandoff(foregroundHandoffs, sessionParentID)) {
                        continue;
                    }
                    await handleSessionIdle(sessionID, sessionDirectory, async () => {
                        const messages = await context.session.context({ sessionID });
                        const normalized = normalizeV2Messages(messages);
                        const contract = extractTaskContract(normalized);
                        if (contract)
                            contracts.set(sessionID, contract);
                        return normalized;
                    }, async (text) => {
                        if (controller.signal.aborted)
                            return;
                        await context.session.synthetic({
                            sessionID,
                            text,
                            description: "OpenCode Guardian remediation",
                            metadata: { "opencode-guardian": true },
                            delivery: "queue",
                            resume: true,
                        });
                    }, engine, verificationStore.snapshots(sessionID), controller.signal, sessionIsSubagent, sessionIsSubagent
                        ? async () => {
                            const cached = getCachedAgentCapability(sessionID);
                            if (cached)
                                return cached;
                            let agentName;
                            try {
                                const msgs = await context.session.context({ sessionID });
                                const normalized = normalizeV2Messages(msgs);
                                agentName = extractAgentNameFromMessages(normalized);
                            }
                            catch { }
                            const p = await resolveV2AgentCapability(context, sessionID, agentName);
                            cacheAgentCapability(sessionID, p);
                            return p;
                        }
                        : undefined, toastNotifier);
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
    recordGuardianEvent({ kind: "runtime-started", runtime: "v2", preflight: strictPreflight ? "active" : "disabled" }, directory);
    void eventLoop();
    return async () => {
        controller.abort();
        contracts.clear();
        verificationStore.clear();
        foregroundHandoffs.clear();
        interventionSnapshots.clear();
        clearAllAgentCapabilities();
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
 * OpenCode Dual-Mode Plugin Definition.
 */
export const OpencodeGuardian = {
    id: "opencode-guardian",
    server,
    setup,
};
export const OpencodeGuard = OpencodeGuardian;
export default OpencodeGuardian;
