import type { Plugin as OpenCodeV1ServerPlugin } from "@opencode-ai/plugin";
import type { Plugin as OpenCodeV2 } from "@opencode/plugin";
import { GuardEngine, loadConfig, resolveEffectiveConfig, type EngineExecutionResult } from "./engine.js";
import type { MessagePart, SessionMessage } from "./types.js";
import { extractTaskContract, taskGuidance } from "./task-contract.js";
import type { TaskContract } from "./task-contract.js";
import { evaluatePreflight, GuardianPreflightError, isShellExecutionTool, isFileMutationTool, isProcessStartTool } from "./preflight.js";
import { recordGuardianEvent, sessionFingerprint } from "./telemetry.js";
import { auditReasons } from "./audit.js";
import { VerificationSnapshotStore, type VerificationSnapshot } from "./evidence.js";
import { announceGuardianUpdate } from "./version-notice.js";
import { createV1TurnWatcher } from "./v1-turn-watcher.js";
import { registerGuardianCapability } from "./handoff.js";
import {
  type AgentMutationProfile,
  resolveV1AgentCapability,
  resolveV2AgentCapability,
  getCachedAgentCapability,
  cacheAgentCapability,
  cacheV2SessionPermissions,
  clearAgentCapability,
  clearAllAgentCapabilities,
  extractAgentNameFromMessages,
  type V2PermissionRule,
} from "./agent-capability.js";
import {
  resolveSanitizerOptions,
  sanitizeMessages,
  sanitizeObject,
  sanitizeString,
  sanitizeToolResult,
} from "./secrets/index.js";
import {
  createGuardianToastNotifier,
  formatGuardianToast,
  type GuardianToastNotifier,
  type GuardianToastPayload,
} from "./toast.js";
import {
  formatGuardianTranscriptMessage,
  GUARDIAN_VISIBLE_INTERVENTION_KEY,
} from "./intervention.js";
import {
  createGuardianMessageMetadata,
  forgetGuardianProvenance,
  isTrustedGuardianMetadata,
} from "./provenance.js";
import {
  GUARDIAN_INTERVENTION_RPC_DEFINITION,
  GUARDIAN_INTERVENTION_RPC_METHOD,
  activeGuardianIntervention,
  inactiveGuardianIntervention,
  readGuardianInterventionSessionID,
} from "./intervention-rpc.js";

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
export * from "./provenance.js";

function sanitizeV2ToolError<T>(
  error: T,
  options: NonNullable<ReturnType<typeof resolveSanitizerOptions>>
): T {
  const fallback = (): T => {
    const safe = new Error("[OUTPUT REDACTED: sanitization failure]");
    if (error && typeof error === "object") {
      try { Object.setPrototypeOf(safe, Object.getPrototypeOf(error)); } catch {}
    }
    return safe as unknown as T;
  };

  try {
    if (!error || typeof error !== "object") {
      return sanitizeToolResult(error, options);
    }
    const source = error as Record<string, unknown> & {
      message?: unknown;
      stack?: unknown;
      name?: unknown;
    };
    const snapshot: Record<string, unknown> = { ...source };
    if (typeof source.message === "string") snapshot.message = source.message;
    if (typeof source.stack === "string") snapshot.stack = source.stack;
    if (typeof source.name === "string") snapshot.name = source.name;

    const sanitized = sanitizeObject(snapshot, options).sanitized;
    if (!sanitized || typeof sanitized !== "object" || Array.isArray(sanitized)) {
      return fallback();
    }

    return Object.assign(
      Object.create(Object.getPrototypeOf(error)),
      sanitized
    ) as T;
  } catch {
    return fallback();
  }
}

function stringifyV2ToolContent(content: unknown): string {
  if (!Array.isArray(content)) return "";
  return content
    .map((item) => {
      if (
        item &&
        typeof item === "object" &&
        "type" in item &&
        (item as { type?: unknown }).type === "text" &&
        "text" in item &&
        typeof (item as { text?: unknown }).text === "string"
      ) {
        return (item as { text: string }).text;
      }
      try {
        return JSON.stringify(item);
      } catch {
        return String(item);
      }
    })
    .filter(Boolean)
    .join("\n");
}

function normalizeV2AssistantPart(part: unknown): MessagePart | null {
  if (!part || typeof part !== "object") return null;
  const value = part as Record<string, unknown>;

  if (value.type === "text" && typeof value.text === "string") {
    return { type: "text", text: value.text };
  }

  if (value.type !== "tool" || !value.state || typeof value.state !== "object") {
    return null;
  }

  const state = value.state as Record<string, unknown>;
  const normalizedState: NonNullable<MessagePart["state"]> = {};
  if (typeof state.status === "string") normalizedState.status = state.status;
  if (state.input && typeof state.input === "object") {
    normalizedState.input = state.input as Record<string, unknown>;
  }
  if (state.error !== undefined) normalizedState.error = state.error;
  if (state.metadata && typeof state.metadata === "object") {
    normalizedState.metadata = state.metadata as Record<string, unknown>;
  }
  if (state.exitCode !== undefined) normalizedState.exitCode = state.exitCode;
  if (state.raw !== undefined) normalizedState.raw = state.raw;

  const output =
    typeof state.output === "string"
      ? state.output
      : stringifyV2ToolContent(state.content);
  if (output) normalizedState.output = output;

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
export function normalizeV2Messages(
  messages: readonly unknown[],
  sessionID?: string
): SessionMessage[] {
  const normalized: SessionMessage[] = [];

  for (const raw of messages) {
    if (!raw || typeof raw !== "object") continue;
    const msg = raw as Record<string, unknown>;
    const id = typeof msg.id === "string" ? msg.id : undefined;
    const type = typeof msg.type === "string" ? msg.type : undefined;
    if (!id || !type) continue;
    if (isTrustedGuardianMetadata(sessionID, msg.metadata, "visible")) continue;

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
        .filter((part): part is MessagePart => part !== null);

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

function markForegroundHandoff(
  handoffs: Map<string, Set<string>>,
  sessionID: string,
  callID: string
): void {
  const active = handoffs.get(sessionID) ?? new Set<string>();
  active.add(callID);
  handoffs.set(sessionID, active);
}

function clearForegroundHandoff(
  handoffs: Map<string, Set<string>>,
  sessionID: string,
  callID: string
): void {
  const active = handoffs.get(sessionID);
  if (!active) return;
  active.delete(callID);
  if (active.size === 0) handoffs.delete(sessionID);
}

function hasForegroundHandoff(
  handoffs: ReadonlyMap<string, ReadonlySet<string>>,
  sessionID?: string
): boolean {
  return Boolean(sessionID && handoffs.get(sessionID)?.size);
}

function renderV1TaskResult(sessionID: string, text: string): string {
  return [
    `<task id="${sessionID}" state="completed">`,
    "<task_result>",
    text,
    "</task_result>",
    "</task>",
  ].join("\n");
}

function latestAssistantText(messages: readonly SessionMessage[]): string | undefined {
  const assistant = messages.findLast((message) => message.info.role === "assistant");
  if (!assistant) return undefined;
  const text = (assistant.parts ?? [])
    .filter((part) => part.type === "text" && typeof part.text === "string")
    .map((part) => part.text ?? "")
    .join("\n")
    .trim();
  return text || undefined;
}

function recordInspectionOutcome(
  result: EngineExecutionResult,
  sessionID: string,
  directory: string,
  toastNotifier?: GuardianToastNotifier
) {
  const findings = result.results.filter((item) => item.findings.length > 0);

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
  } else if (result.remediationStatus === "unverified") {
    recordGuardianEvent({
      kind: "remediation-unverified",
      session: sessionFingerprint(sessionID),
      rules: result.pendingRemediationRules ?? [],
    }, directory);
  } else if (result.remediationStatus === "failed") {
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

async function finalizeSubagentHandoff(input: {
  sessionID: string;
  directory: string;
  engine: GuardEngine;
  fetchMessages: () => Promise<SessionMessage[]>;
  sendAndWait: (promptText: string) => Promise<void>;
  snapshots?: (() => ReadonlyMap<string, VerificationSnapshot> | undefined) | undefined;
  signal?: AbortSignal | undefined;
  agentName?: string | undefined;
  resolveCapability?: (() => Promise<AgentMutationProfile>) | undefined;
  toastNotifier?: GuardianToastNotifier | undefined;
}): Promise<string | undefined> {
  let remediated = false;
  let resolvedCapability: AgentMutationProfile | undefined;
  if (input.resolveCapability) {
    try {
      resolvedCapability = await input.resolveCapability();
    } catch {
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

    let messages: SessionMessage[];
    try {
      messages = await input.fetchMessages();
    } catch {
      recordGuardianEvent({
        kind: "inspection-error",
        session: sessionFingerprint(input.sessionID),
        rules: ["message-fetch-failed"],
        reasons: [{ rule: "message-fetch-failed", code: "message-fetch-failed" }],
      }, input.directory);
      throw new Error("[opencode-guardian handoff] could not read the subagent result.");
    }

    let result: EngineExecutionResult;
    try {
      result = await input.engine.inspect(
        input.sessionID,
        input.directory,
        messages,
        input.snapshots?.(),
        { isSubagent: true, agentCapability }
      );
    } catch {
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
      } catch {
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
async function handleSessionIdle(
  sessionID: string,
  directory: string,
  fetchMessages: () => Promise<SessionMessage[]>,
  sendPrompt: (promptText: string, ruleIds: readonly string[]) => Promise<void>,
  engine: GuardEngine,
  snapshots?: ReadonlyMap<string, VerificationSnapshot> | undefined,
  signal?: AbortSignal | undefined,
  isSubagent?: boolean | undefined,
  resolveCapability?: (() => Promise<AgentMutationProfile>) | undefined,
  toastNotifier?: GuardianToastNotifier | undefined
): Promise<void> {
  let stage: "message-fetch" | "engine-inspect" | "prompt-send" = "message-fetch";
  try {
    if (signal?.aborted) return;
    const messages = await fetchMessages();
    if (signal?.aborted) return;
    stage = "engine-inspect";
    // Unknown topology is not permission to treat a session as root. Fail safe
    // as a non-self-remediating child until the host proves parent/root state.
    const effectiveIsSubagent = isSubagent ?? true;
    let resolvedCapability: AgentMutationProfile | undefined;
    if (effectiveIsSubagent && resolveCapability) {
      try {
        resolvedCapability = await resolveCapability();
      } catch {
        resolvedCapability = {
          capability: "unknown",
          evidence: { reasons: ["capability resolution failed"] },
        };
      }
    }
    const agentCapability = resolvedCapability?.capability ?? (effectiveIsSubagent ? "unknown" : undefined);
    const result = await engine.inspect(
      sessionID,
      directory,
      messages,
      snapshots,
      { isSubagent: effectiveIsSubagent, ...(agentCapability ? { agentCapability } : {}) }
    );
    if (signal?.aborted) { result.rollback?.(); return; }
    const findings = recordInspectionOutcome(result, sessionID, directory, toastNotifier);

    if (result.decision === "block" && result.combinedRemediationPrompt) {
      if (effectiveIsSubagent && agentCapability !== "write-allowed") {
        return;
      }
      stage = "prompt-send";
      try {
        if (signal?.aborted) { result.rollback?.(); return; }
        await sendPrompt(
          result.combinedRemediationPrompt,
          findings.map((item) => item.ruleId)
        );
        if (signal?.aborted) return;
        recordGuardianEvent({ kind: "post-remediation", session: sessionFingerprint(sessionID), rules: findings.map((item) => item.ruleId), reasons: auditReasons(findings) }, directory);
        toastNotifier?.notify({
          kind: "remediation",
          ruleIds: findings.map((item) => item.ruleId),
          sessionID,
        });
      } catch (promptError) {
        result.rollback?.();
        throw promptError;
      }
    }
  } catch {
    if (signal?.aborted) return;
    const errorCode =
      stage === "message-fetch"
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
function inspectPreflight(
  tool: string, args: unknown, sessionID?: string, directory?: string,
  additionalTools: readonly string[] = [],
  toastNotifier?: GuardianToastNotifier
): void {
  if (!isShellExecutionTool(tool, additionalTools) && !isFileMutationTool(tool) && !isProcessStartTool(tool)) return;
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

const server: OpenCodeV1ServerPlugin = async ({ client, directory }, pluginOptions) => {
  const mergedConfig = resolveEffectiveConfig(loadConfig(directory), pluginOptions);
  if (mergedConfig.enabled === false) {
    recordGuardianEvent({ kind: "runtime-started", runtime: "v1", preflight: "disabled" }, directory);
    // Preserve the V1 hook shape without inspecting turns or injecting context.
    return {
      "chat.message": async () => {},
      "experimental.chat.system.transform": async () => {},
      event: async () => {},
    };
  }
  const unregisterGuardianCapability = registerGuardianCapability();
  const sanitizerOpts = resolveSanitizerOptions(mergedConfig);
  const toastNotifier = createGuardianToastNotifier({
    client,
    directory,
    enabled: mergedConfig.notifications?.enabled !== false,
  });
  const engine = new GuardEngine(mergedConfig);
  const verificationStore = new VerificationSnapshotStore();
  const contracts = new Map<string, TaskContract>();
  let promptSequence = 0;
  let updateChecked = false;
  const updateNoticeController = new AbortController();
  const strictPreflight = mergedConfig.preflight?.enabled === true;
  const foregroundHandoffs = new Map<string, Set<string>>();
  const provenanceSessions = new Set<string>();
  const v1GuardianMetadata = (
    sessionID: string,
    kind: "remediation" | "visible",
    base: Record<string, unknown> = {}
  ) => {
    provenanceSessions.add(sessionID);
    return createGuardianMessageMetadata(sessionID, kind, base);
  };

  const sendV1Remediation = async (
    sessionID: string,
    text: string,
    ruleIds: readonly string[]
  ): Promise<void> => {
    const remediationText = sanitizerOpts
      ? sanitizeString(text, sanitizerOpts).sanitized
      : text;
    const response = await client.session.promptAsync({
      path: { id: sessionID },
      query: { directory },
      body: {
        parts: [{
          type: "text",
          text: remediationText,
          synthetic: true,
          metadata: v1GuardianMetadata(sessionID, "remediation"),
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
            metadata: v1GuardianMetadata(sessionID, "visible", {
              [GUARDIAN_VISIBLE_INTERVENTION_KEY]: true,
            }),
          }],
        },
      });
      if (visible.error) {
        return;
      }
    } catch {
      // Transcript visibility is secondary to the already-delivered
      // remediation. Native toast remains the fallback UI channel.
    }
  };

  const hostSessionRelation = async (sessionID: string): Promise<{
    known: boolean;
    parentID?: string;
  }> => {
    const getSession = (client.session as typeof client.session & {
      get?: (input: { path: { id: string }; query?: { directory?: string } }) =>
        Promise<{ data?: { parentID?: string }; error?: unknown }>;
    }).get;
    if (typeof getSession !== "function") return { known: false };
    try {
      const response = await getSession.call(client.session, {
        path: { id: sessionID },
        query: { directory },
      });
      if (response.error || !response.data) return { known: false };
      const parentID =
        typeof response.data.parentID === "string" && response.data.parentID.length > 0
          ? response.data.parentID
          : undefined;
      return { known: true, ...(parentID ? { parentID } : {}) };
    } catch {
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
        return response.data as SessionMessage[];
      },
      onIdle: async (sessionID, messages) => {
        const relation = await hostSessionRelation(sessionID);
        if (relation.parentID && hasForegroundHandoff(foregroundHandoffs, relation.parentID)) {
          return;
        }
        const contract = extractTaskContract(messages);
        if (contract) contracts.set(sessionID, contract);
        await handleSessionIdle(
          sessionID, directory, async () => messages,
          async (text, ruleIds) => sendV1Remediation(sessionID, text, ruleIds),
          engine,
          verificationStore.snapshots(sessionID),
          undefined,
          relation.known ? Boolean(relation.parentID) : undefined,
          relation.known && relation.parentID
            ? async () => {
                const cached = getCachedAgentCapability(sessionID);
                if (cached) return cached;
                const agentName = extractAgentNameFromMessages(messages);
                const p = await resolveV1AgentCapability(client, directory, agentName);
                cacheAgentCapability(sessionID, p);
                return p;
              }
            : undefined,
          toastNotifier
        );
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
      updateNoticeController.abort();
      watcher?.stopAll();
      verificationStore.clear();
      contracts.clear();
      foregroundHandoffs.clear();
      clearAllAgentCapabilities();
      for (const sessionID of provenanceSessions) {
        forgetGuardianProvenance(sessionID);
      }
      provenanceSessions.clear();
      unregisterGuardianCapability();
    },
    "tool.execute.before": async (input, output) => {
      const args =
        output.args && typeof output.args === "object" && !Array.isArray(output.args)
          ? output.args as Record<string, unknown>
          : {};
      if (
        input.tool === "task" &&
        typeof input.sessionID === "string" &&
        typeof input.callID === "string" &&
        args.background !== true
      ) {
        markForegroundHandoff(foregroundHandoffs, input.sessionID, input.callID);
      }
      if (strictPreflight) {
        inspectPreflight(
          input.tool,
          output.args,
          input.sessionID,
          directory,
          mergedConfig.preflight?.shellTools,
          toastNotifier
        );
      }
    },
    "tool.execute.after": async (input, output) => {
      const args =
        input.args && typeof input.args === "object" && !Array.isArray(input.args)
          ? input.args as Record<string, unknown>
          : {};
      const tracked =
        input.tool === "task" &&
        typeof input.sessionID === "string" &&
        typeof input.callID === "string" &&
        args.background !== true &&
        Boolean(foregroundHandoffs.get(input.sessionID)?.has(input.callID));

      try {
        if (
          tracked &&
          output.metadata &&
          typeof output.metadata === "object" &&
          !Array.isArray(output.metadata)
        ) {
          const metadata = output.metadata as Record<string, unknown>;
          const childID =
            typeof metadata.sessionId === "string" ? metadata.sessionId : undefined;
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
                  if (cached) return cached;
                  let resolvedName = childAgent;
                  if (!resolvedName) {
                    try {
                      const res = await client.session.messages({
                        path: { id: childID },
                        query: { directory },
                      });
                      if (Array.isArray(res?.data)) {
                        resolvedName = extractAgentNameFromMessages(res.data as SessionMessage[]);
                      }
                    } catch {}
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
                  return response.data as SessionMessage[];
                },
                sendAndWait: async (text) => {
                  const remediationText = sanitizerOpts
                    ? sanitizeString(text, sanitizerOpts).sanitized
                    : text;
                  const response = await client.session.prompt({
                    path: { id: childID },
                    query: { directory },
                    body: {
                      parts: [{
                        type: "text",
                        text: remediationText,
                        synthetic: true,
                        metadata: v1GuardianMetadata(childID, "remediation"),
                      }],
                    },
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
          } else if (output.output && typeof output.output === "object") {
            output.output = sanitizeToolResult(output.output, sanitizerOpts);
          }
          if (output.metadata && typeof output.metadata === "object") {
            const sanitizedMeta = sanitizeObject(output.metadata, sanitizerOpts);
            output.metadata = sanitizedMeta.sanitized as Record<string, unknown>;
          }
        }

        verificationStore.observe(input.sessionID, input.callID, input.tool,
          args,
          output.output,
          output.metadata && typeof output.metadata === "object"
            ? output.metadata as Record<string, unknown>
            : {},
          directory);
      } finally {
        if (tracked) {
          clearForegroundHandoff(foregroundHandoffs, input.sessionID, input.callID);
        }
      }
    },
    "chat.message": async (input, output) => {
      const visibleIntervention = output.parts.some(
        (part) => part.type === "text" &&
          isTrustedGuardianMetadata(input.sessionID, part.metadata, "visible")
      );
      if (visibleIntervention) return;

      const guardianRemediation = output.parts.some(
        (part) => part.type === "text" &&
          part.synthetic === true &&
          isTrustedGuardianMetadata(input.sessionID, part.metadata, "remediation")
      );
      const text = output.parts
        .map((part) => part.type === "text" ? part.text : "")
        .join("\n");
      if (!text) return;
      if (!guardianRemediation) {
        verificationStore.beginTurn(input.sessionID);
        const contract = extractTaskContract([{
          info: { id: input.messageID ?? ("v1-prompt-" + (++promptSequence)), role: "user" },
          parts: [{ type: "text", text }],
        }]);
        if (contract) contracts.set(input.sessionID, contract);
      }
      watcher?.watch(input.sessionID);
    },
    "experimental.chat.system.transform": async (input, output) => {
      if (sanitizerOpts && Array.isArray(output.system)) {
        output.system = output.system.map(
          (part) => sanitizeString(part, sanitizerOpts).sanitized
        );
      }
      if (!input.sessionID) return;
      const contract = contracts.get(input.sessionID);
      if (!contract) return;
      const guidance = taskGuidance(contract);
      if (guidance && !output.system.includes(guidance)) {
        output.system.push(guidance);
      }
    },
    "experimental.chat.messages.transform": async (_input, output) => {
      if (!output || !Array.isArray(output.messages)) return;

      // Display-only transcript rows are host UI state, not model context.
      // Strip every ignored part at the FINAL gate regardless of whether
      // secret redaction is enabled.
      output.messages = output.messages
        .map((message) => ({
          ...message,
          parts: Array.isArray(message.parts)
            ? message.parts.filter(
                (part) => !("ignored" in part) || part.ignored !== true
              )
            : message.parts,
        }))
        .filter((message) => !Array.isArray(message.parts) || message.parts.length > 0);

      if (sanitizerOpts) {
        output.messages = sanitizeMessages(
          output.messages,
          sanitizerOpts
        ) as unknown as typeof output.messages;
      }
    },
    event: async ({ event }) => {
      const eventData = event as {
        type?: string;
        properties?: { sessionID?: string };
        data?: { sessionID?: string; info?: { id?: string } };
      };

      if (eventData.type === "session.created" && !updateChecked && mergedConfig.updateNotice?.enabled !== false) {
        updateChecked = true;
        const tui = (client as unknown as { tui?: { showToast?: (input: { body: { title: string; message: string; variant: "info"; duration: number } }) => Promise<unknown> } }).tui;
        if (typeof tui?.showToast === "function") {
          const showToast = tui.showToast;
          void announceGuardianUpdate((current, latest) => showToast({
            body: { title: "OpenCode Guardian — New version", message: `v${current} → v${latest} (update manually)`, variant: "info", duration: 5000 },
          }), { signal: updateNoticeController.signal });
        }
      }

      if (eventData.type === "session.deleted") {
        const deletedSessionID =
          eventData.properties?.sessionID ??
          eventData.data?.sessionID ??
          eventData.data?.info?.id;
        if (deletedSessionID) {
          watcher?.stop(deletedSessionID);
          engine.forgetSession(deletedSessionID);
          verificationStore.forget(deletedSessionID);
          contracts.delete(deletedSessionID);
          foregroundHandoffs.delete(deletedSessionID);
          clearAgentCapability(deletedSessionID);
          forgetGuardianProvenance(deletedSessionID);
          provenanceSessions.delete(deletedSessionID);
        }
        return;
      }

      if (eventData.type !== "session.idle") return;
      const sessionID =
        eventData.properties?.sessionID ?? eventData.data?.sessionID;
      if (!sessionID) return;
      watcher?.stop(sessionID);
      const relation = await hostSessionRelation(sessionID);
      if (relation.parentID && hasForegroundHandoff(foregroundHandoffs, relation.parentID)) {
        return;
      }

      const isSubagent = relation.known ? Boolean(relation.parentID) : undefined;
      await handleSessionIdle(
        sessionID,
        directory,
        async () => {
          const res = await client.session.messages({
            path: { id: sessionID },
            query: { directory },
          });
          if (res?.error || !Array.isArray(res?.data)) {
            throw new Error("V1 session.messages() failed during idle inspection.");
          }
          const messages = res.data as SessionMessage[];
          const contract = extractTaskContract(messages);
          if (contract) contracts.set(sessionID, contract);
          return messages;
        },
        async (text, ruleIds) => sendV1Remediation(sessionID, text, ruleIds),
        engine,
        verificationStore.snapshots(sessionID),
        undefined,
        isSubagent,
        isSubagent
          ? async () => {
              const cached = getCachedAgentCapability(sessionID);
              if (cached) return cached;
              const res = await client.session.messages({
                path: { id: sessionID },
                query: { directory },
              });
              const msgs = Array.isArray(res?.data) ? (res.data as SessionMessage[]) : [];
              const agentName = extractAgentNameFromMessages(msgs);
              const p = await resolveV1AgentCapability(client, directory, agentName);
              cacheAgentCapability(sessionID, p);
              return p;
            }
          : undefined,
        toastNotifier
      );
    },
  };
};

const setup: OpenCodeV2.Plugin["setup"] = async (
  context: OpenCodeV2.Context
) => {
  // Transition builds may call setup() with a partial v2 context.
  // Resolve the explicit security setting first: strict preflight must never
  // silently disappear merely because another v2 capability is unavailable.
  const directory = context?.location?.directory ?? process.cwd();
  const mergedConfig = resolveEffectiveConfig(loadConfig(directory), context.options);
  if (mergedConfig.enabled === false) {
    recordGuardianEvent({ kind: "runtime-started", runtime: "v2", preflight: "disabled" }, directory);
    return;
  }
  const sanitizerOpts = resolveSanitizerOptions(mergedConfig);
  const strictPreflight = mergedConfig.preflight?.enabled === true;
  if (!context || typeof context !== "object") {
    if (strictPreflight) {
      throw new Error("[opencode-guardian preflight] V2 host context is unavailable; strict preflight cannot be enabled.");
    }
    if (sanitizerOpts) {
      throw new Error("[opencode-guardian secrets] V2 host context is unavailable; secret protection cannot be enabled safely.");
    }
    return;
  }

  const controller = new AbortController();
  const provenanceSessions = new Set<string>();
  const v2GuardianMetadata = (
    sessionID: string,
    kind: "remediation" | "visible",
    base: Record<string, unknown> = {}
  ) => {
    provenanceSessions.add(sessionID);
    return createGuardianMessageMetadata(sessionID, kind, base);
  };
  let events: AsyncIterable<unknown> | undefined;
  const canRunPostTurnInspection =
    typeof context.event?.subscribe === "function" &&
    typeof context.session?.context === "function" &&
    typeof context.session?.synthetic === "function";

  if (canRunPostTurnInspection) {
    try {
      const candidate = context.event.subscribe({
        signal: controller.signal,
      });
      if (
        candidate &&
        typeof (candidate as AsyncIterable<unknown>)[Symbol.asyncIterator] ===
          "function"
      ) {
        events = candidate as AsyncIterable<unknown>;
      }
    } catch {
      // Post-turn inspection is optional relative to independent PRE/POST/FINAL
      // security hooks. Its failure is recorded below without disabling them.
    }
  }

  const runtimeByDirectory = new Map<string, {
    config: typeof mergedConfig;
    sanitizer: ReturnType<typeof resolveSanitizerOptions>;
    engine: GuardEngine;
  }>();
  const runtimeForDirectory = (runtimeDirectory: string) => {
    const key = runtimeDirectory || directory;
    const cached = runtimeByDirectory.get(key);
    if (cached) return cached;

    const config = resolveEffectiveConfig(loadConfig(key), context.options);
    const runtime = {
      config,
      sanitizer: resolveSanitizerOptions(config),
      engine: new GuardEngine(config),
    };
    runtimeByDirectory.set(key, runtime);
    return runtime;
  };
  runtimeByDirectory.set(directory, {
    config: mergedConfig,
    sanitizer: sanitizerOpts,
    engine: new GuardEngine(mergedConfig),
  });

  const sessionDirectories = new Map<string, string>();
  const rememberSessionDirectory = (sessionID: string, value: unknown): string => {
    const resolved =
      typeof value === "string" && value.trim().length > 0
        ? value
        : sessionDirectories.get(sessionID) ?? directory;
    sessionDirectories.set(sessionID, resolved);
    return resolved;
  };
  const resolveSessionDirectory = async (sessionID: string): Promise<string> => {
    const cached = sessionDirectories.get(sessionID);
    if (cached) return cached;
    try {
      if (typeof context.session.get === "function") {
        const session = await context.session.get({ sessionID });
        return rememberSessionDirectory(sessionID, session.location?.directory);
      }
    } catch {}
    return rememberSessionDirectory(sessionID, directory);
  };
  const forgetSessionRuntime = (sessionID: string): void => {
    for (const runtime of runtimeByDirectory.values()) {
      runtime.engine.forgetSession(sessionID);
    }
    sessionDirectories.delete(sessionID);
  };

  const verificationStore = new VerificationSnapshotStore();
  const contracts = new Map<string, TaskContract>();
  const foregroundHandoffs = new Map<string, Set<string>>();
  const registrations: Array<{ dispose(): Promise<void> | void }> = [];
  const interventionSnapshots = new Map<string, GuardianToastPayload>();
  const toastNotifiersByDirectory = new Map<string, GuardianToastNotifier>();

  if (typeof context.rpc?.register === "function") {
    try {
      const rpcRegistration = await context.rpc.register(
        GUARDIAN_INTERVENTION_RPC_DEFINITION,
        {
          [GUARDIAN_INTERVENTION_RPC_METHOD]: async (input) => {
            const sessionID = readGuardianInterventionSessionID(input);
            if (!sessionID) return inactiveGuardianIntervention();
            const payload = interventionSnapshots.get(sessionID);
            return payload
              ? activeGuardianIntervention(payload)
              : inactiveGuardianIntervention();
          },
        }
      );
      if (rpcRegistration && typeof rpcRegistration.dispose === "function") {
        registrations.push(rpcRegistration);
      }
    } catch {
      // Visibility bridge is additive; core policy/security must keep running
      // even when this host build does not expose plugin RPC.
    }
  }

  const baseToastForDirectory = (runtimeDirectory: string): GuardianToastNotifier => {
    const key = runtimeDirectory || directory;
    const cached = toastNotifiersByDirectory.get(key);
    if (cached) return cached;
    const runtime = runtimeForDirectory(key);
    const notifier = createGuardianToastNotifier({
      context,
      directory: key,
      enabled:
        runtime.config.enabled !== false &&
        runtime.config.notifications?.enabled !== false,
    });
    toastNotifiersByDirectory.set(key, notifier);
    return notifier;
  };
  const toastNotifier: GuardianToastNotifier = {
    notify(input): void {
      if (
        typeof input.sessionID === "string" &&
        input.sessionID.length > 0
      ) {
        try {
          interventionSnapshots.set(input.sessionID, formatGuardianToast(input));
          while (interventionSnapshots.size > 64) {
            const oldest = interventionSnapshots.keys().next().value;
            if (typeof oldest !== "string") break;
            interventionSnapshots.delete(oldest);
          }
        } catch {}
      }
      const runtimeDirectory =
        typeof input.sessionID === "string"
          ? sessionDirectories.get(input.sessionID) ?? directory
          : directory;
      baseToastForDirectory(runtimeDirectory).notify(input);
    },
    clear(sessionID): void {
      interventionSnapshots.delete(sessionID);
      const runtimeDirectory = sessionDirectories.get(sessionID) ?? directory;
      baseToastForDirectory(runtimeDirectory).clear?.(sessionID);
    },
  };

  if (typeof context.tool?.hook === "function") {
    try {
      const registration = await context.tool.hook("execute.before", async (event) => {
        const runtimeDirectory = await resolveSessionDirectory(event.sessionID);
        const runtime = runtimeForDirectory(runtimeDirectory);
        if (
          runtime.config.enabled === false ||
          runtime.config.preflight?.enabled !== true
        ) {
          return;
        }

        inspectPreflight(
          event.tool,
          event.input,
          event.sessionID,
          runtimeDirectory,
          runtime.config.preflight?.shellTools,
          toastNotifier
        );
      });
      if (!registration || typeof registration.dispose !== "function") {
        throw new Error("V2 tool hook did not return a valid registration.");
      }
      registrations.push(registration);
    } catch {
      if (strictPreflight) {
        controller.abort();
        for (const registration of registrations.splice(0).reverse()) {
          try { await registration.dispose(); } catch {}
        }
        throw new Error("[opencode-guardian preflight] V2 tool hook registration failed; strict preflight cannot be enabled.");
      }
    }
  } else if (strictPreflight) {
    controller.abort();
    for (const registration of registrations.splice(0).reverse()) {
      try { await registration.dispose(); } catch {}
    }
    throw new Error("[opencode-guardian preflight] V2 tool.execute.before hook is unavailable; strict preflight cannot be enabled.");
  }

  // Verification and foreground subagent finalization share one atomic
  // registration group. If either hook cannot be installed, dispose the other
  // immediately so a stale foreground marker can never suppress idle handling.
  if (sanitizerOpts && typeof context.tool?.hook !== "function") {
    controller.abort();
    for (const registration of registrations.splice(0).reverse()) {
      try { await registration.dispose(); } catch {}
    }
    throw new Error("[opencode-guardian secrets] V2 execute.after hook is unavailable; POST redaction cannot be enabled safely.");
  }
  if (typeof context.tool?.hook === "function") {
    const toolRegistrations: Array<{ dispose(): Promise<void> | void }> = [];
    const canFinalizeSubagent =
      typeof context.session.get === "function" &&
      typeof context.session.context === "function" &&
      typeof context.session.synthetic === "function" &&
      typeof context.session.wait === "function";
    try {
      if (canFinalizeSubagent) {
        const before = await context.tool.hook("execute.before", async (event) => {
          if (controller.signal.aborted) return;
          const runtimeDirectory = await resolveSessionDirectory(event.sessionID);
          const runtime = runtimeForDirectory(runtimeDirectory);
          if (runtime.config.enabled === false) return;

          const input =
            event.input && typeof event.input === "object" && !Array.isArray(event.input)
              ? event.input as Record<string, unknown>
              : {};
          if (event.tool !== "subagent") return;
          if (input.background === true) return;
          markForegroundHandoff(foregroundHandoffs, event.sessionID, event.id);
        });
        if (!before || typeof before.dispose !== "function") {
          throw new Error("V2 foreground handoff hook has no disposer");
        }
        toolRegistrations.push(before);
      }

      const after = await context.tool.hook("execute.after", async (event) => {
        if (controller.signal.aborted) return;

        const input =
          event.input && typeof event.input === "object" && !Array.isArray(event.input)
            ? event.input as Record<string, unknown>
            : {};
        const tracked =
          canFinalizeSubagent &&
          event.tool === "subagent" &&
          input.background !== true &&
          Boolean(foregroundHandoffs.get(event.sessionID)?.has(event.id));

        try {
          const observedDirectory = await resolveSessionDirectory(event.sessionID);
          const runtime = runtimeForDirectory(observedDirectory);
          if (runtime.config.enabled === false) return;

          if (runtime.sanitizer && event.status === "error") {
            event.error = sanitizeV2ToolError(event.error, runtime.sanitizer);
          }

          if (controller.signal.aborted) return;

          if (tracked && event.status === "completed") {
            const current = event.result as {
              output?: unknown;
              content?: unknown;
              metadata?: Record<string, unknown>;
            };
            const structured =
              current.output && typeof current.output === "object" && !Array.isArray(current.output)
                ? current.output as Record<string, unknown>
                : undefined;
            const childID =
              typeof current.metadata?.sessionID === "string"
                ? current.metadata.sessionID
                : typeof structured?.sessionID === "string"
                  ? structured.sessionID
                  : undefined;
            const completed =
              current.metadata?.status === "completed" ||
              structured?.status === "completed";

            if (childID && completed) {
              const child = await context.session.get({ sessionID: childID });
              if (child.parentID !== event.sessionID) {
                throw new Error("[opencode-guardian handoff] child session ownership mismatch.");
              }
              const childDirectory = rememberSessionDirectory(
                childID,
                typeof child.location?.directory === "string" && child.location.directory.trim()
                  ? child.location.directory
                  : observedDirectory
              );
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
                  if (cached) return cached;
                  let resolvedName = childAgent;
                  if (!resolvedName) {
                    try {
                      const ctxMsgs = normalizeV2Messages(
                        await context.session.context({ sessionID: childID }),
                        childID
                      );
                      resolvedName = extractAgentNameFromMessages(ctxMsgs);
                    } catch {}
                  }
                  const p = await resolveV2AgentCapability(
                    context,
                    childID,
                    resolvedName,
                    undefined,
                    childDirectory
                  );
                  cacheAgentCapability(childID, p);
                  return p;
                },
                fetchMessages: async () =>
                  normalizeV2Messages(
                    await context.session.context({ sessionID: childID }),
                    childID
                  ),
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

          const result = event.status === "completed" ? event.result as {
            output?: unknown; content?: unknown; metadata?: Record<string, unknown>;
          } : undefined;
          verificationStore.observe(event.sessionID, event.id, event.tool,
            input,
            result?.output ?? result?.content ?? "", result?.metadata ?? {}, observedDirectory,
            event.status);
        } finally {
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
    } catch {
      foregroundHandoffs.clear();
      await Promise.allSettled(toolRegistrations.map((registration) =>
        Promise.resolve().then(() => registration.dispose())
      ));
      recordGuardianEvent({ kind: "verification-unavailable",
        rules: ["verification-snapshot-unavailable"] }, directory);
      if (sanitizerOpts) {
        controller.abort();
        for (const registration of registrations.splice(0).reverse()) {
          try { await registration.dispose(); } catch {}
        }
        throw new Error("[opencode-guardian secrets] V2 execute.after security hook registration failed; POST redaction cannot be enabled safely.");
      }
    }
  }

  if (sanitizerOpts && typeof context.session.hook !== "function") {
    controller.abort();
    for (const registration of registrations.splice(0).reverse()) {
      try { await registration.dispose(); } catch {}
    }
    throw new Error("[opencode-guardian secrets] V2 session.context hook is unavailable; FINAL context redaction cannot be enabled safely.");
  }

  if (typeof context.session.hook === "function") {
    const taskRegistrations: Array<{ dispose(): Promise<void> | void }> = [];
    try {
      const promptRegistration = await context.session.hook("prompt", async (event) => {
        if (
          isTrustedGuardianMetadata(event.sessionID, event.metadata, "visible") ||
          isTrustedGuardianMetadata(event.sessionID, event.metadata, "remediation")
        ) {
          return;
        }
        const runtimeDirectory = await resolveSessionDirectory(event.sessionID);
        const runtime = runtimeForDirectory(runtimeDirectory);
        if (runtime.config.enabled === false) {
          contracts.delete(event.sessionID);
          return;
        }

        const text = event.prompt.text;
        if (!text) return;
        verificationStore.beginTurn(event.sessionID);
        const contract = extractTaskContract([{
          info: { id: event.messageID, role: "user" },
          parts: [{ type: "text", text }],
        }]);
        if (contract) contracts.set(event.sessionID, contract);
      });
      if (!promptRegistration || typeof promptRegistration.dispose !== "function") {
        throw new Error("V2 prompt hook did not return a valid registration.");
      }
      taskRegistrations.push(promptRegistration);
      const sanitizeV2ModelRequest = async (event: {
        sessionID: string;
        messages: unknown[];
        system: unknown[];
      }): Promise<ReturnType<typeof runtimeForDirectory>> => {
        if (Array.isArray(event.messages)) {
          event.messages = event.messages.filter((message) =>
            !isTrustedGuardianMetadata(
              event.sessionID,
              (message as { metadata?: unknown }).metadata,
              "visible"
            )
          );
        }

        const runtimeDirectory = await resolveSessionDirectory(event.sessionID);
        const runtime = runtimeForDirectory(runtimeDirectory);
        if (runtime.config.enabled === false || !runtime.sanitizer) return runtime;

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
        if (runtime.config.enabled === false) return;
        const contract = contracts.get(event.sessionID);
        if (!contract) return;
        const guidance = taskGuidance(contract);
        if (guidance && !event.system.some((part) => part.text === guidance)) {
          event.system.push({ type: "text", text: guidance, metadata: { "opencode-guardian": true } });
        }
      });
      if (!contextRegistration || typeof contextRegistration.dispose !== "function") {
        throw new Error("V2 context hook did not return a valid registration.");
      }
      taskRegistrations.push(contextRegistration);

      const compactionRegistration = await context.session.hook("compaction", async (event) => {
        await sanitizeV2ModelRequest(event);
      });
      const generateRegistration = await context.session.hook("generate", async (event) => {
        await sanitizeV2ModelRequest(event);
      });
      const titleRegistration = await context.session.hook("title", async (event) => {
        await sanitizeV2ModelRequest(event);
      });
      for (const registration of [
        compactionRegistration,
        generateRegistration,
        titleRegistration,
      ]) {
        if (!registration || typeof registration.dispose !== "function") {
          throw new Error("V2 auxiliary model hook did not return a valid registration.");
        }
        taskRegistrations.push(registration);
      }

      registrations.push(...taskRegistrations);
    } catch {
      // Never leave a partial task/security hook group installed.
      await Promise.allSettled(taskRegistrations.map((registration) =>
        Promise.resolve().then(() => registration.dispose())
      ));
      contracts.clear();
      recordGuardianEvent({ kind: "inspection-error" }, directory);
      if (sanitizerOpts) {
        controller.abort();
        for (const registration of registrations.splice(0).reverse()) {
          try { await registration.dispose(); } catch {}
        }
        throw new Error("[opencode-guardian secrets] V2 session context security hook registration failed; FINAL context redaction cannot be enabled safely.");
      }
    }
  }

  const eventLoop = async () => {
    if (!events) return;
    let activeEvents: AsyncIterable<unknown> = events;
    // A terminated stream must never disable session inspection silently.
    // Retry a bounded number of times and keep strict tool hooks registered.
    for (let attempt = 0; attempt < 3 && !controller.signal.aborted; attempt++) {
      try {
        for await (const event of activeEvents) {
        const eventData = event as {
          type?: string;
          data?: {
            sessionID?: string;
            info?: { id?: string };
            status?: { type?: string };
            location?: { directory?: string };
            permissions?: V2PermissionRule[];
          };
        };

        if (eventData.type === "session.created") {
          const createdSessionID =
            eventData.data?.sessionID ?? eventData.data?.info?.id;
          if (createdSessionID) {
            rememberSessionDirectory(
              createdSessionID,
              eventData.data?.location?.directory
            );
          }
        }

        if (eventData.type === "session.deleted") {
          const deletedSessionID =
            eventData.data?.sessionID ?? eventData.data?.info?.id;
          if (deletedSessionID) {
            forgetSessionRuntime(deletedSessionID);
            verificationStore.forget(deletedSessionID);
            contracts.delete(deletedSessionID);
            foregroundHandoffs.delete(deletedSessionID);
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
              cacheV2SessionPermissions(
                permissionSessionID,
                eventData.data.permissions
              );
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
            forgetSessionRuntime(movedSessionID);
            rememberSessionDirectory(
              movedSessionID,
              eventData.data?.location?.directory
            );
            verificationStore.forget(movedSessionID);
            contracts.delete(movedSessionID);
            foregroundHandoffs.delete(movedSessionID);
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

        const idleEvent =
          eventData.type === "session.idle" ||
          (eventData.type === "session.status" &&
            eventData.data?.status?.type === "idle");
        if (!idleEvent) continue;

        const sessionID = eventData.data?.sessionID;
        if (!sessionID) continue;

        let activeDirectory = await resolveSessionDirectory(sessionID);
        let sessionIsSubagent: boolean | undefined;
        let sessionParentID: string | undefined;
        try {
          if (typeof context.session.get === "function") {
            const session = await context.session.get({ sessionID });
            activeDirectory = rememberSessionDirectory(
              sessionID,
              session.location?.directory
            );
            sessionParentID =
              typeof session.parentID === "string" && session.parentID.length > 0
                ? session.parentID
                : undefined;
            sessionIsSubagent = Boolean(sessionParentID);
          }
        } catch {
          // A transient/partial host must not disable the existing idle path.
        }

        if (sessionParentID && hasForegroundHandoff(foregroundHandoffs, sessionParentID)) {
          continue;
        }

        const runtime = runtimeForDirectory(activeDirectory);
        if (runtime.config.enabled === false) continue;

        await handleSessionIdle(
          sessionID,
          activeDirectory,
          async () => {
            const messages = await context.session.context({ sessionID });
            const normalized = normalizeV2Messages(messages, sessionID);
            const contract = extractTaskContract(normalized);
            if (contract) contracts.set(sessionID, contract);
            return normalized;
          },
          async (text) => {
            if (controller.signal.aborted) return;
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
          },
          runtime.engine,
          verificationStore.snapshots(sessionID),
          controller.signal,
          sessionIsSubagent,
          sessionIsSubagent
            ? async () => {
                const cached = getCachedAgentCapability(sessionID);
                if (cached) return cached;
                let agentName: string | undefined;
                try {
                  const msgs = await context.session.context({ sessionID });
                  const normalized = normalizeV2Messages(msgs, sessionID);
                  agentName = extractAgentNameFromMessages(normalized);
                } catch {}
                const p = await resolveV2AgentCapability(
                  context,
                  sessionID,
                  agentName,
                  undefined,
                  activeDirectory
                );
                cacheAgentCapability(sessionID, p);
                return p;
              }
            : undefined,
          toastNotifier
        );
        }
        if (controller.signal.aborted) return;
        throw new Error("V2 event stream ended before plugin teardown.");
      } catch {
        if (controller.signal.aborted) return;
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

      await new Promise<void>((resolve) => {
        const onAbort = () => {
          clearTimeout(timer);
          controller.signal.removeEventListener("abort", onAbort);
          resolve();
        };
        const timer = setTimeout(() => {
          controller.signal.removeEventListener("abort", onAbort);
          resolve();
        }, 200 * (attempt + 1));
        if (controller.signal.aborted) onAbort();
        else controller.signal.addEventListener("abort", onAbort, { once: true });
      });
      if (controller.signal.aborted) return;
      try {
        const next = context.event.subscribe({ signal: controller.signal });
        if (!next || typeof next[Symbol.asyncIterator] !== "function") {
          throw new Error("V2 event resubscription did not return an async iterable.");
        }
        activeEvents = next;
      } catch {
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
  } else {
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
    contracts.clear();
    verificationStore.clear();
    foregroundHandoffs.clear();
    interventionSnapshots.clear();
    clearAllAgentCapabilities();
    for (const sessionID of provenanceSessions) {
      forgetGuardianProvenance(sessionID);
    }
    provenanceSessions.clear();
    unregisterGuardianCapability();
    for (const registration of registrations.splice(0).reverse()) {
      try { await registration.dispose(); } catch {
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
