import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Plugin as OpenCodeV2 } from "@opencode/plugin";
import { GuardEngine, loadConfig, resolveEffectiveConfig, type EngineExecutionResult } from "./engine.js";
import type { MessagePart, PreflightMode, SessionMessage } from "./types.js";
import { extractTaskContract, taskGuidance } from "./task-contract.js";
import type { TaskContract } from "./task-contract.js";
import { evaluatePreflight, GuardianPreflightError, isShellExecutionTool, isFileMutationTool, isProcessStartTool } from "./preflight.js";
import { configureGuardianTelemetry, recordGuardianEvent, recordGuardianRedaction, sessionFingerprint } from "./telemetry.js";
import { auditReasons } from "./audit.js";
import { VerificationSnapshotStore, type VerificationSnapshot } from "./evidence.js";
import { createIdleQueue } from "./idle-queue.js";
import { registerGuardianCapability } from "./handoff.js";
import {
  type AgentMutationProfile,
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
  dispatchGuardianToastClear,
  formatGuardianToast,
  type GuardianToastNotifier,
  type GuardianToastPayload,
} from "./toast.js";
import {
  createGuardianMessageMetadata,
  forgetGuardianProvenance,
  isTrustedGuardianMetadata,
} from "./provenance.js";
import {
  GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD,
  GUARDIAN_INTERVENTION_RPC_DEFINITION,
  GUARDIAN_INTERVENTION_RPC_METHOD,
  activeGuardianIntervention,
  inactiveGuardianIntervention,
  readGuardianInterventionDirectory,
  readGuardianInterventionSessionID,
} from "./intervention-rpc.js";
import { StreamLoopWatcher } from "./stream-loop.js";
import {
  acquireSessionLease,
  clearMeshIntervention,
  getBlockingSessionLease,
  getLatestMeshIntervention,
  invalidateActiveMeshHandoff,
  isTrustedMeshMessage,
  recordMeshIntervention,
  registerMeshStateRpc,
  resolveMeshAgentProfile,
} from "./bridge.js";

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
export {
  MESH_VERSION,
  BRIDGE_REVISION,
  MESH_SYMBOL,
  MESH_METADATA_KEY,
  MESH_REMEDIATION_MARKER,
  MESH_STATE_RPC_ID,
  MESH_STATE_RPC_DEFINITION,
  registerMeshPeer,
  getMeshPeers,
  hasMeshCapability,
  stampMeshMetadata,
  verifyMeshMetadata,
  isTrustedMeshMessage,
  isMeshProtectedPart,
  wasMeshSanitized,
  wasMeshBounded,
  forgetMeshSession,
  acquireSessionLease,
  getBlockingSessionLease,
  isSessionWaitingOnUser,
  isSessionRemediating,
  registerRoleProfileResolver,
  resolveMeshAgentProfile,
  recordMeshIntervention,
  getLatestMeshIntervention,
  clearMeshIntervention,
  setActiveMeshHandoff,
  getActiveMeshHandoff,
  consumeActiveMeshHandoff,
  invalidateActiveMeshHandoff,
  clearActiveMeshHandoff,
  callMeshRpc,
  resetMeshStateForTests,
} from "./bridge.js";

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
    if (error instanceof Error) {
      return sanitizeObject(error, options).sanitized;
    }
    const source = error as Record<string, unknown> & {
      message?: unknown;
      stack?: unknown;
      name?: unknown;
    };
    const snapshot: Record<string, unknown> = { ...source };
    for (const key of Object.getOwnPropertyNames(source)) {
      snapshot[key] = source[key];
    }
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
  if (typeof content === "string") return content;
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

function extractV2OutputText(output: unknown, content: unknown): string {
  if (typeof output === "string") return output;
  if (output && typeof output === "object" && !Array.isArray(output)) {
    const obj = output as Record<string, unknown>;
    if (typeof obj.output === "string") return obj.output;
    if (typeof obj.content === "string") return obj.content;
    if (Array.isArray(obj.entries)) {
      return `Read directory\n${obj.entries.filter((e): e is string => typeof e === "string").join("\n")}`;
    }
    const nestedContent = stringifyV2ToolContent(obj.content);
    if (nestedContent) return nestedContent;
  }
  return stringifyV2ToolContent(content);
}

function extractShellCommandFromSyntheticText(text: string): string {
  const attr = /^<shell\b[^>]*\scommand="([^"]*)"/i.exec(text)?.[1];
  return attr ?? "";
}

function normalizeV2AssistantParts(part: unknown): MessagePart[] {
  if (!part || typeof part !== "object") return [];
  const value = part as Record<string, unknown>;

  if ((value.type === "text" || value.type === "reasoning") && typeof value.text === "string") {
    return [{ type: value.type, text: value.text }];
  }

  if (value.type !== "tool" || !value.state || typeof value.state !== "object") {
    return [];
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

  const output = extractV2OutputText(state.output, state.content);
  if (output) normalizedState.output = output;

  const primary: MessagePart = {
    type: "tool",
    tool: typeof value.name === "string" ? value.name : undefined,
    name: typeof value.name === "string" ? value.name : undefined,
    callID: typeof value.id === "string" ? value.id :
      typeof value.callID === "string" ? value.callID : undefined,
    state: normalizedState,
  };

  const toolCalls = normalizedState.metadata?.toolCalls;
  const isCodeModeCall =
    value.name === "execute" ||
    normalizedState.metadata?.codemode === true ||
    (typeof value.name === "string" && value.name.startsWith("tools."));
  if (!isCodeModeCall || !Array.isArray(toolCalls)) {
    return [primary];
  }

  const nestedParts: MessagePart[] = [];
  for (let i = 0; i < toolCalls.length; i++) {
    const call = toolCalls[i];
    if (!call || typeof call !== "object") continue;
    const rec = call as Record<string, unknown>;
    const toolName = typeof rec.tool === "string" ? rec.tool : undefined;
    const callStatus = typeof rec.status === "string" ? rec.status : "completed";
    if (!toolName) continue;
    const callInput =
      rec.input && typeof rec.input === "object" && !Array.isArray(rec.input)
        ? (rec.input as Record<string, unknown>)
        : {};
    const recMeta =
      rec.metadata && typeof rec.metadata === "object" && !Array.isArray(rec.metadata)
        ? (rec.metadata as Record<string, unknown>)
        : {};
    const callOutput = extractV2OutputText(rec.output, rec.content);
    const callID =
      typeof rec.id === "string" && rec.id.length > 0
        ? rec.id
        : typeof rec.callID === "string" && rec.callID.length > 0
          ? rec.callID
          : primary.callID
            ? `${primary.callID}:codemode:${i}`
            : undefined;
    const explicitExitCode =
      typeof rec.exitCode === "number" && Number.isFinite(rec.exitCode)
        ? rec.exitCode
        : typeof recMeta.exit === "number" && Number.isFinite(recMeta.exit)
          ? recMeta.exit
          : undefined;
    const isBackgroundOrOutputExit =
      recMeta.status === "running" ||
      recMeta.state === "running" ||
      /(?:^|\n)Exit code:\s*\d+/i.test(callOutput) ||
      /(?:^|\n)Command moved to the background\b/i.test(callOutput);
    nestedParts.push({
      type: "tool",
      tool: toolName,
      name: toolName,
      callID,
      state: {
        status: callStatus,
        input: callInput,
        metadata: { ...recMeta, codemode: true },
        ...(callOutput ? { output: callOutput } : {}),
        ...(rec.error !== undefined ? { error: rec.error } : {}),
        ...(explicitExitCode !== undefined
          ? { exitCode: explicitExitCode }
          : callStatus === "completed" &&
              (toolName === "shell" || toolName === "bash") &&
              !isBackgroundOrOutputExit
            ? { exitCode: 0 }
            : {}),
      },
    });
  }

  return [primary, ...nestedParts];
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
      const trustedMesh = isTrustedMeshMessage(msg, sessionID);
      normalized.push({
        info: { id, role: "user" },
        parts: [{
          type: "text",
          text: msg.text,
          ...(trustedMesh ? { synthetic: true } : {}),
          ...(msg.metadata && typeof msg.metadata === "object"
            ? { metadata: msg.metadata }
            : {}),
        }],
      });
      continue;
    }

    if (type === "synthetic" && typeof msg.text === "string") {
      const meta =
        msg.metadata && typeof msg.metadata === "object" && !Array.isArray(msg.metadata)
          ? (msg.metadata as Record<string, unknown>)
          : undefined;
      if (meta?.source === "shell") {
        const extractedCmd = extractShellCommandFromSyntheticText(msg.text);
        const command =
          typeof meta.command === "string" && meta.command.trim().length > 0
            ? meta.command
            : extractedCmd.length > 0
              ? extractedCmd
              : typeof msg.description === "string" && msg.description.trim().length > 0
                ? msg.description
                : "";
        const shellState = meta.state ?? meta.status;
        const completedOk =
          shellState === "completed" &&
          (meta.exit === 0 || meta.exit === undefined);
        const mappedStatus =
          shellState === "running"
            ? "running"
            : completedOk
              ? "completed"
              : "error";
        normalized.push({
          info: { id, role: "assistant" },
          parts: [{
            type: "tool",
            tool: "shell",
            name: "shell",
            callID: typeof meta.shellID === "string" ? meta.shellID : id,
            state: {
              status: mappedStatus,
              input: { command },
              output: msg.text,
              metadata: meta,
              ...(meta.exit !== undefined ? { exitCode: meta.exit } : {}),
            },
          }],
        });
        continue;
      }
      if (
        meta?.source === "codemode" ||
        meta?.source === "image" ||
        meta?.source === "video" ||
        typeof meta?.jobID === "string"
      ) {
        const jobState = meta.state ?? meta.status;
        const jobStatus =
          jobState === "running"
            ? "running"
            : jobState === "error" || jobState === "failed" || jobState === "cancelled"
              ? "error"
              : "completed";
        const toolName =
          meta.source === "image"
            ? "generate_image"
            : meta.source === "video"
              ? "generate_video"
              : "execute";
        normalized.push({
          info: { id, role: "assistant" },
          parts: [{
            type: "tool",
            tool: toolName,
            name: toolName,
            callID: typeof meta.jobID === "string" ? meta.jobID : id,
            state: {
              status: jobStatus,
              input: {},
              output: msg.text,
              metadata: { ...meta, status: jobStatus },
            },
          }],
        });
        continue;
      }
      normalized.push({
        info: { id, role: "user" },
        parts: [{
          type: "text",
          text: msg.text,
          synthetic: true,
          ...(meta ? { metadata: meta } : {}),
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
      const parts = msg.content.flatMap(normalizeV2AssistantParts);

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
      const shellOutput =
        msg.output && typeof msg.output === "object"
          ? (msg.output as { output?: unknown }).output
          : undefined;
      const isRunning = msg.status === "running";
      const exitedOk = msg.status === "exited" && (msg.exit === 0 || msg.exit === undefined);
      normalized.push({
        info: { id, role: "assistant" },
        parts: [{
          type: "tool",
          tool: "shell",
          name: "shell",
          callID: typeof msg.shellID === "string" ? msg.shellID : id,
          state: {
            status: isRunning ? "running" : exitedOk ? "completed" : "error",
            input: { command: msg.command },
            metadata: {
              ...(typeof msg.status === "string" ? { status: msg.status } : {}),
              ...(typeof msg.shellID === "string" ? { shellID: msg.shellID } : {}),
            },
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
const FOREGROUND_HANDOFF_TTL_MS = 5 * 60_000;
const activeRemediationLeases = new Map<string, () => void>();

function setRemediationLeaseForSession(sessionID: string, release: () => void): void {
  const existing = activeRemediationLeases.get(sessionID);
  if (existing && existing !== release) {
    activeRemediationLeases.delete(sessionID);
    try { existing(); } catch {}
  }
  activeRemediationLeases.delete(sessionID);
  activeRemediationLeases.set(sessionID, release);
  while (activeRemediationLeases.size > 512) {
    const oldest = activeRemediationLeases.keys().next().value;
    if (oldest === undefined) break;
    const oldRelease = activeRemediationLeases.get(oldest);
    activeRemediationLeases.delete(oldest);
    try { oldRelease?.(); } catch {}
  }
}

function releaseRemediationLeaseForSession(sessionID: string): void {
  const release = activeRemediationLeases.get(sessionID);
  if (!release) return;
  activeRemediationLeases.delete(sessionID);
  try { release(); } catch {}
}

function pruneExpiredForegroundHandoffs(
  handoffs: Map<string, Map<string, number>>,
  sessionID: string,
  now = Date.now()
): Map<string, number> | undefined {
  const active = handoffs.get(sessionID);
  if (!active) return undefined;
  for (const [callID, timestamp] of active.entries()) {
    if (now - timestamp > FOREGROUND_HANDOFF_TTL_MS) {
      active.delete(callID);
    }
  }
  if (active.size === 0) {
    handoffs.delete(sessionID);
    return undefined;
  }
  return active;
}

function markForegroundHandoff(
  handoffs: Map<string, Map<string, number>>,
  sessionID: string,
  callID: string,
  now = Date.now()
): void {
  const active = pruneExpiredForegroundHandoffs(handoffs, sessionID, now) ?? new Map<string, number>();
  active.set(callID, now);
  handoffs.delete(sessionID);
  handoffs.set(sessionID, active);
  while (handoffs.size > 512) {
    const oldest = handoffs.keys().next().value;
    if (oldest === undefined) break;
    handoffs.delete(oldest);
  }
}

function clearForegroundHandoff(
  handoffs: Map<string, Map<string, number>>,
  sessionID: string,
  callID: string
): void {
  const active = handoffs.get(sessionID);
  if (!active) return;
  active.delete(callID);
  if (active.size === 0) handoffs.delete(sessionID);
}

function hasForegroundHandoff(
  handoffs: Map<string, Map<string, number>>,
  sessionID?: string,
  now = Date.now()
): boolean {
  if (!sessionID) return false;
  const active = pruneExpiredForegroundHandoffs(handoffs, sessionID, now);
  return Boolean(active && active.size > 0);
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

const INTERVENTION_TRACKER = Symbol("opencode-guardian.intervention-tracker");

interface InterventionResolutionTracker {
  noteHumanPrompt(sessionID: string): void;
  recordOutcome(
    sessionID: string,
    result: EngineExecutionResult,
    findingsCount: number,
    toastNotifier?: GuardianToastNotifier
  ): void;
  forget(sessionID: string): void;
}

type TrackedGuardianToastNotifier = GuardianToastNotifier & {
  [INTERVENTION_TRACKER]?: InterventionResolutionTracker;
};

function createTrackedToastNotifier(base: GuardianToastNotifier): TrackedGuardianToastNotifier {
  const remainingCleanTurns = new Map<string, number>();
  const tracker: InterventionResolutionTracker = {
    noteHumanPrompt(sessionID: string): void {
      if (remainingCleanTurns.has(sessionID)) {
        remainingCleanTurns.delete(sessionID);
        base.clear?.(sessionID);
      }
    },
    recordOutcome(
      sessionID: string,
      result: EngineExecutionResult,
      findingsCount: number,
      toastNotifier?: GuardianToastNotifier
    ): void {
      if (result.remediationStatus === "verified") {
        if (findingsCount === 0) {
          remainingCleanTurns.delete(sessionID);
        }
        return;
      }
      if (
        findingsCount > 0 ||
        result.decision === "block" ||
        result.remediationStatus === "failed" ||
        result.remediationStatus === "unverified"
      ) {
        if (remainingCleanTurns.has(sessionID) && (remainingCleanTurns.get(sessionID) ?? 0) < 1) {
          remainingCleanTurns.set(sessionID, 1);
        }
        return;
      }
      if (result.results.length === 0) return;
      const remaining = remainingCleanTurns.get(sessionID);
      if (remaining === undefined) return;
      if (remaining <= 1) {
        remainingCleanTurns.delete(sessionID);
        toastNotifier?.clear?.(sessionID);
      } else {
        remainingCleanTurns.set(sessionID, remaining - 1);
      }
    },
    forget(sessionID: string): void {
      remainingCleanTurns.delete(sessionID);
    },
  };
  return {
    notify(input): void {
      if (typeof input.sessionID === "string" && input.sessionID.length > 0) {
        const requiredCleanTurns =
          input.kind === "stream-interrupt-requested" || input.kind === "preflight-blocked"
            ? 2
            : 1;
        remainingCleanTurns.delete(input.sessionID);
        remainingCleanTurns.set(input.sessionID, requiredCleanTurns);
        while (remainingCleanTurns.size > 512) {
          const oldest = remainingCleanTurns.keys().next().value;
          if (oldest === undefined) break;
          remainingCleanTurns.delete(oldest);
        }
      }
      base.notify(input);
    },
    clear(sessionID: string): void {
      remainingCleanTurns.delete(sessionID);
      base.clear?.(sessionID);
    },
    [INTERVENTION_TRACKER]: tracker,
  };
}

function recordInspectionOutcome(
  result: EngineExecutionResult,
  sessionID: string,
  directory: string,
  toastNotifier?: GuardianToastNotifier
) {
  const findings = result.results.filter((item) => item.findings.length > 0);
  // Only completed, non-duplicate rule evaluations count toward Inspected.
  if (result.results.length > 0) {
    recordGuardianEvent({
      kind: "post-inspected",
      session: sessionFingerprint(sessionID),
    }, directory);
  }

  if (result.remediationStatus === "verified") {
    clearMeshIntervention(sessionID);
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

  if (result.results.length > 0 && result.decision === "pass" && result.remediationStatus !== "failed") {
    clearMeshIntervention(sessionID);
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

  (toastNotifier as TrackedGuardianToastNotifier | undefined)?.[INTERVENTION_TRACKER]?.recordOutcome(
    sessionID,
    result,
    findings.length,
    toastNotifier
  );
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
      if (getBlockingSessionLease(input.sessionID, "active_remediation", "opencode-guardian")) {
        return latestAssistantText(messages);
      }
      if (round === MAX_SUBAGENT_HANDOFF_ROUNDS - 1) {
        result.rollback?.();
        throw new Error("[opencode-guardian handoff] remediation did not converge before the safety limit.");
      }
      const releaseRemediationLease = acquireSessionLease({
        sessionID: input.sessionID,
        owner: "opencode-guardian",
        kind: "active_remediation",
        ttlMs: 45_000,
        reason: "guardian-subagent-remediation",
      });
      recordMeshIntervention({
        sessionID: input.sessionID,
        directory: input.directory,
        owner: "opencode-guardian",
        kind: "post-remediation",
        ruleIds: findings.map((item) => item.ruleId),
        deterministic: true,
        active: true,
        updatedAt: Date.now(),
        message: "guardian-subagent-remediation",
      });
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
        clearMeshIntervention(input.sessionID);
        recordGuardianEvent({
          kind: "inspection-error",
          session: sessionFingerprint(input.sessionID),
          rules: ["prompt-delivery-failed"],
          reasons: [{ rule: "prompt-delivery-failed", code: "prompt-delivery-failed" }],
        }, input.directory);
        throw new Error("[opencode-guardian handoff] could not complete subagent remediation.");
      } finally {
        releaseRemediationLease();
      }
      continue;
    }

    if (result.remediationStatus === "failed") {
      clearMeshIntervention(input.sessionID);
      throw new Error("[opencode-guardian handoff] unresolved Guardian findings; subagent result withheld.");
    }

    const latest = latestAssistantText(messages);
    if (remediated && !latest) {
      clearMeshIntervention(input.sessionID);
      throw new Error("[opencode-guardian handoff] remediated subagent produced no final text result.");
    }
    return latest;
  }

  clearMeshIntervention(input.sessionID);
  throw new Error("[opencode-guardian handoff] subagent finalization exceeded its bounded loop.");
}

export function hasUnfinishedBackgroundTool(messages: readonly SessionMessage[]): boolean {
  const lastHumanIdx = messages.findLastIndex(
    (msg) =>
      msg.info.role === "user" &&
      msg.parts.some(
        (p) =>
          p.type === "text" &&
          typeof p.text === "string" &&
          p.synthetic !== true &&
          p.ignored !== true &&
          p.text.trim().length > 0
      )
  );
  const turn = lastHumanIdx >= 0 ? messages.slice(lastHumanIdx) : messages;
  const runningIDs = new Set<string>();
  const finishedIDs = new Set<string>();
  let anonymousRunning = 0;

  for (const msg of turn) {
    for (const part of msg.parts) {
      if (part.type !== "tool" || !part.state) continue;
      const meta = part.state.metadata;
      const outputText = typeof part.state.output === "string" ? part.state.output : "";
      const shellID = typeof meta?.shellID === "string" ? meta.shellID : undefined;
      const jobID = typeof meta?.jobID === "string" ? meta.jobID : undefined;
      const id = shellID ?? jobID ?? (typeof part.callID === "string" ? part.callID : undefined);
      const isMovedToBackground =
        /(?:^|\n)(?:Command|Execution)\s+moved to the background\b/i.test(outputText) ||
        /(?:^|\n)The (?:command|execution) did not finish within its timeout\b[\s\S]*\bmoved to the background\b/i.test(outputText) ||
        /\bmoved to the background\s*\(job\b/i.test(outputText);
      const isPendingJobID =
        Boolean(jobID) &&
        meta?.status !== "completed" &&
        meta?.state !== "completed" &&
        meta?.source === undefined;
      const isRunning =
        part.state.status === "running" ||
        meta?.status === "running" ||
        meta?.state === "running" ||
        isMovedToBackground ||
        isPendingJobID;
      if (isRunning) {
        if (id) runningIDs.add(id);
        else anonymousRunning += 1;
      } else if (id && (part.state.status === "completed" || part.state.status === "error")) {
        finishedIDs.add(id);
      }
    }
  }

  if (anonymousRunning > 0) return true;
  for (const id of runningIDs) {
    if (!finishedIDs.has(id)) return true;
  }
  return false;
}

/**
 * Common handler to process session.idle events in OpenCode V2.
 */
async function handleSessionIdle(
  sessionID: string,
  directory: string,
  fetchMessages: () => Promise<SessionMessage[]>,
  sendPrompt: (promptText: string) => Promise<void>,
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
    if (getBlockingSessionLease(sessionID, "active_remediation", "opencode-guardian")) {
      return;
    }
    const messages = await fetchMessages();
    if (signal?.aborted) return;
    if (hasUnfinishedBackgroundTool(messages)) return;
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
    if (signal?.aborted) return;
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
        releaseRemediationLeaseForSession(sessionID);
        return;
      }
      stage = "prompt-send";
      recordMeshIntervention({
        sessionID,
        directory,
        owner: "opencode-guardian",
        kind: "post-remediation",
        ruleIds: findings.map((item) => item.ruleId),
        deterministic: false,
        active: true,
        updatedAt: Date.now(),
      });
      releaseRemediationLeaseForSession(sessionID);
      const releaseRemediationLease = acquireSessionLease({
        sessionID,
        owner: "opencode-guardian",
        kind: "active_remediation",
        ttlMs: 45_000,
        reason: "guardian-remediation",
      });
      try {
        if (signal?.aborted) {
          releaseRemediationLease();
          result.rollback?.();
          clearMeshIntervention(sessionID);
          return;
        }
        await sendPrompt(result.combinedRemediationPrompt);
        if (signal?.aborted) {
          releaseRemediationLease();
          return;
        }
        setRemediationLeaseForSession(sessionID, releaseRemediationLease);
        recordGuardianEvent({ kind: "post-remediation", session: sessionFingerprint(sessionID), rules: findings.map((item) => item.ruleId), reasons: auditReasons(findings) }, directory);
        toastNotifier?.notify({
          kind: "remediation",
          ruleIds: findings.map((item) => item.ruleId),
          sessionID,
        });
      } catch (promptError) {
        releaseRemediationLease();
        result.rollback?.();
        clearMeshIntervention(sessionID);
        throw promptError;
      }
    } else if (result.results.length > 0) {
      releaseRemediationLeaseForSession(sessionID);
    }
  } catch {
    releaseRemediationLeaseForSession(sessionID);
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
  toastNotifier?: GuardianToastNotifier,
  mode: PreflightMode = "strict"
): void {
  if (!isShellExecutionTool(tool, additionalTools) && !isFileMutationTool(tool) && !isProcessStartTool(tool)) return;
  const finding = evaluatePreflight(tool, args, additionalTools, mode);
  const session = sessionFingerprint(sessionID);
  const safeTool = tool.toLowerCase().replace(/^mcp__[a-z0-9_]+__/, "").split(/[.:/]/).at(-1);
  recordGuardianEvent({
    kind: finding ? "preflight-blocked" : "preflight-allowed",
    ...(session ? { session } : {}),
    ...(safeTool ? { tool: safeTool } : {}),
    ...(finding ? { rules: [finding] } : {}),
  }, directory);
  if (finding) {
    if (sessionID) {
      recordMeshIntervention({
        sessionID,
        directory: directory ?? "",
        owner: "opencode-guardian",
        kind: "preflight-blocked",
        ruleIds: [finding],
        deterministic: true,
        active: true,
        updatedAt: Date.now(),
      });
    }
    toastNotifier?.notify({
      kind: "preflight-blocked",
      ruleId: finding,
      ...(safeTool ? { tool: safeTool } : {}),
      ...(sessionID ? { sessionID } : {}),
    });
    throw new GuardianPreflightError(finding);
  }
  if (sessionID && getLatestMeshIntervention(sessionID)?.kind === "preflight-blocked") {
    clearMeshIntervention(sessionID);
  }
}

function realpathLoose(targetPath: string): string {
  const resolved = path.resolve(targetPath);
  try {
    return fs.realpathSync(resolved);
  } catch {
    return resolved;
  }
}

function isSameOrSubdirectory(candidateDir: string, baseDir: string): boolean {
  const candidate = realpathLoose(candidateDir);
  const base = realpathLoose(baseDir);
  return candidate === base || candidate.startsWith(base + path.sep);
}

function isProjectLocalPluginInstall(dir: string): boolean {
  return (
    fs.existsSync(path.join(dir, ".opencode", "plugins", "opencode-guardian")) ||
    fs.existsSync(path.join(dir, ".opencode", "plugin", "opencode-guardian")) ||
    fs.existsSync(path.join(dir, ".opencode", "node_modules", "opencode-guardian"))
  );
}

function globalOpenCodeConfigDir(): string {
  if (process.env.OPENCODE_CONFIG_DIR && process.env.OPENCODE_CONFIG_DIR.trim()) {
    return path.resolve(process.env.OPENCODE_CONFIG_DIR);
  }
  if (process.env.XDG_CONFIG_HOME && process.env.XDG_CONFIG_HOME.trim()) {
    return path.join(path.resolve(process.env.XDG_CONFIG_HOME), "opencode");
  }
  return path.join(os.homedir(), ".config", "opencode");
}

function openCodeConfigMentionsGuardian(dir: string): boolean {
  for (const name of ["opencode.json", "opencode.jsonc"]) {
    const candidate = path.join(dir, name);
    if (!fs.existsSync(candidate)) continue;
    try {
      const raw = fs.readFileSync(candidate, "utf8");
      if (raw.includes("opencode-guardian") && !raw.includes("-opencode-guardian")) {
        return true;
      }
    } catch {}
  }
  return false;
}

function hasExplicitGuardianConfigOrInstall(dir: string): boolean {
  return (
    fs.existsSync(path.join(dir, "opencode-guardian.json")) ||
    fs.existsSync(path.join(dir, ".opencode", "opencode-guardian.json")) ||
    fs.existsSync(path.join(dir, "opencode-guard.json")) ||
    fs.existsSync(path.join(dir, ".opencode", "opencode-guard.json")) ||
    isProjectLocalPluginInstall(dir) ||
    openCodeConfigMentionsGuardian(dir) ||
    openCodeConfigMentionsGuardian(path.join(dir, ".opencode"))
  );
}

function hasGlobalGuardianInstall(): boolean {
  const globalDir = globalOpenCodeConfigDir();
  return (
    fs.existsSync(path.join(globalDir, "opencode-guardian.json")) ||
    fs.existsSync(path.join(globalDir, "opencode-guard.json")) ||
    fs.existsSync(path.join(globalDir, "plugins", "opencode-guardian")) ||
    fs.existsSync(path.join(globalDir, "plugin", "opencode-guardian")) ||
    fs.existsSync(path.join(globalDir, "node_modules", "opencode-guardian")) ||
    openCodeConfigMentionsGuardian(globalDir)
  );
}

function hasLocalProjectMarker(dir: string): boolean {
  return (
    hasExplicitGuardianConfigOrInstall(dir) ||
    fs.existsSync(path.join(dir, ".opencode")) ||
    fs.existsSync(path.join(dir, ".git"))
  );
}

function isDirectoryInGuardianScope(startupDirectory: string, targetDirectory: string): boolean {
  if (!targetDirectory || isSameOrSubdirectory(targetDirectory, startupDirectory)) {
    return true;
  }
  if (hasExplicitGuardianConfigOrInstall(targetDirectory)) {
    return true;
  }
  if (isProjectLocalPluginInstall(startupDirectory)) {
    return false;
  }
  if (hasGlobalGuardianInstall()) {
    return true;
  }
  if (hasLocalProjectMarker(startupDirectory) || hasLocalProjectMarker(targetDirectory)) {
    return false;
  }
  return true;
}

const setup: OpenCodeV2.Plugin["setup"] = async (
  context: OpenCodeV2.Context
) => {
  // Transition builds may call setup() with a partial v2 context.
  // Resolve the explicit security setting first: strict preflight must never
  // silently disappear merely because another v2 capability is unavailable.
  const directory = context?.location?.directory ?? process.cwd();
  const mergedConfig = resolveEffectiveConfig(loadConfig(directory), context.options);
  configureGuardianTelemetry(directory, mergedConfig.telemetry);
  if (mergedConfig.enabled === false) {
    recordGuardianEvent({ kind: "runtime-started", runtime: "v2", preflight: "disabled" }, directory);
    configureGuardianTelemetry(directory, undefined);
    return;
  }
  const sanitizerOpts = resolveSanitizerOptions(mergedConfig);
  const strictPreflight = mergedConfig.preflight?.enabled === true;
  if (
    !context ||
    typeof context !== "object" ||
    typeof context.event?.subscribe !== "function" ||
    typeof context.session?.context !== "function" ||
    typeof context.session?.synthetic !== "function"
  ) {
    configureGuardianTelemetry(directory, undefined);
    if (strictPreflight) {
      throw new Error("[opencode-guardian preflight] V2 host context is unavailable; strict preflight cannot be enabled.");
    }
    if (sanitizerOpts) {
      throw new Error("[opencode-guardian secrets] V2 host context is unavailable; secret protection cannot be enabled safely.");
    }
    return;
  }

  const runtimeByDirectory = new Map<string, {
    config: typeof mergedConfig;
    sanitizer: ReturnType<typeof resolveSanitizerOptions>;
    engine: GuardEngine;
  }>();
  const controller = new AbortController();
  controller.signal.addEventListener("abort", () => {
    configureGuardianTelemetry(directory, undefined);
    for (const key of runtimeByDirectory.keys()) {
      configureGuardianTelemetry(key, undefined);
    }
  });
  const provenanceSessions = new Set<string>();
  const v2GuardianMetadata = (
    sessionID: string,
    kind: "remediation" | "visible",
    base: Record<string, unknown> = {}
  ) => {
    provenanceSessions.delete(sessionID);
    provenanceSessions.add(sessionID);
    while (provenanceSessions.size > 512) {
      const oldest = provenanceSessions.values().next().value;
      if (oldest === undefined) break;
      provenanceSessions.delete(oldest);
      forgetGuardianProvenance(oldest);
    }
    return createGuardianMessageMetadata(sessionID, kind, base);
  };
  let events: AsyncIterable<unknown>;
  try {
    const candidate = context.event.subscribe({
      signal: controller.signal,
    });
    if (
      !candidate ||
      typeof (candidate as AsyncIterable<unknown>)[Symbol.asyncIterator] !==
        "function"
    ) {
      throw new Error("V2 event subscriber did not return an async iterable");
    }
    events = candidate as AsyncIterable<unknown>;
  } catch (error) {
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
  const runtimeForDirectory = (runtimeDirectory: string) => {
    const key = runtimeDirectory || directory;
    const cached = runtimeByDirectory.get(key);
    if (cached && (!cached.config.enabled || (toolOutputProtectionReady && modelRequestProtectionReady) || !cached.sanitizer)) {
      return cached;
    }
    if (!isDirectoryInGuardianScope(directory, key)) {
      const disabledConfig: typeof mergedConfig = { ...mergedConfig, enabled: false };
      const disabledRuntime = {
        config: disabledConfig,
        sanitizer: null,
        engine: new GuardEngine(disabledConfig),
      };
      runtimeByDirectory.set(key, disabledRuntime);
      return disabledRuntime;
    }
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

  const sessionDirectories = new Map<string, string>();
  const rememberSessionDirectory = (sessionID: string, value: unknown): string => {
    const resolved =
      typeof value === "string" && value.trim().length > 0
        ? value
        : sessionDirectories.get(sessionID) ?? directory;
    sessionDirectories.delete(sessionID);
    sessionDirectories.set(sessionID, resolved);
    while (sessionDirectories.size > 512) {
      const oldest = sessionDirectories.keys().next().value;
      if (oldest === undefined) break;
      sessionDirectories.delete(oldest);
    }
    return resolved;
  };
  const resolveSessionDirectory = async (sessionID: string): Promise<string> => {
    const cached = sessionDirectories.get(sessionID);
    if (cached) return cached;
    try {
      if (typeof context.session.get === "function") {
        const session = await context.session.get({ sessionID });
        const sessionDirectory = session.location?.directory;
        if (typeof sessionDirectory === "string" && sessionDirectory.trim()) {
          return rememberSessionDirectory(sessionID, sessionDirectory);
        }
      }
    } catch {}
    // Retry failed location lookups instead of caching the startup project.
    return directory;
  };
  const forgetSessionRuntime = (sessionID: string): void => {
    for (const runtime of runtimeByDirectory.values()) {
      runtime.engine.forgetSession(sessionID);
    }
    sessionDirectories.delete(sessionID);
  };

  const verificationStore = new VerificationSnapshotStore();
  const backgroundSessions = new Set<string>();
  const sessionBackgroundJobs = new Map<string, Set<string>>();
  const backgroundJobKey = (job: unknown): string | undefined => {
    if (!job || typeof job !== "object") return undefined;
    const rec = job as {
      id?: unknown;
      jobID?: unknown;
      shellID?: unknown;
      childSessionID?: unknown;
      path?: unknown;
      kind?: unknown;
    };
    if (typeof rec.id === "string" && rec.id.length > 0) return rec.id;
    if (typeof rec.jobID === "string" && rec.jobID.length > 0) return rec.jobID;
    if (typeof rec.shellID === "string" && rec.shellID.length > 0) return rec.shellID;
    if (typeof rec.childSessionID === "string" && rec.childSessionID.length > 0) return rec.childSessionID;
    if (typeof rec.path === "string" && rec.path.length > 0) {
      return typeof rec.kind === "string" ? `${rec.kind}:${rec.path}` : rec.path;
    }
    return typeof rec.kind === "string" && rec.kind.length > 0 ? rec.kind : undefined;
  };
  const contracts = new Map<string, TaskContract>();
  const setSessionContract = (sessionID: string, contract: TaskContract): void => {
    contracts.delete(sessionID);
    contracts.set(sessionID, contract);
    while (contracts.size > 512) {
      const oldest = contracts.keys().next().value;
      if (oldest === undefined) break;
      contracts.delete(oldest);
    }
  };
  const foregroundHandoffs = new Map<string, Map<string, number>>();
  const registrations: Array<{ dispose(): Promise<void> | void }> = [];
  const interventionSnapshots = new Map<string, { payload: GuardianToastPayload; expiresAt: number }>();
  const interventionExpiryTimers = new Map<string, ReturnType<typeof setTimeout>>();
  const clearInterventionSnapshot = (sessionID: string): void => {
    const existingTimer = interventionExpiryTimers.get(sessionID);
    if (existingTimer !== undefined) {
      clearTimeout(existingTimer);
      interventionExpiryTimers.delete(sessionID);
    }
    interventionSnapshots.delete(sessionID);
  };
  const toastNotifiersByDirectory = new Map<string, GuardianToastNotifier>();
  const idleQueue = createIdleQueue(controller.signal, () => {
    recordGuardianEvent({ kind: "inspection-error", rules: ["engine-inspection-failed"] }, directory);
  });

  if (typeof context.rpc?.register === "function") {
    try {
      const disposeMeshRpc = await registerMeshStateRpc({
        rpcRegister: context.rpc.register.bind(context.rpc) as any,
        owner: "opencode-guardian",
        directory,
      });
      registrations.push({ dispose: disposeMeshRpc });
    } catch {}
    try {
      const rpcRegistration = await context.rpc.register(
        GUARDIAN_INTERVENTION_RPC_DEFINITION,
        {
          [GUARDIAN_INTERVENTION_RPC_METHOD]: async (input) => {
            const sessionID = readGuardianInterventionSessionID(input);
            if (!sessionID) return inactiveGuardianIntervention();
            const entry = interventionSnapshots.get(sessionID);
            if (!entry) return inactiveGuardianIntervention();
            const now = Date.now();
            if (now >= entry.expiresAt) {
              toastNotifier.clear?.(sessionID);
              return inactiveGuardianIntervention();
            }
            return activeGuardianIntervention({
              ...entry.payload,
              duration: Math.max(1, entry.expiresAt - now),
            });
          },
          [GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD]: async (input, ...rest: unknown[]) => {
            const sessionID = readGuardianInterventionSessionID(input);
            if (sessionID) {
              clearMeshIntervention(sessionID);
              toastNotifier.clear?.(sessionID);
              return { cleared: true };
            }
            const rpcContext = rest[0] as { location?: { directory?: unknown } } | undefined;
            const contextDir =
              typeof rpcContext?.location?.directory === "string" && rpcContext.location.directory.trim()
                ? rpcContext.location.directory
                : undefined;
            const targetDirectory =
              readGuardianInterventionDirectory(input) ?? contextDir ?? directory;
            for (const activeSessionID of Array.from(interventionSnapshots.keys())) {
              const sessionDir =
                sessionDirectories.get(activeSessionID) ??
                await resolveSessionDirectory(activeSessionID);
              if (sessionDir === targetDirectory) {
                clearMeshIntervention(activeSessionID);
                toastNotifier.clear?.(activeSessionID);
              }
            }
            for (const [knownSessionID, knownDir] of sessionDirectories.entries()) {
              if (knownDir === targetDirectory) {
                clearMeshIntervention(knownSessionID);
              }
            }
            dispatchGuardianToastClear({ directory: targetDirectory });
            return { cleared: true };
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
  const toastNotifier: TrackedGuardianToastNotifier = createTrackedToastNotifier({
    notify(input): void {
      if (
        typeof input.sessionID === "string" &&
        input.sessionID.length > 0
      ) {
        try {
          const sid = input.sessionID;
          clearInterventionSnapshot(sid);
          const payload = formatGuardianToast(input);
          const ttlMs = payload.duration > 0 ? payload.duration : 5000;
          interventionSnapshots.set(sid, {
            payload,
            expiresAt: Date.now() + ttlMs,
          });
          const timer = setTimeout(() => {
            interventionExpiryTimers.delete(sid);
            toastNotifier.clear?.(sid);
          }, ttlMs);
          (timer as { unref?: () => void }).unref?.();
          interventionExpiryTimers.set(sid, timer);
          while (interventionSnapshots.size > 64) {
            const oldest = interventionSnapshots.keys().next().value;
            if (typeof oldest !== "string") break;
            clearInterventionSnapshot(oldest);
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
      clearInterventionSnapshot(sessionID);
      const runtimeDirectory = sessionDirectories.get(sessionID) ?? directory;
      try {
        baseToastForDirectory(runtimeDirectory).clear?.(sessionID);
      } catch {}
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
      if (typeof context.session.interrupt !== "function") throw new Error("Session interrupt unavailable");
      return context.session.interrupt({ sessionID, resume: false });
    },
    notifier: toastNotifier,
  });

  if (strictPreflight && typeof context.tool?.hook !== "function") {
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
    {
      try {
        const before = await context.tool.hook("execute.before", async (event) => {
          if (controller.signal.aborted) return;
          const runtimeDirectory = await resolveSessionDirectory(event.sessionID);
          if (controller.signal.aborted) return;
          const runtime = runtimeForDirectory(runtimeDirectory);
          if (runtime.config.enabled === false) return;
          if (event.input && typeof event.input === "object" && !Array.isArray(event.input)) {
            verificationStore.observeBefore(event.sessionID, event.id, event.tool,
              event.input as Record<string, unknown>, runtimeDirectory);
          }

          if (runtime.config.preflight?.enabled === true) {
            inspectPreflight(
              event.tool,
              event.input,
              event.sessionID,
              runtimeDirectory,
              runtime.config.preflight?.shellTools,
              toastNotifier,
              runtime.config.preflight?.mode ?? "strict"
            );
          }

          if (canFinalizeSubagent && event.tool === "subagent") {
            const input =
              event.input && typeof event.input === "object" && !Array.isArray(event.input)
                ? event.input as Record<string, unknown>
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
      } catch (error) {
        if (strictPreflight) {
          controller.abort();
          for (const registration of registrations.splice(0).reverse()) {
            try { await registration.dispose(); } catch {}
          }
          throw new Error("[opencode-guardian preflight] V2 tool hook registration failed; strict preflight cannot be enabled.", { cause: error });
        }
      }
    }

    try {
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
          Boolean(pruneExpiredForegroundHandoffs(foregroundHandoffs, event.sessionID)?.has(event.id));

        try {
          const observedDirectory = await resolveSessionDirectory(event.sessionID);
          const runtime = runtimeForDirectory(observedDirectory);
          if (runtime.config.enabled === false) return;

          if (runtime.sanitizer && event.status === "error") {
            const beforeErr = JSON.stringify(event.error);
            event.error = sanitizeV2ToolError(event.error, runtime.sanitizer);
            if (JSON.stringify(event.error) !== beforeErr) {
              recordGuardianRedaction(1, observedDirectory);
            }
          }

          if (controller.signal.aborted) return;

          if (
            event.status === "completed" &&
            event.sessionID &&
            getLatestMeshIntervention(event.sessionID)?.kind === "preflight-blocked"
          ) {
            clearMeshIntervention(event.sessionID);
          }

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
                : typeof current.metadata?.sessionId === "string"
                  ? current.metadata.sessionId
                  : typeof structured?.sessionID === "string"
                    ? structured.sessionID
                    : typeof structured?.sessionId === "string"
                      ? structured.sessionId
                      : undefined;
            const isBackground =
              input.background === true ||
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
              const childDirectory = rememberSessionDirectory(
                childID,
                typeof child.location?.directory === "string" && child.location.directory.trim()
                  ? child.location.directory
                  : observedDirectory
              );
              const childRuntime = runtimeForDirectory(childDirectory);
              const rawChildAgent = (child as { agent?: unknown }).agent;
              const childAgent =
                typeof input.agent === "string" && input.agent.trim().length > 0
                  ? input.agent
                  : typeof rawChildAgent === "string" && rawChildAgent.trim().length > 0
                    ? rawChildAgent.trim()
                    : undefined;
              const revised = childRuntime.config.enabled === false
                ? undefined
                : await finalizeSubagentHandoff({
                sessionID: childID,
                directory: childDirectory,
                engine: childRuntime.engine,
                agentName: childAgent,
                resolveCapability: async () => {
                  const meshProfile = await resolveMeshAgentProfile(childID, childDirectory);
                  if (meshProfile && meshProfile.capability !== "unknown") {
                    const resolved: AgentMutationProfile = {
                      capability: meshProfile.capability,
                      evidence: {
                        agentName: meshProfile.agentName ?? childAgent,
                        reasons: [`mesh:${meshProfile.managedBy}`],
                      },
                    };
                    cacheAgentCapability(childID, resolved);
                    return resolved;
                  }
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
                  if (p.capability !== "unknown") {
                    cacheAgentCapability(childID, p);
                  }
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
                const existingText = extractV2OutputText(current.output, current.content).replace(
                  /\r?\n?<\/subagent>\s*$/i,
                  ""
                );
                const trailingOutcomeLine = /(?:^|\r?\n)(\[TASK OUTCOME\][^\r\n]*)\s*$/.exec(
                  existingText
                )?.[1];
                const finalRevised =
                  trailingOutcomeLine && !revised.includes(trailingOutcomeLine)
                    ? `${revised}\n${trailingOutcomeLine}`
                    : revised;
                event.result = {
                  ...event.result,
                  output: {
                    ...structured,
                    sessionID: childID,
                    status: "completed",
                    output: finalRevised,
                  },
                  content: `<subagent sessionID="${childID}" state="completed">\n${finalRevised}\n</subagent>`,
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
            const beforeRes = JSON.stringify(event.result);
            event.result = sanitizeToolResult(event.result, runtime.sanitizer);
            if (JSON.stringify(event.result) !== beforeRes) {
              recordGuardianRedaction(1, observedDirectory);
            }
          }

          const result = event.status === "completed" ? event.result as {
            output?: unknown; content?: unknown; metadata?: Record<string, unknown>;
          } : undefined;
          verificationStore.observe(event.sessionID, event.id, event.tool,
            input,
            extractV2OutputText(result?.output, result?.content),
            result?.metadata ?? {}, observedDirectory,
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
      toolOutputProtectionReady = true;
    } catch {
      recordGuardianEvent({ kind: "verification-unavailable",
        rules: ["verification-snapshot-unavailable"] }, directory);
      if (sanitizerOpts) {
        controller.abort();
        for (const registration of toolRegistrations.splice(0).reverse()) {
          try { await registration.dispose(); } catch {}
        }
        for (const registration of registrations.splice(0).reverse()) {
          try { await registration.dispose(); } catch {}
        }
        throw new Error("[opencode-guardian secrets] V2 execute.after security hook registration failed; POST redaction cannot be enabled safely.");
      }
    }
    registrations.push(...toolRegistrations);
  }

  if (typeof context.shell?.hook === "function") {
    try {
      const shellBefore = await context.shell.hook("create.before", async (event) => {
        if (controller.signal.aborted) return;
        const eventRecord = event as {
          sessionID?: string;
          command?: unknown;
          cwd?: unknown;
          env?: Record<string, string | undefined>;
          location?: { directory?: string };
        };
        const sid =
          typeof eventRecord.sessionID === "string" && eventRecord.sessionID.trim().length > 0
            ? eventRecord.sessionID
            : typeof eventRecord.env?.OPENCODE_SESSION_ID === "string" &&
                eventRecord.env.OPENCODE_SESSION_ID.trim().length > 0
              ? eventRecord.env.OPENCODE_SESSION_ID
              : undefined;
        const candidateCwd =
          typeof eventRecord.cwd === "string" && eventRecord.cwd.trim().length > 0
            ? eventRecord.cwd
            : undefined;
        const runtimeDirectory = sid
          ? await resolveSessionDirectory(sid)
          : (typeof eventRecord.location?.directory === "string" && eventRecord.location.directory.trim()
              ? eventRecord.location.directory
              : candidateCwd && isDirectoryInGuardianScope(directory, candidateCwd)
                ? candidateCwd
                : directory);
        if (controller.signal.aborted) return;
        const runtime = runtimeForDirectory(runtimeDirectory);
        if (runtime.config.enabled === false) return;
        if (runtime.config.preflight?.enabled === true) {
          inspectPreflight(
            "shell",
            { command: eventRecord.command },
            sid,
            runtimeDirectory,
            runtime.config.preflight?.shellTools,
            toastNotifier,
            runtime.config.preflight?.mode ?? "strict"
          );
        }
      });
      if (!shellBefore || typeof shellBefore.dispose !== "function") {
        throw new Error("V2 shell.create.before hook did not return a valid registration.");
      }
      registrations.push(shellBefore);
    } catch (error) {
      if (strictPreflight) {
        controller.abort();
        for (const registration of registrations.splice(0).reverse()) {
          try { await registration.dispose(); } catch {}
        }
        throw new Error("[opencode-guardian preflight] V2 shell hook registration failed; strict preflight cannot be enabled.", { cause: error });
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
    let auxiliaryRegistrationStarted = false;
    try {
      const promptRegistration = await context.session.hook("prompt", async (event) => {
        if (
          isTrustedGuardianMetadata(event.sessionID, event.metadata, "visible") ||
          isTrustedGuardianMetadata(event.sessionID, event.metadata, "remediation") ||
          isTrustedMeshMessage(event, event.sessionID)
        ) {
          return;
        }
        idleQueue.forget(event.sessionID);
        releaseRemediationLeaseForSession(event.sessionID);
        invalidateActiveMeshHandoff(event.sessionID);
        clearMeshIntervention(event.sessionID);
        foregroundHandoffs.delete(event.sessionID);
        contracts.delete(event.sessionID);
        backgroundSessions.delete(event.sessionID);
        sessionBackgroundJobs.delete(event.sessionID);
        toastNotifier[INTERVENTION_TRACKER]?.noteHumanPrompt(event.sessionID);
        verificationStore.beginTurn(event.sessionID);
        const runtimeDirectory = await resolveSessionDirectory(event.sessionID);
        const runtime = runtimeForDirectory(runtimeDirectory);
        if (runtime.config.enabled === false) {
          return;
        }

        const text = typeof event.prompt?.text === "string" ? event.prompt.text : "";
        if (!text) return;
        const contract = extractTaskContract([{
          info: { id: event.messageID, role: "user" },
          parts: [{ type: "text", text }],
        }]);
        if (contract) setSessionContract(event.sessionID, contract);
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
        const runtimeDirectory = await resolveSessionDirectory(event.sessionID);
        const runtime = runtimeForDirectory(runtimeDirectory);
        if (runtime.config.enabled === false) return runtime;

        if (Array.isArray(event.messages)) {
          event.messages = event.messages.filter((message) =>
            !isTrustedGuardianMetadata(
              event.sessionID,
              (message as { metadata?: unknown }).metadata,
              "visible"
            )
          );
        }

        if (!runtime.sanitizer) return runtime;

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
      for (const kind of ["compaction", "generate", "title"] as const) {
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

      try {
        const expIdleReg = await context.session.hook("experimental.idle", (event) => {
          const bg = (event as { background?: unknown }).background;
          const ownBg = Array.isArray(bg)
            ? bg.filter((job) => {
                if (!job || typeof job !== "object") return true;
                const jobSid = (job as { sessionID?: unknown }).sessionID;
                return typeof jobSid !== "string" || jobSid.length === 0 || jobSid === event.sessionID;
              })
            : [];
          if (ownBg.length > 0) {
            const keys = new Set<string>();
            for (const job of ownBg) {
              const key = backgroundJobKey(job);
              if (key) keys.add(key);
            }
            if (keys.size > 0) {
              sessionBackgroundJobs.delete(event.sessionID);
              sessionBackgroundJobs.set(event.sessionID, keys);
              while (sessionBackgroundJobs.size > 512) {
                const oldest = sessionBackgroundJobs.keys().next().value;
                if (oldest === undefined) break;
                sessionBackgroundJobs.delete(oldest);
              }
            }
            backgroundSessions.delete(event.sessionID);
            backgroundSessions.add(event.sessionID);
            if (backgroundSessions.size > 512) {
              const oldest = backgroundSessions.values().next().value;
              if (oldest !== undefined) backgroundSessions.delete(oldest);
            }
          } else {
            sessionBackgroundJobs.delete(event.sessionID);
            backgroundSessions.delete(event.sessionID);
          }
        });
        if (expIdleReg && typeof expIdleReg.dispose === "function") {
          registrations.push(expIdleReg);
        }
      } catch {
        // Optional v2.3.0+ experimental.idle hook; absent on older/minimal test hosts.
      }
    } catch {
      // Never leave a partial task/security hook group installed.
      await Promise.allSettled(taskRegistrations.map((registration) =>
        Promise.resolve().then(() => registration.dispose())
      ));
      contracts.clear();
      recordGuardianEvent({ kind: "inspection-error" }, directory);
      if (sanitizerOpts || auxiliaryRegistrationStarted) {
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
          sessionID?: string;
          location?: { directory?: string };
          properties?: {
            sessionID?: string;
            id?: string;
            info?: { id?: string };
            status?: { type?: string };
            location?: { directory?: string };
            permissions?: V2PermissionRule[];
            part?: { id?: string; sessionID?: string; type?: string; text?: string };
          };
          data?: {
            sessionID?: string;
            id?: string;
            info?: { id?: string };
            status?: { type?: string };
            location?: { directory?: string };
            permissions?: V2PermissionRule[];
            part?: { id?: string; sessionID?: string; type?: string; text?: string };
          };
        };

        const eventPayload = eventData.data ?? eventData.properties;
        const extractEventSessionID = (): string | undefined =>
          eventData.data?.sessionID ??
          eventData.data?.info?.id ??
          eventData.data?.id ??
          eventData.properties?.sessionID ??
          eventData.properties?.info?.id ??
          eventData.properties?.id ??
          eventData.sessionID;

        streamWatcher.dispatch(event);

        if (eventData.type === "session.created" || eventData.type === "session.forked") {
          const createdSessionID = extractEventSessionID();
          if (createdSessionID) {
            const createdDirectory =
              eventPayload?.location?.directory ?? eventData.location?.directory;
            if (typeof createdDirectory === "string" && createdDirectory.trim()) {
              rememberSessionDirectory(createdSessionID, createdDirectory);
            }
          }
        }

        if (eventData.type === "session.deleted") {
          const deletedSessionID = extractEventSessionID();
          if (deletedSessionID) {
            idleQueue.forget(deletedSessionID);
            streamWatcher.forget(deletedSessionID);
            releaseRemediationLeaseForSession(deletedSessionID);
            toastNotifier.clear?.(deletedSessionID);
            clearInterventionSnapshot(deletedSessionID);
            forgetSessionRuntime(deletedSessionID);
            verificationStore.forget(deletedSessionID);
            backgroundSessions.delete(deletedSessionID);
            sessionBackgroundJobs.delete(deletedSessionID);
            contracts.delete(deletedSessionID);
            foregroundHandoffs.delete(deletedSessionID);
            clearAgentCapability(deletedSessionID);
            forgetGuardianProvenance(deletedSessionID);
            provenanceSessions.delete(deletedSessionID);
          }
          continue;
        }

        if (
          eventData.type === "session.execution.failed" ||
          eventData.type === "session.execution.interrupted"
        ) {
          const failedSessionID = extractEventSessionID();
          if (failedSessionID) {
            idleQueue.forget(failedSessionID);
            backgroundSessions.delete(failedSessionID);
            sessionBackgroundJobs.delete(failedSessionID);
            releaseRemediationLeaseForSession(failedSessionID);
          }
          continue;
        }

        if (eventData.type === "session.permissions") {
          const permissionSessionID = extractEventSessionID();
          if (permissionSessionID) {
            clearAgentCapability(permissionSessionID);
            const perms = eventData.data?.permissions ?? eventData.properties?.permissions;
            if (Array.isArray(perms)) {
              cacheV2SessionPermissions(
                permissionSessionID,
                perms
              );
            }
          }
          continue;
        }

        if (eventData.type === "session.agent.selected") {
          const selectedSessionID = extractEventSessionID();
          if (selectedSessionID) {
            clearAgentCapability(selectedSessionID);
          }
          continue;
        }

        if (eventData.type === "session.moved") {
          const movedSessionID = extractEventSessionID();
          if (movedSessionID) {
            idleQueue.forget(movedSessionID);
            streamWatcher.forget(movedSessionID);
            releaseRemediationLeaseForSession(movedSessionID);
            toastNotifier.clear?.(movedSessionID);
            clearInterventionSnapshot(movedSessionID);
            forgetSessionRuntime(movedSessionID);
            const movedDirectory =
              eventPayload?.location?.directory ?? eventData.location?.directory;
            if (typeof movedDirectory === "string" && movedDirectory.trim()) {
              rememberSessionDirectory(movedSessionID, movedDirectory);
            }
            verificationStore.forget(movedSessionID);
            backgroundSessions.delete(movedSessionID);
            sessionBackgroundJobs.delete(movedSessionID);
            contracts.delete(movedSessionID);
            foregroundHandoffs.delete(movedSessionID);
            clearAgentCapability(movedSessionID);
            forgetGuardianProvenance(movedSessionID);
            provenanceSessions.delete(movedSessionID);
          }
          continue;
        }

        if (eventData.type === "agent.updated" || eventData.type === "plugin.updated") {
          clearAllAgentCapabilities();
          continue;
        }

        if (eventData.type === "experimental.job.updated") {
          const jobInfo = (
            eventPayload as {
              info?: {
                id?: unknown;
                sessionID?: unknown;
                status?: unknown;
                kind?: unknown;
                shellID?: unknown;
                childSessionID?: unknown;
                path?: unknown;
              };
            } | undefined
          )?.info;
          const jobSessionID =
            typeof jobInfo?.sessionID === "string" && jobInfo.sessionID.length > 0
              ? jobInfo.sessionID
              : undefined;
          if (jobSessionID) {
            const jobStatus = typeof jobInfo?.status === "string" ? jobInfo.status : undefined;
            if (jobStatus === "running") {
              const key = backgroundJobKey(jobInfo);
              const set = sessionBackgroundJobs.get(jobSessionID) ?? new Set<string>();
              if (key) set.add(key);
              sessionBackgroundJobs.set(jobSessionID, set);
              backgroundSessions.add(jobSessionID);
            } else if (
              jobStatus === "completed" ||
              jobStatus === "error" ||
              jobStatus === "cancelled"
            ) {
              const set = sessionBackgroundJobs.get(jobSessionID);
              if (set) {
                for (const candidate of [
                  jobInfo?.id,
                  jobInfo?.shellID,
                  jobInfo?.childSessionID,
                  typeof jobInfo?.path === "string" && typeof jobInfo?.kind === "string"
                    ? `${jobInfo.kind}:${jobInfo.path}`
                    : undefined,
                  typeof jobInfo?.path === "string" ? jobInfo.path : undefined,
                  jobInfo?.kind,
                ]) {
                  if (typeof candidate === "string" && candidate.length > 0) {
                    set.delete(candidate);
                  }
                }
                if (set.size === 0) {
                  sessionBackgroundJobs.delete(jobSessionID);
                  backgroundSessions.delete(jobSessionID);
                }
              } else {
                backgroundSessions.delete(jobSessionID);
              }
            }
          }
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
            (eventData.data?.status?.type ?? eventData.properties?.status?.type) === "idle");
        if (!idleEvent) continue;

        const sessionID = extractEventSessionID();
        if (!sessionID) continue;

        foregroundHandoffs.delete(sessionID);

        idleQueue.enqueue(sessionID, async (idleSignal) => {
          foregroundHandoffs.delete(sessionID);
          let activeDirectory = await resolveSessionDirectory(sessionID);
          let sessionIsSubagent: boolean | undefined;
          let sessionParentID: string | undefined;
          let sessionAgentName: string | undefined;
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
              const isForkedSession = Boolean(
                (session as { fork?: unknown }).fork && typeof (session as { fork?: unknown }).fork === "object"
              );
              const isAutomationRunSession = sessionID.startsWith("ses_aut_");
              sessionIsSubagent = (Boolean(sessionParentID) || isAutomationRunSession) && !isForkedSession;
              const rawAgent = (session as { agent?: unknown }).agent;
              if (typeof rawAgent === "string" && rawAgent.trim().length > 0) {
                sessionAgentName = rawAgent.trim();
              }
            }
          } catch {
            // A transient/partial host must not disable the existing idle path.
          }

          if (sessionParentID && sessionIsSubagent !== false && hasForegroundHandoff(foregroundHandoffs, sessionParentID)) {
            return;
          }

          const runtime = runtimeForDirectory(activeDirectory);
          if (runtime.config.enabled === false || idleSignal.aborted) return;

          if (backgroundSessions.has(sessionID)) {
            return;
          }

          let fetchedNormalizedMessages: SessionMessage[] | undefined;
          await handleSessionIdle(
            sessionID,
            activeDirectory,
            async () => {
              const messages = await context.session.context({ sessionID });
              const normalized = normalizeV2Messages(messages, sessionID);
              fetchedNormalizedMessages = normalized;
              const contract = extractTaskContract(normalized);
              if (contract) setSessionContract(sessionID, contract);
              return normalized;
            },
            async (text) => {
              if (idleSignal.aborted) return;
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
          idleSignal,
          sessionIsSubagent,
          (sessionIsSubagent ?? true)
            ? async () => {
                const meshProfile = await resolveMeshAgentProfile(sessionID, activeDirectory);
                if (meshProfile && meshProfile.capability !== "unknown") {
                  const resolved: AgentMutationProfile = {
                    capability: meshProfile.capability,
                    evidence: {
                      agentName: meshProfile.agentName ?? sessionAgentName,
                      reasons: [`mesh:${meshProfile.managedBy}`],
                    },
                  };
                  if (!idleSignal.aborted) cacheAgentCapability(sessionID, resolved);
                  return resolved;
                }
                const cached = getCachedAgentCapability(sessionID);
                if (cached) return cached;
                let agentName = sessionAgentName;
                if (!agentName) {
                  try {
                    const normalized =
                      fetchedNormalizedMessages ??
                      normalizeV2Messages(
                        await context.session.context({ sessionID }),
                        sessionID
                      );
                    agentName = extractAgentNameFromMessages(normalized);
                  } catch {}
                }
                const p = await resolveV2AgentCapability(
                  context,
                  sessionID,
                  agentName,
                  undefined,
                  activeDirectory
                );
                if (!idleSignal.aborted && p.capability !== "unknown") {
                  cacheAgentCapability(sessionID, p);
                }
                return p;
              }
            : undefined,
          toastNotifier
        );
        });
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

  const unregisterGuardianCapability = registerGuardianCapability(directory);
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
    streamWatcher.clear();
    await streamWatcher.drain();
    for (const sessionID of Array.from(activeRemediationLeases.keys())) {
      releaseRemediationLeaseForSession(sessionID);
    }
    contracts.clear();
    verificationStore.clear();
    foregroundHandoffs.clear();
    backgroundSessions.clear();
    sessionBackgroundJobs.clear();
    for (const timer of interventionExpiryTimers.values()) {
      clearTimeout(timer);
    }
    interventionExpiryTimers.clear();
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
      try { await registration.dispose(); } catch {
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
