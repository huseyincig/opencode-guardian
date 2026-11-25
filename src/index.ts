import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Plugin as OpenCodeV2 } from "@opencode/plugin";
import { GuardEngine, loadConfig, resolveEffectiveConfig, type EngineExecutionResult } from "./engine.js";
import type { MessagePart, PreflightMode, SessionMessage } from "./types.js";
import { extractTaskContract, taskGuidance } from "./task-contract.js";
import type { TaskContract } from "./task-contract.js";
import { evaluatePreflight, extractToolAction, GuardianPreflightError, isShellExecutionTool, isFileMutationTool, isProcessStartTool } from "./preflight.js";
import { configureGuardianTelemetry, readGuardianStatus, recordGuardianEvent, recordGuardianRedaction, sessionFingerprint } from "./telemetry.js";
import { guardianResetReport } from "./commands.js";
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
  defaultRuntimeSecrets,
  neutralizeInheritedSerializer,
  resolveSanitizerOptions,
  sanitizeMessages,
  sanitizeObject,
  sanitizeString,
  sanitizeToolResultWithMeta,
} from "./secrets/index.js";
import {
  createGuardianToastNotifier,
  dispatchGuardianToastClear,
  formatGuardianToast,
  type GuardianInterventionDetail,
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
  GUARDIAN_RESET_RPC_METHOD,
  GUARDIAN_STATUS_RPC_METHOD,
  activeGuardianIntervention,
  inactiveGuardianIntervention,
  readGuardianInterventionDirectory,
  readGuardianInterventionSessionID,
} from "./intervention-rpc.js";
import { StreamLoopWatcher } from "./stream-loop.js";
import {
  acquireSessionLease,
  clearMeshIntervention,
  forgetMeshSession,
  getBlockingSessionLease,
  getLatestMeshIntervention,
  invalidateActiveMeshHandoff,
  isTrustedMeshMessage,
  recordMeshIntervention,
  registerMeshStateRpc,
  renewSessionLease,
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

function sanitizeV2ToolErrorWithMeta<T>(
  error: T,
  options: NonNullable<ReturnType<typeof resolveSanitizerOptions>>
): { sanitized: T; redactedCount: number } {
  const fallback = (): { sanitized: T; redactedCount: number } => {
    // Return a plain Error without re-attaching an untrusted prototype that could
    // carry a leaking toJSON() or sensitive getter.
    const safe = new Error("[OUTPUT REDACTED: sanitization failure]");
    return { sanitized: safe as unknown as T, redactedCount: 1 };
  };

  try {
    if (!error || typeof error !== "object") {
      return sanitizeToolResultWithMeta(error, options);
    }
    if (error instanceof Error) {
      const res = sanitizeObject(error, options);
      return { sanitized: res.sanitized, redactedCount: res.redactedCount };
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

    const res = sanitizeObject(snapshot, options);
    if (!res.sanitized || typeof res.sanitized !== "object" || Array.isArray(res.sanitized)) {
      return fallback();
    }

    const proto = Object.getPrototypeOf(error);
    const sanitizedOut = Object.assign(
      proto === null ? Object.create(null) : Object.create(proto),
      res.sanitized
    ) as Record<string, unknown>;
    neutralizeInheritedSerializer(
      sanitizedOut,
      proto,
      options,
      options.replacement ?? "[REDACTED]"
    );
    return {
      sanitized: sanitizedOut as T,
      redactedCount: res.redactedCount,
    };
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
    const recMeta =
      rec.metadata && typeof rec.metadata === "object" && !Array.isArray(rec.metadata)
        ? (rec.metadata as Record<string, unknown>)
        : {};
    const parentErrored =
      normalizedState.status === "error" ||
      normalizedState.status === "aborted" ||
      normalizedState.status === "cancelled" ||
      normalizedState.status === "canceled";
    const explicitNestedStatus = typeof rec.status === "string" ? rec.status : undefined;
    const callStatus =
      explicitNestedStatus ??
      (rec.error !== undefined || recMeta.error === true
        ? "error"
        : normalizedState.status === "running" || normalizedState.status === "pending"
          ? "running"
          : "unknown");
    if (!toolName) continue;
    const callInput =
      rec.input && typeof rec.input === "object" && !Array.isArray(rec.input)
        ? (rec.input as Record<string, unknown>)
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
      rec.error !== undefined ||
      recMeta.error === true ||
      recMeta.status === "running" ||
      recMeta.state === "running" ||
      typeof recMeta.jobID === "string" ||
      typeof recMeta.shellID === "string" ||
      /(?:^|\n)Exit code:\s*\d+/i.test(callOutput) ||
      /(?:^|\n)Command (?:killed by signal|timed out)\b/i.test(callOutput) ||
      /(?:^|\n)(?:Command|Execution)\s+moved to the background\b/i.test(callOutput);
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
          : explicitNestedStatus === "completed" &&
              !parentErrored &&
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

    if (type === "user") {
      const userText =
        typeof msg.text === "string"
          ? msg.text
          : extractV2OutputText(msg.text, msg.content);
      const trustedMesh = isTrustedMeshMessage(msg, sessionID);
      normalized.push({
        info: { id, role: "user" },
        parts: [{
          type: "text",
          text: userText,
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
const MAX_IDLE_LEASE_DURATION_MS = 10 * 60_000;
const activeRemediationLeases = new Map<
  string,
  { release: () => void; heartbeat?: ReturnType<typeof setInterval>; instanceId?: number; leaseToken?: string }
>();

function disposeRemediationLeaseEntry(entry: {
  release: () => void;
  heartbeat?: ReturnType<typeof setInterval>;
}): void {
  if (entry.heartbeat !== undefined) clearInterval(entry.heartbeat);
  try { entry.release(); } catch {}
}

function setRemediationLeaseForSession(
  sessionID: string,
  release: () => void,
  options?: { instanceId?: number; ttlMs?: number; leaseToken?: string }
): void {
  const existing = activeRemediationLeases.get(sessionID);
  if (existing && existing.release !== release) {
    activeRemediationLeases.delete(sessionID);
    disposeRemediationLeaseEntry(existing);
  }
  const ttlMs = options?.ttlMs ?? 45_000;
  const leaseToken = options?.leaseToken;
  const startedAt = Date.now();
  const heartbeat = setInterval(() => {
    if (Date.now() - startedAt >= MAX_IDLE_LEASE_DURATION_MS) {
      releaseRemediationLeaseForSession(sessionID, options?.instanceId, leaseToken);
      return;
    }
    const renewed = renewSessionLease({
      sessionID,
      owner: "opencode-guardian",
      kind: "active_remediation",
      ttlMs,
      ...(leaseToken !== undefined ? { leaseToken } : {}),
    });
    if (!renewed) {
      releaseRemediationLeaseForSession(sessionID, options?.instanceId, leaseToken);
    }
  }, Math.max(50, Math.floor(ttlMs / 3)));
  heartbeat.unref?.();

  activeRemediationLeases.delete(sessionID);
  activeRemediationLeases.set(sessionID, {
    release,
    heartbeat,
    ...(options?.instanceId !== undefined ? { instanceId: options.instanceId } : {}),
    ...(leaseToken !== undefined ? { leaseToken } : {}),
  });
  while (activeRemediationLeases.size > 512) {
    const oldest = activeRemediationLeases.keys().next().value;
    if (oldest === undefined) break;
    const oldEntry = activeRemediationLeases.get(oldest);
    activeRemediationLeases.delete(oldest);
    if (oldEntry) disposeRemediationLeaseEntry(oldEntry);
  }
}

function releaseRemediationLeaseForSession(
  sessionID: string,
  ownerInstanceId?: number,
  expectedLeaseToken?: string
): void {
  const existing = activeRemediationLeases.get(sessionID);
  if (!existing) return;
  if (ownerInstanceId !== undefined && existing.instanceId !== ownerInstanceId) return;
  if (expectedLeaseToken !== undefined && existing.leaseToken !== expectedLeaseToken) return;
  activeRemediationLeases.delete(sessionID);
  disposeRemediationLeaseEntry(existing);
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

function buildInterventionDetails(
  results: readonly EngineExecutionResult["results"][number][]
): GuardianInterventionDetail[] {
  const details: GuardianInterventionDetail[] = [];
  for (const item of results) {
    for (const finding of item.findings) {
      details.push({
        ruleId: finding.ruleId || item.ruleId,
        ...(finding.pattern ? { pattern: finding.pattern } : {}),
        ...(finding.description ? { description: finding.description } : {}),
        ...(finding.filePath ? { filePath: finding.filePath } : {}),
        ...(finding.confidence ? { confidence: finding.confidence } : {}),
      });
    }
  }
  return details;
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
    clearMeshIntervention(sessionID, "opencode-guardian");
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
    clearMeshIntervention(sessionID, "opencode-guardian");
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
      details: buildInterventionDetails(findings),
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

export async function finalizeSubagentHandoff(input: {
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
  onRemediated?: (() => void) | undefined;
  leaseTtlMs?: number | undefined;
  remediationTimeoutMs?: number | undefined;
  interrupt?: (() => Promise<unknown> | void) | undefined;
}): Promise<string | undefined> {
  let remediated = false;

  for (let round = 0; round < MAX_SUBAGENT_HANDOFF_ROUNDS; round++) {
    if (input.signal?.aborted) {
      throw new Error("[opencode-guardian handoff] plugin teardown interrupted subagent finalization.");
    }

    // Re-evaluate capability on every round so mid-handoff permission/agent revocations
    // immediately block subsequent autonomous remediation dispatches (cache-backed when unchanged).
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
        result.rollback?.();
        return latestAssistantText(messages);
      }
      if (getBlockingSessionLease(input.sessionID, "active_remediation", "opencode-guardian")) {
        result.rollback?.();
        return latestAssistantText(messages);
      }
      if (round === MAX_SUBAGENT_HANDOFF_ROUNDS - 1) {
        result.rollback?.();
        clearMeshIntervention(input.sessionID, "opencode-guardian");
        throw new Error("[opencode-guardian handoff] remediation did not converge before the safety limit.");
      }
      const leaseTtlMs =
        typeof input.leaseTtlMs === "number" && Number.isFinite(input.leaseTtlMs) && input.leaseTtlMs > 0
          ? input.leaseTtlMs
          : 45_000;
      const remediationTimeoutMs =
        typeof input.remediationTimeoutMs === "number" && Number.isFinite(input.remediationTimeoutMs) && input.remediationTimeoutMs > 0
          ? input.remediationTimeoutMs
          : 10 * 60_000;
      const releaseRemediationLease = acquireSessionLease({
        sessionID: input.sessionID,
        owner: "opencode-guardian",
        kind: "active_remediation",
        ttlMs: leaseTtlMs,
        reason: "guardian-subagent-remediation",
      });
      const heartbeatMs = Math.max(30, Math.floor(leaseTtlMs / 3));
      const leaseHeartbeat = setInterval(() => {
        if (input.signal?.aborted) return;
        const renewed = renewSessionLease({
          sessionID: input.sessionID,
          owner: "opencode-guardian",
          kind: "active_remediation",
          ttlMs: leaseTtlMs,
          leaseToken: releaseRemediationLease.leaseToken,
        });
        if (!renewed) {
          clearInterval(leaseHeartbeat);
        }
      }, heartbeatMs);
      leaseHeartbeat.unref?.();
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
      let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
      let onAbortHandler: (() => void) | undefined;
      let settled = false;
      const awaitInterruptGrace = async (): Promise<void> => {
        if (!input.interrupt) return;
        let graceTimer: ReturnType<typeof setTimeout> | undefined;
        try {
          await Promise.race([
            Promise.resolve().then(() => input.interrupt?.()).catch(() => {}),
            new Promise<void>((r) => {
              graceTimer = setTimeout(r, 500);
            }),
          ]);
        } finally {
          if (graceTimer !== undefined) clearTimeout(graceTimer);
        }
      };
      try {
        if (input.signal?.aborted) {
          throw new Error("[opencode-guardian handoff] plugin teardown interrupted subagent remediation.");
        }
        const waitPromise = Promise.resolve().then(() => input.sendAndWait(result.combinedRemediationPrompt!));
        waitPromise.catch(() => {});
        const guardedWait = new Promise<void>((resolve, reject) => {
          deadlineTimer = setTimeout(() => {
            if (settled) return;
            settled = true;
            void awaitInterruptGrace().finally(() => {
              reject(new Error("[opencode-guardian handoff] subagent remediation exceeded deadline."));
            });
          }, remediationTimeoutMs);
          onAbortHandler = () => {
            if (settled) return;
            settled = true;
            void awaitInterruptGrace().finally(() => {
              reject(new Error("[opencode-guardian handoff] plugin teardown interrupted subagent remediation."));
            });
          };
          if (input.signal?.aborted) {
            onAbortHandler();
            return;
          }
          input.signal?.addEventListener("abort", onAbortHandler, { once: true });
          waitPromise.then(
            () => {
              if (settled) return;
              settled = true;
              resolve();
            },
            (err) => {
              if (settled) return;
              settled = true;
              reject(err);
            }
          );
        });
        await guardedWait;
        remediated = true;
        input.onRemediated?.();
        recordGuardianEvent({
          kind: "post-remediation",
          session: sessionFingerprint(input.sessionID),
          rules: findings.map((item) => item.ruleId),
          reasons: auditReasons(findings),
        }, input.directory);
        input.toastNotifier?.notify({
          kind: "remediation",
          ruleIds: findings.map((item) => item.ruleId),
          details: buildInterventionDetails(findings),
          sessionID: input.sessionID,
        });
      } catch {
        result.rollback?.();
        clearMeshIntervention(input.sessionID, "opencode-guardian");
        recordGuardianEvent({
          kind: "inspection-error",
          session: sessionFingerprint(input.sessionID),
          rules: ["prompt-delivery-failed"],
          reasons: [{ rule: "prompt-delivery-failed", code: "prompt-delivery-failed" }],
        }, input.directory);
        throw new Error("[opencode-guardian handoff] could not complete subagent remediation.");
      } finally {
        clearInterval(leaseHeartbeat);
        if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
        if (onAbortHandler && input.signal) {
          input.signal.removeEventListener("abort", onAbortHandler);
        }
        releaseRemediationLease();
      }
      continue;
    }

    if (result.remediationStatus === "failed") {
      clearMeshIntervention(input.sessionID, "opencode-guardian");
      throw new Error("[opencode-guardian handoff] unresolved Guardian findings; subagent result withheld.");
    }

    const latest = latestAssistantText(messages);
    if (remediated && !latest) {
      clearMeshIntervention(input.sessionID, "opencode-guardian");
      throw new Error("[opencode-guardian handoff] remediated subagent produced no final text result.");
    }
    return latest;
  }

  clearMeshIntervention(input.sessionID, "opencode-guardian");
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
  const activeIDs = new Set<string>();
  let anonymousRunning = 0;

  for (const msg of turn) {
    for (const part of msg.parts) {
      // OpenCode V2 background subagent completion notices arrive as synthetic
      // user text messages with metadata: { source: "subagent", childID, state }.
      if (part.type === "text" && part.synthetic === true) {
        const rawMeta = (part as { metadata?: unknown }).metadata;
        const meta =
          rawMeta && typeof rawMeta === "object" && !Array.isArray(rawMeta)
            ? (rawMeta as Record<string, unknown>)
            : undefined;
        if (meta?.source === "subagent") {
          const childID =
            typeof meta.childID === "string" && meta.childID.length > 0
              ? meta.childID
              : typeof meta.childSessionID === "string" && meta.childSessionID.length > 0
                ? meta.childSessionID
                : typeof meta.sessionID === "string" && meta.sessionID.length > 0
                  ? meta.sessionID
                  : undefined;
          const subState = meta.state ?? meta.status;
          if (childID) {
            if (subState === "running") {
              activeIDs.add(childID);
            } else {
              activeIDs.delete(childID);
            }
          }
        }
        continue;
      }

      if (part.type !== "tool" || !part.state) continue;
      const meta = part.state.metadata;
      const outputText = typeof part.state.output === "string" ? part.state.output : "";
      const toolName =
        typeof part.tool === "string"
          ? part.tool
          : typeof part.name === "string"
            ? part.name
            : undefined;
      const isSubagentTool = toolName === "subagent";
      const subagentChildID = isSubagentTool
        ? (typeof meta?.childSessionID === "string" && meta.childSessionID.length > 0
            ? meta.childSessionID
            : typeof meta?.childID === "string" && meta.childID.length > 0
              ? meta.childID
              : typeof meta?.sessionID === "string" && meta.sessionID.length > 0
                ? meta.sessionID
                : undefined)
        : undefined;
      const shellID = typeof meta?.shellID === "string" ? meta.shellID : undefined;
      const jobID = typeof meta?.jobID === "string" ? meta.jobID : undefined;
      const id =
        subagentChildID ??
        shellID ??
        jobID ??
        (typeof part.callID === "string" ? part.callID : undefined);
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
        if (id) activeIDs.add(id);
        else anonymousRunning += 1;
      } else if (id && (part.state.status === "completed" || part.state.status === "error")) {
        activeIDs.delete(id);
      }
    }
  }

  return anonymousRunning > 0 || activeIDs.size > 0;
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
  toastNotifier?: GuardianToastNotifier | undefined,
  ownerInstanceId?: number | undefined
): Promise<void> {
  let stage: "message-fetch" | "engine-inspect" | "prompt-send" = "message-fetch";
  let acquiredLeaseToken: string | undefined;
  try {
    if (signal?.aborted) return;
    if (getBlockingSessionLease(sessionID, "active_remediation", "opencode-guardian")) {
      return;
    }
    const messages = await fetchMessages();
    if (signal?.aborted) return;
    if (hasUnfinishedBackgroundTool(messages)) return;
    const lastAssistantID = messages.findLast((m) => m.info.role === "assistant")?.info.id;
    if (lastAssistantID && wasMessageInspectedInProcess(sessionID, lastAssistantID)) {
      return;
    }
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
    const rollbackProcessInspect =
      lastAssistantID && result.results.length > 0
        ? recordMessageInspectedInProcess(sessionID, lastAssistantID, directory)
        : undefined;
    const findings = recordInspectionOutcome(result, sessionID, directory, toastNotifier);

    if (result.decision === "block" && result.combinedRemediationPrompt) {
      if (effectiveIsSubagent && agentCapability !== "write-allowed") {
        releaseRemediationLeaseForSession(sessionID, ownerInstanceId);
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
      releaseRemediationLeaseForSession(sessionID, ownerInstanceId);
      const releaseRemediationLease = acquireSessionLease({
        sessionID,
        owner: "opencode-guardian",
        kind: "active_remediation",
        ttlMs: 45_000,
        reason: "guardian-remediation",
      });
      acquiredLeaseToken = releaseRemediationLease.leaseToken;
      setRemediationLeaseForSession(sessionID, releaseRemediationLease, {
        ...(ownerInstanceId !== undefined ? { instanceId: ownerInstanceId } : {}),
        ttlMs: 45_000,
        leaseToken: acquiredLeaseToken,
      });
      try {
        if (signal?.aborted) {
          releaseRemediationLeaseForSession(sessionID, ownerInstanceId, acquiredLeaseToken);
          result.rollback?.();
          rollbackProcessInspect?.();
          clearMeshIntervention(sessionID, "opencode-guardian");
          return;
        }
        await sendPrompt(result.combinedRemediationPrompt);
        if (signal?.aborted) {
          releaseRemediationLeaseForSession(sessionID, ownerInstanceId, acquiredLeaseToken);
          return;
        }
        recordGuardianEvent({ kind: "post-remediation", session: sessionFingerprint(sessionID), rules: findings.map((item) => item.ruleId), reasons: auditReasons(findings) }, directory);
        toastNotifier?.notify({
          kind: "remediation",
          ruleIds: findings.map((item) => item.ruleId),
          details: buildInterventionDetails(findings),
          sessionID,
        });
      } catch (promptError) {
        releaseRemediationLeaseForSession(sessionID, ownerInstanceId, acquiredLeaseToken);
        result.rollback?.();
        rollbackProcessInspect?.();
        clearMeshIntervention(sessionID, "opencode-guardian");
        throw promptError;
      }
    } else if (result.results.length > 0) {
      releaseRemediationLeaseForSession(sessionID, ownerInstanceId);
    }
  } catch {
    if (acquiredLeaseToken !== undefined) {
      releaseRemediationLeaseForSession(sessionID, ownerInstanceId, acquiredLeaseToken);
    }
    if (signal?.aborted) return;
    if (acquiredLeaseToken === undefined) {
      releaseRemediationLeaseForSession(sessionID, ownerInstanceId);
    }
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
  mode: PreflightMode = "strict",
  secretOptions?: import("./secrets/types.js").SanitizerOptions
): void {
  if (!isShellExecutionTool(tool, additionalTools) && !isFileMutationTool(tool) && !isProcessStartTool(tool)) return;
  const finding = evaluatePreflight(tool, args, additionalTools, mode, secretOptions);
  const session = sessionFingerprint(sessionID);
  const safeTool = extractToolAction(tool);
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
    clearMeshIntervention(sessionID, "opencode-guardian");
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
  const MAX_BYTES = 256 * 1024;
  for (const name of ["opencode.json", "opencode.jsonc"]) {
    const candidate = path.join(dir, name);
    let fd: number | undefined;
    try {
      fd = fs.openSync(
        candidate,
        fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0)
      );
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.size > MAX_BYTES) continue;
      const buf = Buffer.alloc(stat.size);
      const read = fs.readSync(fd, buf, 0, stat.size, 0);
      const raw = buf.toString("utf8", 0, read);
      if (raw.includes("opencode-guardian") && !raw.includes("-opencode-guardian")) {
        return true;
      }
    } catch {
      // Ignore missing, unreadable, symlinked, or non-regular config files.
    } finally {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch {}
      }
    }
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

const GUARDIAN_PROCESS_REGISTRY_SYMBOL = Symbol.for("opencode.guardian.runtime.v2");
const INFLIGHT_IDLE_TTL_MS = 60_000;
const MAX_TRACKED_PROCESS_SESSIONS = 512;

interface GuardianInstanceEntry {
  id: number;
  directory: string;
  canonicalDir: string;
}

interface GuardianProcessRegistry {
  nextInstanceId: number;
  nextIdleSlotToken?: number;
  activeInstances: Map<number, GuardianInstanceEntry>;
  inflightIdle: Map<string, { instanceId: number; startedAt: number; token: number }>;
  inspectedMessages: Map<string, { messageID: string; canonicalDir: string }>;
}

function getGuardianProcessRegistry(): GuardianProcessRegistry {
  const g = globalThis as Record<symbol, unknown>;
  let reg = g[GUARDIAN_PROCESS_REGISTRY_SYMBOL] as GuardianProcessRegistry | undefined;
  if (!reg || typeof reg !== "object" || !(reg.activeInstances instanceof Map)) {
    reg = {
      nextInstanceId: 0,
      activeInstances: new Map(),
      inflightIdle: new Map(),
      inspectedMessages: new Map(),
    };
    g[GUARDIAN_PROCESS_REGISTRY_SYMBOL] = reg;
  }
  return reg;
}

function registerGuardianInstance(directory: string): {
  id: number;
  canonicalDir: string;
  unregister: () => void;
} {
  const reg = getGuardianProcessRegistry();
  const id = ++reg.nextInstanceId;
  const canonicalDir = realpathLoose(directory);
  reg.activeInstances.set(id, { id, directory, canonicalDir });
  return {
    id,
    canonicalDir,
    unregister: () => {
      reg.activeInstances.delete(id);
      for (const [sid, entry] of reg.inflightIdle.entries()) {
        if (entry.instanceId === id) reg.inflightIdle.delete(sid);
      }
      let hasRemainingForDir = false;
      for (const inst of reg.activeInstances.values()) {
        if (inst.canonicalDir === canonicalDir) {
          hasRemainingForDir = true;
          break;
        }
      }
      if (!hasRemainingForDir) {
        for (const [sid, entry] of reg.inspectedMessages.entries()) {
          if (entry.canonicalDir === canonicalDir) {
            reg.inspectedMessages.delete(sid);
          }
        }
      }
    },
  };
}

/**
 * Ensures exactly one active Guardian instance in a multi-location OpenCode
 * server process owns global event-stream work for a target directory.
 */
function isGuardianOwnerForDirectory(
  instanceId: number,
  startupDirectory: string,
  targetDirectory: string
): boolean {
  if (!isDirectoryInGuardianScope(startupDirectory, targetDirectory)) {
    return false;
  }
  const reg = getGuardianProcessRegistry();
  if (reg.activeInstances.size <= 1) {
    return true;
  }
  const canonicalTarget = realpathLoose(targetDirectory);

  // Tier 1: exact location match (newest active instance wins on reload overlap)
  let exactWinner = -1;
  for (const inst of reg.activeInstances.values()) {
    if (inst.canonicalDir === canonicalTarget && inst.id > exactWinner) {
      exactWinner = inst.id;
    }
  }
  if (exactWinner !== -1) {
    return instanceId === exactWinner;
  }

  // Tier 2: deepest enclosing parent location match
  let parentWinner = -1;
  let parentLen = -1;
  for (const inst of reg.activeInstances.values()) {
    if (isSameOrSubdirectory(canonicalTarget, inst.canonicalDir)) {
      const len = inst.canonicalDir.length;
      if (len > parentLen || (len === parentLen && inst.id > parentWinner)) {
        parentLen = len;
        parentWinner = inst.id;
      }
    }
  }
  if (parentWinner !== -1) {
    return instanceId === parentWinner;
  }

  // Tier 3: single deterministic fallback among global-scope instances
  let scopeWinner = -1;
  for (const inst of reg.activeInstances.values()) {
    if (isDirectoryInGuardianScope(inst.directory, targetDirectory) && inst.id > scopeWinner) {
      scopeWinner = inst.id;
    }
  }
  return scopeWinner === -1 || instanceId === scopeWinner;
}

function acquireProcessIdleSlot(sessionID: string, instanceId: number): (() => void) | undefined {
  const reg = getGuardianProcessRegistry();
  const now = Date.now();
  const existing = reg.inflightIdle.get(sessionID);
  if (existing && existing.instanceId !== instanceId && now - existing.startedAt < INFLIGHT_IDLE_TTL_MS) {
    return undefined;
  }
  const token = (reg.nextIdleSlotToken = (reg.nextIdleSlotToken ?? 0) + 1);
  reg.inflightIdle.delete(sessionID);
  reg.inflightIdle.set(sessionID, { instanceId, startedAt: now, token });
  while (reg.inflightIdle.size > MAX_TRACKED_PROCESS_SESSIONS) {
    const oldest = reg.inflightIdle.keys().next().value;
    if (oldest === undefined) break;
    reg.inflightIdle.delete(oldest);
  }
  return () => {
    const current = reg.inflightIdle.get(sessionID);
    if (current?.token === token) {
      reg.inflightIdle.delete(sessionID);
    }
  };
}

function wasMessageInspectedInProcess(sessionID: string, messageID: string): boolean {
  return getGuardianProcessRegistry().inspectedMessages.get(sessionID)?.messageID === messageID;
}

function recordMessageInspectedInProcess(
  sessionID: string,
  messageID: string,
  directory: string
): () => void {
  const reg = getGuardianProcessRegistry();
  const previous = reg.inspectedMessages.get(sessionID);
  const canonicalDir = realpathLoose(directory);
  reg.inspectedMessages.delete(sessionID);
  reg.inspectedMessages.set(sessionID, { messageID, canonicalDir });
  while (reg.inspectedMessages.size > MAX_TRACKED_PROCESS_SESSIONS) {
    const oldest = reg.inspectedMessages.keys().next().value;
    if (oldest === undefined) break;
    reg.inspectedMessages.delete(oldest);
  }
  return () => {
    if (reg.inspectedMessages.get(sessionID)?.messageID === messageID) {
      if (previous) reg.inspectedMessages.set(sessionID, previous);
      else reg.inspectedMessages.delete(sessionID);
    }
  };
}

function forgetProcessSession(sessionID: string): void {
  const reg = getGuardianProcessRegistry();
  reg.inflightIdle.delete(sessionID);
  reg.inspectedMessages.delete(sessionID);
}

const setup: OpenCodeV2.Plugin["setup"] = async (
  context: OpenCodeV2.Context
) => {
  // Transition builds may call setup() with a partial v2 context.
  // Resolve the explicit security setting first: strict preflight must never
  // silently disappear merely because another v2 capability is unavailable.
  const directory = context?.location?.directory ?? process.cwd();
  defaultRuntimeSecrets.refreshEnv();
  const mergedConfig = resolveEffectiveConfig(loadConfig(directory), context.options);
  if (mergedConfig.enabled === false) {
    configureGuardianTelemetry(directory, mergedConfig.telemetry, "setup-disabled");
    recordGuardianEvent({ kind: "runtime-started", runtime: "v2", preflight: "disabled" }, directory);
    configureGuardianTelemetry(directory, undefined, "setup-disabled");
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
    if (strictPreflight) {
      throw new Error("[opencode-guardian preflight] V2 host context is unavailable; strict preflight cannot be enabled.");
    }
    if (sanitizerOpts) {
      throw new Error("[opencode-guardian secrets] V2 host context is unavailable; secret protection cannot be enabled safely.");
    }
    return;
  }

  const MAX_BOUNDED_DIRECTORIES = 64;
  const HARD_MAX_BOUNDED_DIRECTORIES = 128;
  const setBoundedDirectoryEntry = <T>(map: Map<string, T>, key: string, value: T, protectedDirs?: ReadonlySet<string>): void => {
    map.delete(key);
    map.set(key, value);
    if (map.size <= MAX_BOUNDED_DIRECTORIES) return;
    for (const candidate of map.keys()) {
      if (map.size <= MAX_BOUNDED_DIRECTORIES) break;
      if (candidate === directory || candidate === key || protectedDirs?.has(candidate)) continue;
      map.delete(candidate);
      if (map === (runtimeByDirectory as unknown)) {
        configureGuardianTelemetry(candidate, undefined, instanceId);
      }
    }
    if (map.size <= HARD_MAX_BOUNDED_DIRECTORIES) return;
    for (const candidate of map.keys()) {
      if (map.size <= HARD_MAX_BOUNDED_DIRECTORIES) break;
      if (candidate === directory || candidate === key) continue;
      map.delete(candidate);
      if (map === (runtimeByDirectory as unknown)) {
        configureGuardianTelemetry(candidate, undefined, instanceId);
      }
    }
  };
  const runtimeByDirectory = new Map<string, {
    config: typeof mergedConfig;
    sanitizer: ReturnType<typeof resolveSanitizerOptions>;
    engine: GuardEngine;
  }>();
  const controller = new AbortController();
  const instanceRegistration = registerGuardianInstance(directory);
  const instanceId = instanceRegistration.id;
  configureGuardianTelemetry(directory, mergedConfig.telemetry, instanceId);
  controller.signal.addEventListener("abort", () => {
    instanceRegistration.unregister();
    configureGuardianTelemetry(directory, undefined, instanceId);
    for (const key of runtimeByDirectory.keys()) {
      configureGuardianTelemetry(key, undefined, instanceId);
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
  let toolPreflightReady = false;
  let toolAfterReady = false;
  const shellHookAvailable = typeof context.shell?.hook === "function";
  let shellPreflightReady = false;
  const isPreflightReady = (): boolean =>
    toolPreflightReady && (!shellHookAvailable || shellPreflightReady);
  const runtimeForDirectory = (runtimeDirectory: string) => {
    const key = runtimeDirectory || directory;
    const cached = runtimeByDirectory.get(key);
    if (
      cached &&
      (cached.config.enabled === false ||
        ((!cached.sanitizer || (toolOutputProtectionReady && modelRequestProtectionReady)) &&
          (cached.config.preflight?.enabled !== true || isPreflightReady())))
    ) {
      return cached;
    }
    if (!isDirectoryInGuardianScope(directory, key)) {
      const disabledConfig: typeof mergedConfig = { ...mergedConfig, enabled: false };
      const disabledRuntime = {
        config: disabledConfig,
        sanitizer: null,
        engine: new GuardEngine(disabledConfig),
      };
      setBoundedDirectoryEntry(runtimeByDirectory, key, disabledRuntime, new Set(sessionDirectories.values()));
      return disabledRuntime;
    }
    const config = cached?.config ?? resolveEffectiveConfig(loadConfig(key), context.options);
    configureGuardianTelemetry(key, config.telemetry, instanceId);
    const runtime = cached ?? {
      config,
      sanitizer: resolveSanitizerOptions(config),
      engine: new GuardEngine(config),
    };
    if (config.enabled !== false && runtime.sanitizer &&
        (!toolOutputProtectionReady || !modelRequestProtectionReady)) {
      throw new Error("[opencode-guardian secrets] Required V2 security hooks are unavailable for this project; secret protection cannot be enabled safely.");
    }
    if (config.enabled !== false && config.preflight?.enabled === true && !isPreflightReady()) {
      throw new Error("[opencode-guardian preflight] Required V2 preflight hooks are unavailable for this project; strict preflight cannot be enabled.");
    }
    setBoundedDirectoryEntry(runtimeByDirectory, key, runtime, new Set(sessionDirectories.values()));
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
  const resolveSessionDirectoryDetailed = async (
    sessionID: string
  ): Promise<{ directory: string; verified: boolean }> => {
    const cached = sessionDirectories.get(sessionID);
    if (cached) return { directory: cached, verified: true };
    if (typeof context.session.get !== "function") {
      return { directory, verified: true };
    }
    try {
      const session = await context.session.get({ sessionID });
      const sessionDirectory = session.location?.directory;
      if (typeof sessionDirectory === "string" && sessionDirectory.trim()) {
        return { directory: rememberSessionDirectory(sessionID, sessionDirectory), verified: true };
      }
      return { directory, verified: true };
    } catch {
      // Do not cache the startup project or pretend an unverified lookup belongs to startup scope.
      return { directory, verified: false };
    }
  };
  const forgetSessionRuntime = (sessionID: string): void => {
    for (const runtime of runtimeByDirectory.values()) {
      runtime.engine.forgetSession(sessionID);
    }
    sessionDirectories.delete(sessionID);
  };

  const verificationStore = new VerificationSnapshotStore();
  const BACKGROUND_JOB_STALE_TTL_MS = 10 * 60_000;
  const backgroundSessions = new Set<string>();
  const sessionBackgroundJobs = new Map<string, Map<string, number>>();
  const pruneStaleBackgroundJobs = (sessionID: string, now = Date.now()): void => {
    const jobs = sessionBackgroundJobs.get(sessionID);
    if (!jobs) return;
    for (const [jobKey, updatedAt] of jobs.entries()) {
      if (now - updatedAt > BACKGROUND_JOB_STALE_TTL_MS) {
        jobs.delete(jobKey);
      }
    }
    if (jobs.size === 0) {
      sessionBackgroundJobs.delete(sessionID);
      backgroundSessions.delete(sessionID);
    }
  };
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
    // Prefer shared semantic identifiers present in both SessionIdleBackground
    // (experimental.idle) and Job.Info (experimental.job.updated) so both
    // sources reconcile to the exact same key for every v2.4.x job kind.
    if (typeof rec.jobID === "string" && rec.jobID.length > 0) return rec.jobID;
    if (typeof rec.shellID === "string" && rec.shellID.length > 0) return rec.shellID;
    if (typeof rec.childSessionID === "string" && rec.childSessionID.length > 0) return rec.childSessionID;
    if (typeof rec.id === "string" && rec.id.length > 0) return rec.id;
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
            const resolved = await resolveSessionDirectoryDetailed(sessionID);
            if (isProjectLocalPluginInstall(directory) && !resolved.verified) {
              return inactiveGuardianIntervention();
            }
            if (!isDirectoryInGuardianScope(directory, resolved.directory)) {
              return inactiveGuardianIntervention();
            }
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
              const resolved = await resolveSessionDirectoryDetailed(sessionID);
              if (
                (isProjectLocalPluginInstall(directory) && !resolved.verified) ||
                !isDirectoryInGuardianScope(directory, resolved.directory)
              ) {
                return { cleared: false };
              }
              clearMeshIntervention(sessionID, "opencode-guardian");
              toastNotifier.clear?.(sessionID);
              return { cleared: true };
            }
            const rpcContext = rest[0] as { location?: { directory?: unknown } } | undefined;
            const contextDir =
              typeof rpcContext?.location?.directory === "string" && rpcContext.location.directory.trim()
                ? rpcContext.location.directory
                : undefined;
            const targetDirectory =
              contextDir ?? readGuardianInterventionDirectory(input) ?? directory;
            if (!isDirectoryInGuardianScope(directory, targetDirectory)) {
              return { cleared: false };
            }
            for (const activeSessionID of Array.from(interventionSnapshots.keys())) {
              const cachedDir = sessionDirectories.get(activeSessionID);
              let sessionDir = cachedDir;
              if (!sessionDir) {
                const resolved = await resolveSessionDirectoryDetailed(activeSessionID);
                if (isProjectLocalPluginInstall(directory) && !resolved.verified) continue;
                sessionDir = resolved.directory;
              }
              if (sessionDir === targetDirectory) {
                clearMeshIntervention(activeSessionID, "opencode-guardian");
                toastNotifier.clear?.(activeSessionID);
              }
            }
            for (const [knownSessionID, knownDir] of sessionDirectories.entries()) {
              if (knownDir === targetDirectory) {
                clearMeshIntervention(knownSessionID, "opencode-guardian");
              }
            }
            dispatchGuardianToastClear({ directory: targetDirectory });
            return { cleared: true };
          },
          [GUARDIAN_STATUS_RPC_METHOD]: async (input, ...rest: unknown[]) => {
            const rpcContext = rest[0] as { location?: { directory?: unknown } } | undefined;
            const contextDir =
              typeof rpcContext?.location?.directory === "string" && rpcContext.location.directory.trim()
                ? rpcContext.location.directory
                : undefined;
            const targetDirectory =
              contextDir ?? readGuardianInterventionDirectory(input) ?? directory;
            if (!isDirectoryInGuardianScope(directory, targetDirectory)) {
              return { ok: false };
            }
            return { ok: true, status: readGuardianStatus(targetDirectory) };
          },
          [GUARDIAN_RESET_RPC_METHOD]: async (input, ...rest: unknown[]) => {
            const rpcContext = rest[0] as { location?: { directory?: unknown } } | undefined;
            const contextDir =
              typeof rpcContext?.location?.directory === "string" && rpcContext.location.directory.trim()
                ? rpcContext.location.directory
                : undefined;
            const targetDirectory =
              contextDir ?? readGuardianInterventionDirectory(input) ?? directory;
            if (!isDirectoryInGuardianScope(directory, targetDirectory)) {
              return {
                ok: false,
                title: "Guardian: Reset Statistics",
                message: "Reset failed: target project is outside Guardian scope.",
              };
            }
            const report = guardianResetReport(targetDirectory);
            const ok = !report.message.startsWith("Reset failed");
            return { ok, title: report.title, message: report.message };
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
      detailed:
        runtime.config.enabled !== false &&
        runtime.config.notifications?.transcript === true,
      sanitizer: runtime.sanitizer,
    });
    setBoundedDirectoryEntry(toastNotifiersByDirectory, key, notifier, new Set(sessionDirectories.values()));
    return notifier;
  };
  const toastNotifier: TrackedGuardianToastNotifier = createTrackedToastNotifier({
    notify(input): void {
      const runtimeDirectory =
        typeof input.sessionID === "string"
          ? sessionDirectories.get(input.sessionID) ?? directory
          : directory;
      if (
        typeof input.sessionID === "string" &&
        input.sessionID.length > 0
      ) {
        try {
          const sid = input.sessionID;
          clearInterventionSnapshot(sid);
          const runtime = runtimeForDirectory(runtimeDirectory);
          const detailed =
            runtime.config.enabled !== false &&
            runtime.config.notifications?.transcript === true;
          // OpenCode V2 `session.synthetic` always enqueues into `session_inbox`
          // and triggers an LLM turn on the next drain (even with `resume: false`).
          // Deliver detailed per-finding notices exclusively via the TUI
          // `session.composer.top` intervention snapshot + RPC channel so
          // conversation history and provider turns are never mutated.
          const payload = formatGuardianToast(
            input,
            detailed ? { detailed: true, sanitizer: runtime.sanitizer } : undefined
          );
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
      const resolved = await resolveSessionDirectoryDetailed(sessionID);
      const targetDirectory = resolved.directory;
      if (
        (isProjectLocalPluginInstall(directory) && !resolved.verified) ||
        !isGuardianOwnerForDirectory(instanceId, directory, targetDirectory)
      ) {
        return { config: { enabled: false }, directory: targetDirectory };
      }
      const rt = runtimeForDirectory(targetDirectory);
      return { config: rt.config, directory: targetDirectory };
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
  const hasConcreteHostRestriction = (profile: AgentMutationProfile): boolean => {
    const restrictedEffect = (effect?: string) =>
      effect === "deny" || effect === "disabled" || effect === "restricted";
    return (
      restrictedEffect(profile.evidence.edit) ||
      restrictedEffect(profile.evidence.bash) ||
      (profile.evidence.unknownTools?.length ?? 0) > 0 ||
      profile.evidence.reasons.some((r) => /agent\.list.*failed|agent-list-failed|host-denied/i.test(r))
    );
  };
  const projectLocalInstall = isProjectLocalPluginInstall(directory);
  if (typeof context.tool?.hook === "function") {
    const toolRegistrations: Array<{ dispose(): Promise<void> | void }> = [];
    const canFinalizeSubagent =
      typeof context.session.get === "function" &&
      typeof context.session.context === "function" &&
      typeof context.session.synthetic === "function" &&
      typeof context.session.wait === "function";
    const toolCallStartedAt = new Map<string, number>();
    {
      try {
        const before = await context.tool.hook("execute.before", async (event) => {
          if (controller.signal.aborted) return;
          const resolvedDir = await resolveSessionDirectoryDetailed(event.sessionID);
          if (controller.signal.aborted) return;
          if (projectLocalInstall && !resolvedDir.verified) return;
          const runtimeDirectory = resolvedDir.directory;
          if (!isDirectoryInGuardianScope(directory, runtimeDirectory)) return;
          const runtime = runtimeForDirectory(runtimeDirectory);
          if (runtime.config.enabled === false) return;
          if (event.id) {
            toolCallStartedAt.set(event.id, Date.now());
            while (toolCallStartedAt.size > 512) {
              const oldest = toolCallStartedAt.keys().next().value;
              if (oldest === undefined) break;
              toolCallStartedAt.delete(oldest);
            }
          }
          if (runtime.config.preflight?.enabled === true) {
            inspectPreflight(
              event.tool,
              event.input,
              event.sessionID,
              runtimeDirectory,
              runtime.config.preflight?.shellTools,
              toastNotifier,
              runtime.config.preflight?.mode ?? "strict",
              runtime.config.secrets?.enabled === false ? undefined : (runtime.sanitizer ?? undefined)
            );
          }

          if (toolAfterReady && event.input && typeof event.input === "object" && !Array.isArray(event.input)) {
            verificationStore.observeBefore(event.sessionID, event.id, event.tool,
              event.input as Record<string, unknown>, runtimeDirectory);
          }

          if (toolAfterReady && canFinalizeSubagent && event.tool === "subagent") {
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
        toolPreflightReady = true;
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
          const resolvedDir = await resolveSessionDirectoryDetailed(event.sessionID);
          if (projectLocalInstall && !resolvedDir.verified) return;
          const observedDirectory = resolvedDir.directory;
          if (!isDirectoryInGuardianScope(directory, observedDirectory)) return;
          const runtime = runtimeForDirectory(observedDirectory);
          if (runtime.config.enabled === false) return;

          if (runtime.sanitizer && event.status === "error") {
            const { sanitized, redactedCount } = sanitizeV2ToolErrorWithMeta(event.error, runtime.sanitizer);
            event.error = sanitized;
            if (redactedCount > 0) {
              recordGuardianRedaction(1, observedDirectory);
            }
          }

          if (controller.signal.aborted) return;

          const callStartMs = event.id ? toolCallStartedAt.get(event.id) : undefined;
          if (event.id) toolCallStartedAt.delete(event.id);
          const activeIntervention = event.sessionID ? getLatestMeshIntervention(event.sessionID) : undefined;
          if (
            event.status === "completed" &&
            event.sessionID &&
            activeIntervention?.kind === "preflight-blocked" &&
            (callStartMs === undefined || callStartMs >= activeIntervention.updatedAt)
          ) {
            clearMeshIntervention(event.sessionID, "opencode-guardian");
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
                typeof rawChildAgent === "string" && rawChildAgent.trim().length > 0
                  ? rawChildAgent.trim()
                  : typeof input.agent === "string" && input.agent.trim().length > 0
                    ? input.agent.trim()
                    : undefined;
              let subagentRemediated = false;
              const revised = childRuntime.config.enabled === false
                ? undefined
                : await finalizeSubagentHandoff({
                sessionID: childID,
                directory: childDirectory,
                engine: childRuntime.engine,
                agentName: childAgent,
                onRemediated: () => {
                  subagentRemediated = true;
                },
                resolveCapability: async () => {
                  const cached = getCachedAgentCapability(childID);
                  if (cached) return cached;
                  const meshProfile = await resolveMeshAgentProfile(childID, childDirectory);
                  if (meshProfile && meshProfile.capability === "read-only") {
                    const resolved: AgentMutationProfile = {
                      capability: "read-only",
                      evidence: {
                        agentName: meshProfile.agentName ?? childAgent,
                        reasons: [`mesh:${meshProfile.managedBy}`],
                      },
                    };
                    cacheAgentCapability(childID, resolved);
                    return resolved;
                  }
                  let liveSessionAgent: string | undefined;
                  if (typeof context.session.get === "function") {
                    try {
                      const liveChild = await context.session.get({ sessionID: childID });
                      const rawLiveAgent = (liveChild as { agent?: unknown } | undefined)?.agent;
                      if (typeof rawLiveAgent === "string" && rawLiveAgent.trim().length > 0) {
                        liveSessionAgent = rawLiveAgent.trim();
                      }
                    } catch {}
                  }
                  let resolvedName = liveSessionAgent ?? childAgent ?? meshProfile?.agentName;
                  if (!resolvedName) {
                    try {
                      const ctxMsgs = normalizeV2Messages(
                        await context.session.context({ sessionID: childID }),
                        childID
                      );
                      resolvedName = extractAgentNameFromMessages(ctxMsgs);
                    } catch {}
                  }
                  const hostProfile = await resolveV2AgentCapability(
                    context,
                    childID,
                    resolvedName,
                    undefined,
                    childDirectory
                  );
                  if (
                    hostProfile.capability === "read-only" ||
                    hostProfile.capability === "write-requires-approval"
                  ) {
                    cacheAgentCapability(childID, hostProfile);
                    return hostProfile;
                  }
                  if (
                    meshProfile &&
                    meshProfile.capability === "write-allowed" &&
                    !hasConcreteHostRestriction(hostProfile)
                  ) {
                    const resolved: AgentMutationProfile = {
                      capability: "write-allowed",
                      evidence: {
                        agentName: resolvedName,
                        reasons: [`mesh:${meshProfile.managedBy}`, ...hostProfile.evidence.reasons],
                      },
                    };
                    cacheAgentCapability(childID, resolved);
                    return resolved;
                  }
                  if (hostProfile.capability !== "unknown") {
                    cacheAgentCapability(childID, hostProfile);
                  }
                  return hostProfile;
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
                interrupt:
                  typeof context.session.interrupt === "function"
                    ? () => context.session.interrupt!({ sessionID: childID, resume: false })
                    : undefined,
              });

              if (revised !== undefined) {
                const lastNonEmptyLine = (text: string): string => {
                  const trimmed = text.trimEnd();
                  const nl = trimmed.lastIndexOf("\n");
                  return (nl >= 0 ? trimmed.slice(nl + 1) : trimmed).replace(/\r$/, "").trim();
                };
                const existingText = extractV2OutputText(current.output, current.content).replace(
                  /\r?\n?<\/subagent>\s*$/i,
                  ""
                );
                const revisedLastLine = lastNonEmptyLine(revised);
                const revisedHasOutcome = /^\[TASK OUTCOME\]/i.test(revisedLastLine);
                const existingLastLine = lastNonEmptyLine(existingText);
                const trailingOutcomeLine = !subagentRemediated && !revisedHasOutcome && /^\[TASK OUTCOME\]/i.test(existingLastLine)
                  ? existingLastLine
                  : undefined;
                const finalRevised = trailingOutcomeLine
                  ? `${revised}\n${trailingOutcomeLine}`
                  : revised;
                const TERMINAL_SUBAGENT_STATUSES = new Set([
                  "completed",
                  "blocked",
                  "failed",
                  "partial",
                  "needs_input",
                  "cancelled",
                ]);
                const finalLastLine = lastNonEmptyLine(finalRevised);
                const rawOutcomeStatus = /^\[TASK OUTCOME\][^\r\n]*\bstatus=([a-z_-]+)\b/i.exec(
                  finalLastLine
                )?.[1]?.toLowerCase();
                const outcomeStatus =
                  rawOutcomeStatus && TERMINAL_SUBAGENT_STATUSES.has(rawOutcomeStatus)
                    ? rawOutcomeStatus
                    : undefined;
                const existingStatus =
                  typeof structured?.status === "string" && structured.status.trim().length > 0
                    ? structured.status.trim()
                    : typeof current.metadata?.status === "string" && current.metadata.status.trim().length > 0
                      ? current.metadata.status.trim()
                      : undefined;
                const safeExistingStatus =
                  existingStatus && TERMINAL_SUBAGENT_STATUSES.has(existingStatus.toLowerCase())
                    ? existingStatus
                    : undefined;
                const finalStatus = outcomeStatus ?? (subagentRemediated ? "completed" : (safeExistingStatus ?? "completed"));
                event.result = {
                  ...event.result,
                  output: {
                    ...structured,
                    sessionID: childID,
                    status: finalStatus,
                    output: finalRevised,
                  },
                  content: `<subagent sessionID="${childID}" state="${finalStatus}">\n${finalRevised}\n</subagent>`,
                  metadata: {
                    ...current.metadata,
                    sessionID: childID,
                    status: finalStatus,
                  },
                };
              }
            }
          }

          // Foreground child finalization can replace the tool result with new
          // text. Sanitize only after that rewrite so the parent never receives
          // an unsanitized revised child result.
          if (runtime.sanitizer && event.status === "completed") {
            const { sanitized, redactedCount } = sanitizeToolResultWithMeta(event.result, runtime.sanitizer);
            event.result = sanitized;
            if (redactedCount > 0) {
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
      toolAfterReady = true;
    } catch {
      recordGuardianEvent({ kind: "verification-unavailable",
        rules: ["verification-snapshot-unavailable"] }, directory);
      if (sanitizerOpts) {
        controller.abort();
        toolPreflightReady = false;
        for (const registration of toolRegistrations.splice(0).reverse()) {
          try { await registration.dispose(); } catch {}
        }
        for (const registration of registrations.splice(0).reverse()) {
          try { await registration.dispose(); } catch {}
        }
        throw new Error("[opencode-guardian secrets] V2 execute.after security hook registration failed; POST redaction cannot be enabled safely.");
      }
      if (!strictPreflight) {
        toolPreflightReady = false;
        for (const registration of toolRegistrations.splice(0).reverse()) {
          try { await registration.dispose(); } catch {}
        }
      }
    }
    registrations.push(...toolRegistrations);
  }

  if (shellHookAvailable) {
    try {
      const shellBefore = await context.shell!.hook("create.before", async (event) => {
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
        let runtimeDirectory: string;
        if (sid) {
          const resolvedDir = await resolveSessionDirectoryDetailed(sid);
          if (projectLocalInstall && !resolvedDir.verified) return;
          runtimeDirectory = resolvedDir.directory;
        } else {
          runtimeDirectory =
            typeof eventRecord.location?.directory === "string" && eventRecord.location.directory.trim()
              ? eventRecord.location.directory
              : candidateCwd && isDirectoryInGuardianScope(directory, candidateCwd)
                ? candidateCwd
                : directory;
        }
        if (controller.signal.aborted) return;
        if (!isDirectoryInGuardianScope(directory, runtimeDirectory)) return;
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
      shellPreflightReady = true;
    } catch (error) {
      if (strictPreflight) {
        controller.abort();
        for (const registration of registrations.splice(0).reverse()) {
          try { await registration.dispose(); } catch {}
        }
        throw new Error("[opencode-guardian preflight] V2 shell hook registration failed; strict preflight cannot be enabled.", { cause: error });
      }
    }
  } else if (strictPreflight) {
    recordGuardianEvent({
      kind: "verification-unavailable",
      rules: ["shell-preflight-unavailable"],
      reasons: [{ rule: "shell-preflight-unavailable", code: "shell-preflight-unavailable" }],
    }, directory);
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
        const hadQueuedIdle = idleQueue.has(event.sessionID);
        const resolvedDir = await resolveSessionDirectoryDetailed(event.sessionID);
        if (isProjectLocalPluginInstall(directory) && !resolvedDir.verified) {
          return;
        }
        const runtimeDirectory = resolvedDir.directory;
        if (!isGuardianOwnerForDirectory(instanceId, directory, runtimeDirectory)) {
          return;
        }
        const runtime = runtimeForDirectory(runtimeDirectory);
        if (runtime.config.enabled === false) {
          return;
        }
        if (hadQueuedIdle) idleQueue.forget(event.sessionID);
        releaseRemediationLeaseForSession(event.sessionID, instanceId);
        invalidateActiveMeshHandoff(event.sessionID);
        clearMeshIntervention(event.sessionID, "opencode-guardian");
        foregroundHandoffs.delete(event.sessionID);
        contracts.delete(event.sessionID);
        pruneStaleBackgroundJobs(event.sessionID);
        if (!sessionBackgroundJobs.has(event.sessionID)) {
          backgroundSessions.delete(event.sessionID);
        }
        toastNotifier[INTERVENTION_TRACKER]?.noteHumanPrompt(event.sessionID);
        verificationStore.beginTurn(event.sessionID);

        const text = typeof event.prompt?.text === "string" ? event.prompt.text : "";
        if (!text) return;
        const contract = extractTaskContract([{
          info: { id: event.messageID, role: "user" },
          parts: [{ type: "text", text }],
        }], event.sessionID);
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
      }): Promise<ReturnType<typeof runtimeForDirectory> | undefined> => {
        const resolved = await resolveSessionDirectoryDetailed(event.sessionID);
        if (projectLocalInstall && !resolved.verified) return undefined;
        const runtimeDirectory = resolved.directory;
        if (!isDirectoryInGuardianScope(directory, runtimeDirectory)) return undefined;
        const runtime = runtimeForDirectory(runtimeDirectory);
        if (runtime.config.enabled === false) return runtime;

        if (Array.isArray(event.messages)) {
          const filtered = event.messages.filter((message) =>
            !isTrustedGuardianMetadata(
              event.sessionID,
              (message as { metadata?: unknown }).metadata,
              "visible"
            )
          );
          const lastBefore = event.messages[event.messages.length - 1] as { role?: unknown } | undefined;
          const lastAfter = filtered[filtered.length - 1] as { role?: unknown } | undefined;
          if (!(lastBefore?.role !== "assistant" && lastAfter?.role === "assistant")) {
            event.messages = filtered;
          }
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
        if (!runtime || runtime.config.enabled === false) return;
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
            const now = Date.now();
            const keys = new Map<string, number>();
            for (const job of ownBg) {
              const key = backgroundJobKey(job) ?? "__anonymous__";
              keys.set(key, now);
            }
            sessionBackgroundJobs.delete(event.sessionID);
            sessionBackgroundJobs.set(event.sessionID, keys);
            while (sessionBackgroundJobs.size > 512) {
              const oldest = sessionBackgroundJobs.keys().next().value;
              if (oldest === undefined) break;
              sessionBackgroundJobs.delete(oldest);
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
    let activeEvents: AsyncIterable<unknown> | undefined = events;
    // A terminated stream must never disable session inspection silently.
    // Retry a bounded number of consecutive failures (resetting after a healthy
    // run of >= 30s) and keep strict tool hooks registered.
    const HEALTHY_STREAM_RESET_MS = 30_000;
    for (let attempt = 0; attempt < 3 && !controller.signal.aborted; attempt++) {
      const streamStartedAt = Date.now();
      try {
        if (!activeEvents) {
          const next = context.event.subscribe({ signal: controller.signal });
          if (!next || typeof next[Symbol.asyncIterator] !== "function") {
            throw new Error("V2 event resubscription did not return an async iterable.");
          }
          activeEvents = next;
        }
        for await (const event of activeEvents) {
        if (controller.signal.aborted) break;
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

        const eventLocationDir =
          typeof eventPayload?.location?.directory === "string" && eventPayload.location.directory.trim()
            ? eventPayload.location.directory
            : typeof eventData.location?.directory === "string" && eventData.location.directory.trim()
              ? eventData.location.directory
              : undefined;

        if (!eventLocationDir || isGuardianOwnerForDirectory(instanceId, directory, eventLocationDir)) {
          streamWatcher.dispatch(event);
        }

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
            forgetProcessSession(deletedSessionID);
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
            forgetMeshSession(deletedSessionID);
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
            foregroundHandoffs.delete(failedSessionID);
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
            forgetProcessSession(movedSessionID);
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
                jobID?: unknown;
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
              const now = Date.now();
              const key = backgroundJobKey(jobInfo) ?? "__anonymous__";
              const jobs = sessionBackgroundJobs.get(jobSessionID) ?? new Map<string, number>();
              jobs.delete(key);
              jobs.set(key, now);
              while (jobs.size > 128) {
                const oldestKey = jobs.keys().next().value;
                if (oldestKey === undefined) break;
                jobs.delete(oldestKey);
              }
              sessionBackgroundJobs.delete(jobSessionID);
              sessionBackgroundJobs.set(jobSessionID, jobs);
              while (sessionBackgroundJobs.size > 512) {
                const oldest = sessionBackgroundJobs.keys().next().value;
                if (oldest === undefined) break;
                sessionBackgroundJobs.delete(oldest);
              }
              backgroundSessions.delete(jobSessionID);
              backgroundSessions.add(jobSessionID);
              while (backgroundSessions.size > 512) {
                const oldest = backgroundSessions.values().next().value;
                if (oldest === undefined) break;
                backgroundSessions.delete(oldest);
              }
            } else if (
              jobStatus === "completed" ||
              jobStatus === "error" ||
              jobStatus === "cancelled"
            ) {
              const set = sessionBackgroundJobs.get(jobSessionID);
              if (set) {
                const specificCandidates = [
                  jobInfo?.jobID,
                  jobInfo?.shellID,
                  jobInfo?.childSessionID,
                  jobInfo?.id,
                ];
                let deletedSpecific = false;
                for (const candidate of specificCandidates) {
                  if (typeof candidate === "string" && candidate.length > 0 && set.delete(candidate)) {
                    deletedSpecific = true;
                  }
                }
                if (!deletedSpecific) {
                  for (const candidate of [
                    backgroundJobKey(jobInfo),
                    typeof jobInfo?.path === "string" && typeof jobInfo?.kind === "string"
                      ? `${jobInfo.kind}:${jobInfo.path}`
                      : undefined,
                    typeof jobInfo?.path === "string" ? jobInfo.path : undefined,
                    jobInfo?.kind,
                    "__anonymous__",
                  ]) {
                    if (typeof candidate === "string" && candidate.length > 0) {
                      set.delete(candidate);
                    }
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
          defaultRuntimeSecrets.refreshEnv();
          clearAllAgentCapabilities();
          for (const [runtimeKey, existing] of Array.from(runtimeByDirectory.entries())) {
            try {
              if (!isDirectoryInGuardianScope(directory, runtimeKey)) {
                runtimeByDirectory.delete(runtimeKey);
                configureGuardianTelemetry(runtimeKey, undefined, instanceId);
                continue;
              }
              const nextConfig = resolveEffectiveConfig(loadConfig(runtimeKey), context.options);
              configureGuardianTelemetry(runtimeKey, nextConfig.telemetry, instanceId);
              existing.config = nextConfig;
              existing.sanitizer = resolveSanitizerOptions(nextConfig);
              existing.engine.updateConfig(nextConfig);
            } catch {
              // Keep previous engine state intact, but record a visible audit error so operators know reload was rejected.
              recordGuardianEvent({
                kind: "inspection-error",
                rules: ["config-reload-failed"],
                reasons: [{ rule: "config-reload-failed", code: "config-reload-failed" }],
              }, runtimeKey);
            }
          }
          toastNotifiersByDirectory.clear();
          continue;
        }

        const idleEvent =
          eventData.type === "session.idle" ||
          eventData.type === "session.execution.succeeded" ||
          (eventData.type === "session.status" &&
            (eventData.data?.status?.type ?? eventData.properties?.status?.type) === "idle");
        if (!idleEvent) continue;

        const sessionID = extractEventSessionID();
        if (!sessionID) continue;

        if (eventLocationDir && !isGuardianOwnerForDirectory(instanceId, directory, eventLocationDir)) {
          continue;
        }

        idleQueue.enqueue(sessionID, async (idleSignal) => {
          let activeDirectory: string;
          let directoryVerified = true;
          if (eventLocationDir) {
            activeDirectory = rememberSessionDirectory(sessionID, eventLocationDir);
          } else {
            const resolvedDir = await resolveSessionDirectoryDetailed(sessionID);
            activeDirectory = resolvedDir.directory;
            directoryVerified = resolvedDir.verified;
          }
          if (!directoryVerified) {
            return;
          }
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

          if (!isGuardianOwnerForDirectory(instanceId, directory, activeDirectory)) {
            return;
          }

          if (sessionParentID && sessionIsSubagent !== false && hasForegroundHandoff(foregroundHandoffs, sessionParentID)) {
            return;
          }

          const runtime = runtimeForDirectory(activeDirectory);
          if (runtime.config.enabled === false || idleSignal.aborted) return;

          pruneStaleBackgroundJobs(sessionID);
          if (backgroundSessions.has(sessionID)) {
            return;
          }

          const releaseProcessIdleSlot = acquireProcessIdleSlot(sessionID, instanceId);
          if (!releaseProcessIdleSlot) {
            return;
          }

          let fetchedNormalizedMessages: SessionMessage[] | undefined;
          try {
            await handleSessionIdle(
              sessionID,
              activeDirectory,
              async () => {
                const messages = await context.session.context({ sessionID });
                const normalized = normalizeV2Messages(messages, sessionID);
                fetchedNormalizedMessages = normalized;
                const contract = extractTaskContract(normalized, sessionID);
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
                    const cached = getCachedAgentCapability(sessionID);
                    if (cached) return cached;
                    const meshProfile = await resolveMeshAgentProfile(sessionID, activeDirectory);
                    if (meshProfile && meshProfile.capability === "read-only") {
                      const resolved: AgentMutationProfile = {
                        capability: "read-only",
                        evidence: {
                          agentName: meshProfile.agentName ?? sessionAgentName,
                          reasons: [`mesh:${meshProfile.managedBy}`],
                        },
                      };
                      if (!idleSignal.aborted) cacheAgentCapability(sessionID, resolved);
                      return resolved;
                    }
                    let agentName = sessionAgentName ?? meshProfile?.agentName;
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
                    const hostProfile = await resolveV2AgentCapability(
                      context,
                      sessionID,
                      agentName,
                      undefined,
                      activeDirectory
                    );
                    if (
                      hostProfile.capability === "read-only" ||
                      hostProfile.capability === "write-requires-approval"
                    ) {
                      if (!idleSignal.aborted) cacheAgentCapability(sessionID, hostProfile);
                      return hostProfile;
                    }
                    if (
                    meshProfile &&
                    meshProfile.capability === "write-allowed" &&
                    !hasConcreteHostRestriction(hostProfile)
                  ) {
                      const resolved: AgentMutationProfile = {
                        capability: "write-allowed",
                        evidence: {
                          agentName,
                          reasons: [`mesh:${meshProfile.managedBy}`, ...hostProfile.evidence.reasons],
                        },
                      };
                      if (!idleSignal.aborted) cacheAgentCapability(sessionID, resolved);
                      return resolved;
                    }
                    if (!idleSignal.aborted && hostProfile.capability !== "unknown") {
                      cacheAgentCapability(sessionID, hostProfile);
                    }
                    return hostProfile;
                  }
                : undefined,
              toastNotifier,
              instanceId
            );
          } finally {
            releaseProcessIdleSlot();
          }
        });
        }
        if (controller.signal.aborted) return;
        throw new Error("V2 event stream ended before plugin teardown.");
      } catch {
        activeEvents = undefined;
        if (controller.signal.aborted) return;
        recordGuardianEvent({ kind: "inspection-error",
          rules: ["v2-event-stream-error"],
          reasons: [{ rule: "v2-event-stream-error", code: "v2-event-stream-error" }],
        }, directory);
        // Record only the redacted error; never write host exceptions to the TUI.
      }

      if (Date.now() - streamStartedAt >= HEALTHY_STREAM_RESET_MS) {
        attempt = -1;
        continue;
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
      releaseRemediationLeaseForSession(sessionID, instanceId);
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
