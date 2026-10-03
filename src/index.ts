import type { Plugin as OpenCodeV1ServerPlugin } from "@opencode-ai/plugin";
import type { Plugin as OpenCodeV2 } from "@opencode/plugin";
import { GuardEngine, loadConfig } from "./engine.js";
import type { MessagePart, SessionMessage } from "./types.js";
import { extractTaskContract, taskGuidance } from "./task-contract.js";
import type { TaskContract } from "./task-contract.js";
import { evaluatePreflight, GuardianPreflightError, isShellExecutionTool } from "./preflight.js";
import { recordGuardianEvent, sessionFingerprint } from "./telemetry.js";
import { announceGuardianUpdate } from "./version-notice.js";
import { createV1TurnWatcher } from "./v1-turn-watcher.js";

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
export * from "./version-notice.js";
export * from "./v1-turn-watcher.js";

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
  const normalizedState: NonNullable<MessagePart["state"]> = {
    status: typeof state.status === "string" ? state.status : undefined,
    input:
      state.input && typeof state.input === "object"
        ? (state.input as Record<string, unknown>)
        : undefined,
    error: state.error,
    metadata:
      state.metadata && typeof state.metadata === "object"
        ? (state.metadata as Record<string, unknown>)
        : undefined,
    exitCode: state.exitCode,
    raw: state.raw,
  };

  const output =
    typeof state.output === "string"
      ? state.output
      : stringifyV2ToolContent(state.content);
  if (output) normalizedState.output = output;

  return {
    type: "tool",
    tool: typeof value.name === "string" ? value.name : undefined,
    name: typeof value.name === "string" ? value.name : undefined,
    state: normalizedState,
  };
}

/**
 * Converts OpenCode v2 session.context() records into the stable internal
 * message shape consumed by the rules and engine.
 */
export function normalizeV2Messages(messages: readonly unknown[]): SessionMessage[] {
  const normalized: SessionMessage[] = [];

  for (const raw of messages) {
    if (!raw || typeof raw !== "object") continue;
    const msg = raw as Record<string, unknown>;
    const id = typeof msg.id === "string" ? msg.id : undefined;
    const type = typeof msg.type === "string" ? msg.type : undefined;
    if (!id || !type) continue;

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
        .filter((part): part is MessagePart => part !== null);

      normalized.push({
        info: {
          id,
          role: "assistant",
          agent: typeof msg.agent === "string" ? msg.agent : undefined,
        },
        parts,
      });
    }
  }

  return normalized;
}

/**
 * Common handler to process session.idle events across v1 and v2.
 */
async function handleSessionIdle(
  sessionID: string,
  directory: string,
  fetchMessages: () => Promise<SessionMessage[]>,
  sendPrompt: (promptText: string) => Promise<void>,
  engine: GuardEngine
): Promise<void> {
  try {
    const messages = await fetchMessages();
    const result = await engine.inspect(sessionID, directory, messages);
    const findings = result.results.filter((item) => item.findings.length > 0);
    if (findings.length && !(result.decision === "block" && result.combinedRemediationPrompt)) {
      recordGuardianEvent({ kind: "post-warning", session: sessionFingerprint(sessionID), rules: findings.map((item) => item.ruleId) }, directory);
    }

    if (result.decision === "block" && result.combinedRemediationPrompt) {
      try {
        await sendPrompt(result.combinedRemediationPrompt);
        recordGuardianEvent({ kind: "post-remediation", session: sessionFingerprint(sessionID), rules: findings.map((item) => item.ruleId) }, directory);
      } catch (promptError) {
        result.rollback?.();
        throw promptError;
      }
    }
  } catch (error) {
    recordGuardianEvent({ kind: "inspection-error", session: sessionFingerprint(sessionID) }, directory);
    console.error("[opencode-guardian] Inspection error:", error);
  }
}

/** Records only recognized shell calls and a rule code, never raw commands. */
function inspectPreflight(
  tool: string, args: unknown, sessionID?: string, directory?: string,
  additionalTools: readonly string[] = []
): void {
  if (!isShellExecutionTool(tool, additionalTools)) return;
  const finding = evaluatePreflight(tool, args, additionalTools);
  recordGuardianEvent({
    kind: finding ? "preflight-blocked" : "preflight-allowed",
    session: sessionFingerprint(sessionID),
    tool: tool.toLowerCase().split(/[.:/]/).at(-1),
    ...(finding ? { rules: [finding] } : {}),
  }, directory);
  if (finding) throw new GuardianPreflightError(finding);
}

const server: OpenCodeV1ServerPlugin = async ({ client, directory }) => {
  const config = loadConfig(directory);
  if (config.enabled === false) {
    recordGuardianEvent({ kind: "runtime-started", runtime: "v1", preflight: "disabled" }, directory);
    // Preserve the V1 hook shape without inspecting turns or injecting context.
    return {
      "chat.message": async () => {},
      "experimental.chat.system.transform": async () => {},
      event: async () => {},
    };
  }
  const engine = new GuardEngine(config);
  const contracts = new Map<string, TaskContract>();
  let promptSequence = 0;
  let updateChecked = false;
  const strictPreflight = config.preflight?.enabled === true;
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
        const contract = extractTaskContract(messages);
        if (contract) contracts.set(sessionID, contract);
        await handleSessionIdle(
          sessionID, directory, async () => messages,
          async (text) => {
            await client.session.promptAsync({
              path: { id: sessionID }, query: { directory },
              body: { parts: [{ type: "text", text }] },
            });
          },
          engine
        );
      },
      onError: (sessionID, error) => {
        recordGuardianEvent({ kind: "inspection-error", session: sessionFingerprint(sessionID) }, directory);
        console.error("[opencode-guardian] V1 idle compatibility probe failed:", error);
      },
    })
    : undefined;
  recordGuardianEvent({ kind: "runtime-started", runtime: "v1", preflight: strictPreflight ? "active" : "disabled" }, directory);

  return {
    dispose: async () => {
      watcher?.stopAll();
      contracts.clear();
    },
    ...(strictPreflight ? {
      "tool.execute.before": async (
        input: { tool: string; sessionID?: string }, output: { args: unknown }
      ) => inspectPreflight(input.tool, output.args, input.sessionID, directory, config.preflight?.shellTools),
    } : {}),
    "chat.message": async (input, output) => {
      const text = output.parts
        .map((part) => part.type === "text" ? part.text : "")
        .join("\n");
      if (!text) return;
      if (!text.trimStart().startsWith("[opencode-guardian remediation]")) {
        const contract = extractTaskContract([{
          info: { id: input.messageID ?? ("v1-prompt-" + (++promptSequence)), role: "user" },
          parts: [{ type: "text", text }],
        }]);
        if (contract) contracts.set(input.sessionID, contract);
      }
      watcher?.watch(input.sessionID);
    },
    "experimental.chat.system.transform": async (input, output) => {
      if (!input.sessionID) return;
      const contract = contracts.get(input.sessionID);
      if (!contract) return;
      const guidance = taskGuidance(contract);
      if (guidance && !output.system.includes(guidance)) {
        output.system.push(guidance);
      }
    },
    event: async ({ event }) => {
      const eventData = event as {
        type?: string;
        properties?: { sessionID?: string };
        data?: { sessionID?: string; info?: { id?: string } };
      };

      if (eventData.type === "session.created" && !updateChecked && config.updateNotice?.enabled !== false) {
        updateChecked = true;
        const tui = (client as unknown as { tui?: { showToast?: (input: { body: { title: string; message: string; variant: "info"; duration: number } }) => Promise<unknown> } }).tui;
        if (typeof tui?.showToast === "function") {
          void announceGuardianUpdate((current, latest) => tui.showToast!({
            body: { title: "OpenCode Guardian — New version", message: `v${current} → v${latest} (update manually)`, variant: "info", duration: 5000 },
          }));
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
          contracts.delete(deletedSessionID);
        }
        return;
      }

      if (eventData.type !== "session.idle") return;
      const sessionID =
        eventData.properties?.sessionID ?? eventData.data?.sessionID;
      if (!sessionID) return;
      watcher?.stop(sessionID);

      await handleSessionIdle(
        sessionID,
        directory,
        async () => {
          const res = await client.session.messages({
            path: { id: sessionID },
            query: { directory },
          });
          const messages = (Array.isArray(res) ? res : (res?.data ?? [])) as SessionMessage[];
          const contract = extractTaskContract(messages);
          if (contract) contracts.set(sessionID, contract);
          return messages;
        },
        async (text: string) => {
          await client.session.promptAsync({
            path: { id: sessionID },
            query: { directory },
            body: { parts: [{ type: "text", text }] },
          });
        },
        engine
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
  const config = loadConfig(directory);
  if (config.enabled === false) {
    recordGuardianEvent({ kind: "runtime-started", runtime: "v2", preflight: "disabled" }, directory);
    return;
  }
  const strictPreflight = config.preflight?.enabled === true;
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
    return;
  }

  const controller = new AbortController();
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
      controller.abort();
      if (strictPreflight) {
        throw new Error("[opencode-guardian preflight] V2 event subscription is unavailable; strict preflight cannot be enabled.");
      }
      return;
    }
    events = candidate as AsyncIterable<unknown>;
  } catch (error) {
    controller.abort();
    if (strictPreflight) {
      throw new Error("[opencode-guardian preflight] V2 event subscription failed; strict preflight cannot be enabled.", { cause: error });
    }
    return;
  }

  const engine = new GuardEngine(config);
  const contracts = new Map<string, TaskContract>();
  const registrations: Array<{ dispose(): Promise<void> | void }> = [];

  if (strictPreflight) {
    // An explicitly requested security hook must never be silently skipped.
    if (typeof context.tool?.hook !== "function") {
      controller.abort();
      throw new Error("[opencode-guardian preflight] V2 tool.execute.before hook is unavailable; strict preflight cannot be enabled.");
    }
    try {
      const registration = await context.tool.hook("execute.before", (event) => {
        inspectPreflight(event.tool, event.input, event.sessionID, directory, config.preflight?.shellTools);
      });
      if (!registration || typeof registration.dispose !== "function") {
        throw new Error("V2 tool hook did not return a valid registration.");
      }
      registrations.push(registration);
    } catch (error) {
      controller.abort();
      throw new Error("[opencode-guardian preflight] V2 tool hook registration failed; strict preflight cannot be enabled.", { cause: error });
    }
  }

  if (typeof context.session.hook === "function") {
    const taskRegistrations: Array<{ dispose(): Promise<void> | void }> = [];
    try {
      const promptRegistration = await context.session.hook("prompt", (event) => {
        const text = event.prompt.text;
        if (!text || text.trimStart().startsWith("[opencode-guardian remediation]")) {
          return;
        }
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
      const contextRegistration = await context.session.hook("context", (event) => {
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
      registrations.push(...taskRegistrations);
    } catch (error) {
      // Beta hosts may support only one hook. Undo partial registration now,
      // rather than leaving an orphaned prompt hook until plugin shutdown.
      await Promise.allSettled(taskRegistrations.map((registration) =>
        Promise.resolve().then(() => registration.dispose())
      ));
      contracts.clear();
      console.error("[opencode-guardian] V2 task hooks unavailable:", error);
    }
  }

  const eventLoop = async () => {
    let activeEvents = events;
    // A terminated stream must never disable session inspection silently.
    // Retry a bounded number of times and keep strict tool hooks registered.
    for (let attempt = 0; attempt < 3 && !controller.signal.aborted; attempt++) {
      try {
        for await (const event of activeEvents) {
        const eventData = event as {
          type?: string;
          data?: { sessionID?: string; info?: { id?: string } };
        };

        if (eventData.type === "session.deleted") {
          const deletedSessionID =
            eventData.data?.sessionID ?? eventData.data?.info?.id;
          if (deletedSessionID) {
            engine.forgetSession(deletedSessionID);
            contracts.delete(deletedSessionID);
          }
          continue;
        }

        if (eventData.type !== "session.idle") continue;
        const sessionID = eventData.data?.sessionID;
        if (!sessionID) continue;

        let sessionDirectory: string = directory;
        try {
          if (typeof context.session.get === "function") {
            const session = await context.session.get({ sessionID });
            sessionDirectory = session.location?.directory ?? directory;
          }
        } catch {
          // A transient/partial host must not disable the existing idle path.
        }

        await handleSessionIdle(
          sessionID,
          sessionDirectory,
          async () => {
            const messages = await context.session.context({ sessionID });
            const normalized = normalizeV2Messages(messages);
            const contract = extractTaskContract(normalized);
            if (contract) contracts.set(sessionID, contract);
            return normalized;
          },
          async (text: string) => {
            await context.session.synthetic({
              sessionID,
              text,
              description: "OpenCode Guardian remediation",
              metadata: { "opencode-guardian": true },
              delivery: "queue",
              resume: true,
            });
          },
          engine
        );
        }
        if (controller.signal.aborted) return;
        throw new Error("V2 event stream ended before plugin teardown.");
      } catch (error) {
        if (controller.signal.aborted) return;
        recordGuardianEvent({ kind: "inspection-error" }, directory);
        console.error("[opencode-guardian] V2 event subscription error:", error);
      }

      if (attempt === 2) {
        console.error("[opencode-guardian] V2 idle inspection stopped after three stream failures; reload the plugin to restore it.");
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
      } catch (error) {
        if (!controller.signal.aborted) {
          recordGuardianEvent({ kind: "inspection-error" }, directory);
          console.error("[opencode-guardian] V2 event resubscription failed; reload the plugin:", error);
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
    await Promise.allSettled(registrations.map((registration) => registration.dispose()));
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
