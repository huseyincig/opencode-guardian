import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { guardianCommandReport } from "../dist/commands.js";
import Guardian, { GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD, GUARDIAN_INTERVENTION_RPC_DEFINITION, GUARDIAN_INTERVENTION_RPC_METHOD, GuardEngine, VerificationSnapshotStore, cacheAgentCapability, classifyAgentReport, clearAllAgentCapabilities, clearGuardianTelemetryConfig as clearGuardianTelemetryConfig_10, clearGuardianTelemetryConfig as clearGuardianTelemetryConfig_6, clearGuardianTelemetryConfig as clearGuardianTelemetryConfig_7, collectTurnEvidence, configureGuardianTelemetry, evaluateAgentMutationProfile, evaluatePreflight, getActiveMeshHandoff, getCachedAgentCapability, getLatestMeshIntervention, guardianEventPath, hasUnfinishedBackgroundTool, isSensitiveKey, isSessionRemediating, isSourceReviewEvidence, loadConfig, noSecretsRule, noUnverifiedClaimsRule, normalizeV2Messages, readGuardianStatus, recordGuardianEvent, recordMeshIntervention, resetMeshStateForTests, resolveEffectiveConfig, resolveV2AgentCapability, sanitizeMessages, sanitizeObject, sanitizeString, sanitizeToolResult, taskCompletionRule } from "../dist/index.js";
import plugin from "../dist/index.js";
import * as GuardianIndex from "../dist/index.js";
import { splitShellStages } from "../dist/shell-risk.js";
import { StreamLoopWatcher } from "../dist/stream-loop.js";
import { hasResearchOnlyConstraint } from "../dist/task-constraints.js";
import { clearGuardianTelemetryConfig } from "../dist/telemetry.js";
import TuiPlugin from "../dist/tui.js";

describe("V2 Hook Registration & Disposal Lifecycle", () => {
  function host(t, onHook) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v2-hook-lifecycle-"));
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"),
      JSON.stringify({
        enabled: true,
        preflight: { enabled: false },
        secrets: { enabled: false },
      }));
    const original = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
    t.after(() => {
      if (original === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = original;
      fs.rmSync(directory, { recursive: true, force: true });
    });
    return {
      location: { directory },
      event: { subscribe({ signal }) { return (async function* () {
        await new Promise((resolve) => {
          if (signal.aborted) resolve();
          else signal.addEventListener("abort", resolve, { once: true });
        });
      })(); } },
      session: {
        async context() { return []; },
        async synthetic() {},
        hook: onHook,
      },
    };
  }

  test("V2 task hooks dispose an earlier registration when a later hook fails", async (t) => {
    let disposed = 0;
    const ctx = host(t, async (kind) => {
      if (kind === "prompt") return { dispose() { disposed++; } };
      throw new Error("context hook not supported");
    });
    const prior = console.error;
    console.error = (...args) => { void args; };
    let cleanup;
    try { cleanup = await Guardian.setup(ctx); } finally { console.error = prior; }
    assert.equal(disposed, 1, "orphan prompt hook must be disposed immediately");
    assert.equal(typeof cleanup, "function", "idle inspection remains available");
    await cleanup();
    assert.equal(disposed, 1, "no double-disposal");
  });

  test("V2 task hook without a disposer never poisons plugin shutdown", async (t) => {
    const ctx = host(t, async () => undefined);
    const prior = console.error;
    console.error = (...args) => { void args; };
    let cleanup;
    try { cleanup = await Guardian.setup(ctx); } finally { console.error = prior; }
    assert.equal(typeof cleanup, "function");
    await assert.doesNotReject(cleanup());
  });

  for (const failedHook of ["generate", "title"]) {
    test(`V2 auxiliary ${failedHook} registration failure rolls back every earlier hook`, async (t) => {
      const active = new Set();
      const disposed = [];
      const ctx = host(t, async (kind) => {
        if (kind === failedHook) throw new Error("synthetic registration failure");
        active.add(kind);
        return { dispose() { active.delete(kind); disposed.push(kind); } };
      });
      fs.writeFileSync(path.join(ctx.location.directory, "opencode-guardian.json"),
        JSON.stringify({ enabled: true, secrets: { enabled: true } }));
      ctx.tool = { async hook(kind) {
        active.add(kind);
        return { dispose() { active.delete(kind); disposed.push(kind); } };
      } };
      await assert.rejects(Guardian.setup(ctx), /session context security hook registration failed/);
      assert.deepEqual([...active], [], 'failed setup must leave no active callback');
      assert.equal(disposed.includes('compaction'), true);
      if (failedHook === 'title') assert.equal(disposed.includes('generate'), true);
      assert.equal(new Set(disposed).size, disposed.length, 'each registration is disposed once');
    });
  }
});

describe("V2 Event Stream Resilience", () => {
  async function eventually(check, limit = 1500) {
    const until = Date.now() + limit;
    while (!check()) {
      if (Date.now() > until) assert.fail("V2 event stream did not reach the expected state");
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  function fixture(t, subscribe) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v2-event-"));
    fs.writeFileSync(
      path.join(directory, "opencode-guardian.json"),
      JSON.stringify({ enabled: true, secrets: { enabled: false } })
    );
    const original = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
    t.after(() => {
      if (original === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = original;
      fs.rmSync(directory, { recursive: true, force: true });
    });
    return {
      location: { directory },
      event: { subscribe },
      session: {
        async context() { return []; },
        async synthetic() {},
      },
    };
  }

  test("V2 idle inspection resubscribes after a transient stream failure", async (t) => {
    let subscriptions = 0;
    let inspected = 0;
    const host = fixture(t, ({ signal }) => {
      subscriptions++;
      if (subscriptions === 1) return (async function* () { throw new Error("transient stream"); })();
      return (async function* () {
        yield { type: "session.idle", data: { sessionID: "recovered-session" } };
        await new Promise((resolve) => {
          if (signal.aborted) resolve();
          else signal.addEventListener("abort", resolve, { once: true });
        });
      })();
    });
    host.session.context = async () => { inspected++; return []; };
    const original = console.error;
    const errors = [];
    console.error = (message) => {
      const text = String(message);
      if (!text.includes("ExperimentalWarning:")) errors.push(text);
    };
    let cleanup;
    try {
      cleanup = await Guardian.setup(host);
      await eventually(() => inspected === 1);
      assert.equal(subscriptions, 2);
      assert.equal(readGuardianStatus().errors, 1);
      assert.deepEqual(errors, [], "stream exceptions must not corrupt the interactive TUI");
    } finally {
      await cleanup?.();
      console.error = original;
    }
  });

  test("V2 finite event streams report and bound failed resubscriptions", async (t) => {
    let subscriptions = 0;
    const host = fixture(t, () => {
      subscriptions++;
      return (async function* () {})();
    });
    const original = console.error;
    const errors = [];
    console.error = (message) => {
      const text = String(message);
      if (!text.includes("ExperimentalWarning:")) errors.push(text);
    };
    let cleanup;
    try {
      cleanup = await Guardian.setup(host);
      await eventually(() => readGuardianStatus().errors === 3, 1700);
      assert.deepEqual(errors, [], "stream errors must be recorded without terminal output");
      assert.equal(subscriptions, 3);
      assert.equal(readGuardianStatus().errors, 3);
    } finally {
      await cleanup?.();
      console.error = original;
    }
  });

  test("V2 cleanup cancels pending event-stream reconnect", async (t) => {
    let subscriptions = 0;
    const host = fixture(t, () => {
      subscriptions++;
      return (async function* () {})();
    });
    const original = console.error;
    console.error = () => {};
    let cleanup;
    try {
      cleanup = await Guardian.setup(host);
      await eventually(() => readGuardianStatus().errors === 1);
      await cleanup();
      await new Promise((resolve) => setTimeout(resolve, 260));
      assert.equal(subscriptions, 1);
    } finally {
      await cleanup?.();
      console.error = original;
    }
  });
});

describe("V2 Stage 2a Shell, Fork & Stream Hooks", () => {
  const stateIsolatedTests = new WeakSet();
  function tempProject(t, config = { enabled: true, secrets: { enabled: false }, updateNotice: { enabled: false } }) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-stage2a-"));
    const shouldIsolateState = !stateIsolatedTests.has(t);
    const oldState = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    if (shouldIsolateState) {
      stateIsolatedTests.add(t);
      process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(dir, "state");
    }
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify(config));
    t.after(() => {
      if (shouldIsolateState) {
        if (oldState === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
        else process.env.OPENCODE_GUARDIAN_STATE_DIR = oldState;
      }
      fs.rmSync(dir, { recursive: true, force: true });
    });
    return dir;
  }

  // 1. V2 context.shell.hook("create.before") preflight enforcement & clean disposal/rollback
  test("V2 context.shell.hook('create.before') enforces preflight and rolls back on failure", async (t) => {
    const dir = tempProject(t, { enabled: true, preflight: { enabled: true }, secrets: { enabled: false } });
    let shellHook;
    let shellDisposed = 0;
    let toolDisposed = 0;
    const cleanup = await Guardian.setup({
      location: { directory: dir },
      event: { subscribe: () => (async function* () {})() },
      session: { context: async () => [], synthetic: async () => {} },
      tool: {
        hook: async () => ({ dispose() { toolDisposed++; } }),
      },
      shell: {
        hook: async (name, handler) => {
          if (name === "create.before") shellHook = handler;
          return { dispose() { shellDisposed++; } };
        },
      },
    });
    assert.equal(typeof shellHook, "function");
    await assert.doesNotReject(() => shellHook({ sessionID: "s1", command: "npm test" }));
    await assert.rejects(
      () => shellHook({ sessionID: "s1", command: "rm -rf /critical" }),
      (err) => err.reason === "destructive-command"
    );
    await cleanup();
    assert.equal(shellDisposed, 1);
    assert.equal(toolDisposed, 2);

    // Rollback when shell.hook throws after tool.hook succeeded
    let rollbackToolDisposed = 0;
    await assert.rejects(
      () => Guardian.setup({
        location: { directory: dir },
        event: { subscribe: () => (async function* () {})() },
        session: { context: async () => [], synthetic: async () => {} },
        tool: { hook: async () => ({ dispose() { rollbackToolDisposed++; } }) },
        shell: { hook: async () => { throw new Error("shell hook unavailable"); } },
      }),
      /V2 shell hook registration failed/
    );
    assert.equal(rollbackToolDisposed, 2, "tool hooks must be rolled back if shell.hook fails");
  });

  // 2. StreamLoopWatcher { interrupted: false } rejection handling
  test("StreamLoopWatcher treats { interrupted: false } as rejected without warning toast or stopped state", async () => {
    const toasts = [];
    let attempts = 0;
    const controller = new AbortController();
    const watcher = new StreamLoopWatcher({
      signal: controller.signal,
      directory: process.cwd(),
      settings: async () => ({ config: { enabled: true, rules: { "runtime/circuit-breaker": "error" } }, directory: process.cwd() }),
      interrupt: async () => {
        attempts++;
        return attempts === 1 ? { interrupted: false } : { interrupted: true };
      },
      notifier: { notify(payload) { toasts.push(payload); } },
    });
    const loop = "我想想".repeat(70);
    await watcher.event({ type: "session.text.delta", data: { sessionID: "s1", assistantMessageID: "a1", ordinal: 0, delta: loop } });
    assert.equal(attempts, 1);
    assert.equal(toasts.length, 0, "interrupted: false must not fire stream-interrupt toast");

    await watcher.event({ type: "session.text.delta", data: { sessionID: "s1", assistantMessageID: "a1", ordinal: 0, delta: loop } });
    assert.equal(attempts, 2, "session must not be marked stopped after interrupted: false");
  });

  // 3. V2 prompt hook cancelling in-flight idleQueue job & clearing stale TaskContract
  test("V2 prompt hook cancels in-flight idle inspection and clears stale TaskContract on empty prompt", async (t) => {
    const dir = tempProject(t);
    const entered = Promise.withResolvers();
    const release = Promise.withResolvers();
    const synthetics = [];
    let promptHook;
    let contextHook;
    let emitEvent;

    const cleanup = await Guardian.setup({
      location: { directory: dir },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              const next = await new Promise((resolve) => { emitEvent = resolve; });
              if (next === null) break;
              yield next;
            }
          })();
        },
      },
      session: {
        get: async () => ({ id: "s1", parentID: undefined }),
        context: async () => { entered.resolve(); return release.promise; },
        synthetic: async (req) => { synthetics.push(req); },
        hook: async (name, handler) => {
          if (name === "prompt") promptHook = handler;
          if (name === "context") contextHook = handler;
          return { dispose() {} };
        },
      },
    });
    t.after(async () => { emitEvent?.(null); await cleanup?.(); });

    // Establish a TaskContract
    await promptHook({ sessionID: "s1", prompt: { text: "Implement feature X and run all tests." } });
    const beforeCtx = { system: [] };
    await contextHook({ sessionID: "s1", system: beforeCtx.system });
    assert.ok(beforeCtx.system.length > 0);

    // Start idle inspection, then send empty prompt
    emitEvent({ type: "session.idle", data: { sessionID: "s1" } });
    await entered.promise;
    await promptHook({ sessionID: "s1", prompt: { text: "" } });

    const afterCtx = { system: [] };
    await contextHook({ sessionID: "s1", system: afterCtx.system });
    assert.deepEqual(afterCtx.system, [], "empty prompt must clear stale TaskContract");

    release.resolve([
      { id: "u1", type: "user", text: "Implement feature X." },
      { id: "a1", type: "assistant", content: [{ type: "text", text: "The test failure is unrelated to this change." }] },
    ]);
    await new Promise((r) => setTimeout(r, 40));
    assert.deepEqual(synthetics, [], "cancelled idle job must not emit synthetic remediation");

    // Pending idleQueue timer must keep the Node event loop alive (no unsettled top-level await exit 13)
    const loopCheck = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        [
          'import { createIdleQueue } from "./dist/idle-queue.js";',
          "const q = createIdleQueue(new AbortController().signal, (e) => { throw e; });",
          "let ran = false;",
          "await new Promise((resolve) => { q.enqueue('s-loop', async () => { ran = true; resolve(); }); });",
          'if (!ran) process.exit(2);',
          'console.log("IDLE_QUEUE_OK");',
        ].join(" "),
      ],
      { cwd: path.resolve(import.meta.dirname, ".."), encoding: "utf8" }
    );
    assert.equal(loopCheck.status, 0, `idleQueue event-loop check failed (status ${loopCheck.status}): ${loopCheck.stderr}`);
    assert.equal(loopCheck.stdout.trim(), "IDLE_QUEUE_OK");
  });

  // 4. OpenCode v2.3.0 session.fork / session.forked + top-level location.directory + background: true subagents
  test("V2 session.fork/forked treated as root, top-level location.directory honored, and background subagents isolated", async (t) => {
    const dirA = tempProject(t, { enabled: true, rules: { "discipline/no-evasion": "error" }, secrets: { enabled: false } });
    const dirB = tempProject(t, { enabled: false });
    const synthetics = [];
    const hooks = new Map();

    const eventQueue = [];
    let wake;
    const pushEvent = async (ev) => {
      eventQueue.push(ev);
      wake?.();
      await new Promise((r) => setImmediate(r));
    };

    const cleanup = await Guardian.setup({
      location: { directory: dirA },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              if (!eventQueue.length) {
                await new Promise((resolve) => { wake = resolve; });
              }
              const next = eventQueue.shift();
              if (next === null) break;
              if (next) yield next;
            }
          })();
        },
      },
      tool: {
        hook: async (name, cb) => {
          const list = hooks.get(name) ?? [];
          list.push(cb);
          hooks.set(name, list);
          return { dispose() {} };
        },
      },
      agent: {
        list: async () => [{ name: "worker", permissions: [{ action: "edit", effect: "allow" }] }],
      },
      session: {
        get: async ({ sessionID }) => {
          if (sessionID === "disabled-via-event") return { id: sessionID, parentID: undefined };
          if (sessionID === "forked-1") return { id: "forked-1", parentID: "root-1", fork: { messageID: "m1" }, location: { directory: dirA } };
          if (sessionID === "bg-1" || sessionID === "bg-2") return { id: sessionID, parentID: "root-1", location: { directory: dirA } };
          return { id: sessionID, parentID: undefined, location: { directory: dirA } };
        },
        context: async () => [
          { id: "u", type: "user", text: "Fix bug" },
          { id: "a", type: "assistant", agent: "worker", content: [{ type: "text", text: "The test failure is unrelated to this change." }] },
        ],
        synthetic: async (req) => { synthetics.push(req); },
        wait: async () => {},
      },
    });
    t.after(async () => { await pushEvent(null); await cleanup?.(); });

    // 4a. Top-level location.directory on session.created routes disabled dirB without inspecting
    await pushEvent({ type: "session.created", location: { directory: dirB }, data: { sessionID: "disabled-via-event" } });
    await pushEvent({ type: "session.idle", data: { sessionID: "disabled-via-event" } });
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(synthetics.filter((s) => s.sessionID === "disabled-via-event").length, 0);

    // 4b. Forked session is NOT misclassified as subagent (receives root remediation)
    await pushEvent({ type: "session.forked", data: { sessionID: "forked-1" } });
    await pushEvent({ type: "session.idle", data: { sessionID: "forked-1" } });
    for (let i = 0; i < 40 && !synthetics.some((s) => s.sessionID === "forked-1"); i++) {
      await new Promise((r) => setTimeout(r, 15));
    }
    assert.ok(synthetics.some((s) => s.sessionID === "forked-1"), "forked session must be treated as root");

    // 4c. Background subagent does not trigger foreground handoff or starve sibling background subagent
    for (const cb of hooks.get("execute.before") ?? []) {
      await cb({ tool: "subagent", sessionID: "root-1", id: "call-bg1", input: { agent: "worker", background: true } });
      await cb({ tool: "subagent", sessionID: "root-1", id: "call-bg2", input: { agent: "worker", background: true } });
    }
    const bgEvent = {
      tool: "subagent", sessionID: "root-1", id: "call-bg1",
      input: { agent: "worker", background: true }, status: "completed",
      result: { output: "bg-1 launched", metadata: { sessionId: "bg-1", background: true } },
    };
    for (const cb of hooks.get("execute.after") ?? []) {
      await cb(bgEvent);
    }
    assert.equal(bgEvent.result.output, "bg-1 launched", "background subagent must not rewrite parent output");

    await pushEvent({ type: "session.idle", data: { sessionID: "bg-2" } });
    for (let i = 0; i < 40 && !synthetics.some((s) => s.sessionID === "bg-2"); i++) {
      await new Promise((r) => setTimeout(r, 15));
    }
    assert.ok(synthetics.some((s) => s.sessionID === "bg-2"), "sibling background subagent must not be starved");
  });

  // 5. stringify handling Error instances & V2 { type, message } tool errors + normalizeV2Messages shell & agent-switched
  test("evidence collects V2 Error / { type, message } tool errors and normalizeV2Messages handles shell & agent-switched", () => {
    const errInstance = new Error("ENOENT: missing fixture");
    const v2ObjError = { type: "ToolExecutionError", message: "Permission denied" };
    const msgs = normalizeV2Messages([
      { id: "u1", type: "user", text: "Run tests" },
      { id: "sh1", type: "shell", command: "npm test", output: "failed", exitCode: 1 },
      { id: "sw1", type: "agent-switched", agent: "fixer" },
      {
        id: "a1",
        type: "assistant",
        content: [
          { type: "tool", name: "bash", state: { status: "error", input: { command: "npm test" }, error: errInstance } },
          { type: "tool", name: "read", state: { status: "error", input: { path: "a.ts" }, error: v2ObjError } },
        ],
      },
    ], "s1");

    assert.ok(msgs.some((m) => m.info.role === "assistant" && m.parts.some((p) => p.tool === "bash")));
    const ev = collectTurnEvidence(msgs);
    assert.ok(ev.failures.some((f) => String(f.error).includes("ENOENT: missing fixture")));
    assert.ok(ev.failures.some((f) => String(f.error).includes("Permission denied")));
  });

  // 6. sanitizeObject / sanitizeMessages preserving Uint8Array media buffers and Message class prototypes
  test("sanitizeObject and sanitizeMessages preserve Uint8Array buffers and class prototypes", () => {
    class Message {
      constructor(text) { this.text = text; }
      getText() { return this.text; }
    }
    const media = new Uint8Array([1, 2, 3, 4]);
    const msg = new Message("token=sk-proj-1234567890abcdefghijklmnop");
    const { sanitized } = sanitizeObject({ media, msg }, { includeRuntimeEnv: false });
    assert.equal(sanitized.media instanceof Uint8Array, true);
    assert.deepEqual([...sanitized.media], [1, 2, 3, 4]);
    assert.equal(sanitized.msg instanceof Message, true);
    assert.equal(sanitized.msg.getText(), "token=[REDACTED]");

    const [sanitizedMsg] = sanitizeMessages([msg], { includeRuntimeEnv: false });
    assert.equal(sanitizedMsg instanceof Message, true);
  });

  // 7. resolveV2AgentCapability array and { data } shapes + null safety
  test("resolveV2AgentCapability handles array, { data }, and null/throwing list responses safely", async () => {
    const arrProfile = await resolveV2AgentCapability(
      { agent: { list: async () => [{ name: "builder", permissions: [{ action: "edit", effect: "allow" }] }] } },
      "s-arr",
      "builder"
    );
    assert.equal(arrProfile.capability, "write-allowed");

    const dataProfile = await resolveV2AgentCapability(
      { agent: { list: async () => ({ data: [{ name: "reader", permissions: [{ action: "edit", effect: "deny" }, { action: "bash", effect: "deny" }] }] }) } },
      "s-data",
      "reader"
    );
    assert.equal(dataProfile.capability, "read-only");

    const nullProfile = await resolveV2AgentCapability(
      { agent: { list: async () => null } },
      "s-null",
      "ghost"
    );
    assert.equal(nullProfile.capability, "unknown");
  });

  // 8. clear RPC scoping (directory-scoped {} clear does NOT wipe another project's interventions; maxLength: 256)
  test("RPC clear with {} is directory-scoped and enforces sessionID maxLength: 256", async (t) => {
    const dirA = tempProject(t, { enabled: true, preflight: { enabled: true }, secrets: { enabled: false } });
    const dirB = tempProject(t, { enabled: true, preflight: { enabled: true }, secrets: { enabled: false } });

    assert.equal(GUARDIAN_INTERVENTION_RPC_DEFINITION.methods[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD].input.properties.sessionID.maxLength, 256);

    const rpcA = {};
    const rpcB = {};
    const hooksA = new Map();
    const hooksB = new Map();

    const cleanA = await Guardian.setup({
      location: { directory: dirA },
      event: { subscribe: () => (async function* () {})() },
      session: { context: async () => [], synthetic: async () => {} },
      tool: { hook: async (n, cb) => { hooksA.set(n, cb); return { dispose() {} }; } },
      rpc: { register: async (_def, handlers) => { Object.assign(rpcA, handlers); return { dispose() {} }; } },
    });
    const cleanB = await Guardian.setup({
      location: { directory: dirB },
      event: { subscribe: () => (async function* () {})() },
      session: { context: async () => [], synthetic: async () => {} },
      tool: { hook: async (n, cb) => { hooksB.set(n, cb); return { dispose() {} }; } },
      rpc: { register: async (_def, handlers) => { Object.assign(rpcB, handlers); return { dispose() {} }; } },
    });
    t.after(async () => { await cleanA?.(); await cleanB?.(); });

    await assert.rejects(() => hooksA.get("execute.before")({ tool: "bash", sessionID: "sA", input: { command: "rm -rf /x" } }));
    await assert.rejects(() => hooksB.get("execute.before")({ tool: "bash", sessionID: "sB", input: { command: "rm -rf /y" } }));

    assert.equal((await rpcA[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID: "sA" })).active, true);
    assert.equal((await rpcB[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID: "sB" })).active, true);

    // Directory-scoped clear on A must NOT wipe B
    await rpcA[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD]({});
    assert.equal((await rpcA[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID: "sA" })).active, false);
    assert.equal((await rpcB[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID: "sB" })).active, true);
  });

  // 9. TUI minimal context, session.moved, version-notice O_TRUNC safety, and Bun dist/tui.js fallback
  test("TUI minimal context safety, session.moved subscription, and Bun dist/tui.js fallback", async (t) => {
    const dir = tempProject(t);
    const eventsSubscribed = [];
    const cleanup = TuiPlugin.setup({
      location: { directory: dir },
      ui: { slot: () => () => {} },
      data: {
        on(type) { eventsSubscribed.push(type); return () => {}; },
      },
    });
    assert.equal(typeof cleanup, "function");
    assert.ok(eventsSubscribed.includes("session.deleted"));
    assert.ok(eventsSubscribed.includes("session.moved"));
    cleanup();

    // Verify src/version-notice.ts does not use O_TRUNC in openSync (uses ftruncateSync after fstatSync)
    const vnSource = fs.readFileSync(new URL("../src/version-notice.ts", import.meta.url), "utf8");
    assert.doesNotMatch(vnSource, /O_TRUNC/);
    assert.match(vnSource, /ftruncateSync/);

    // Verify dist/tui.js fallback under Bun 1.4.4 if available
    const bunPath = "/root/.bun/bin/bun";
    if (fs.existsSync(bunPath)) {
      const res = spawnSync(bunPath, ["-e", 'import("./dist/tui.js").then(m => { if (!m.default?.setup) process.exit(2); })'], {
        cwd: path.resolve(import.meta.dirname, ".."),
        encoding: "utf8",
      });
      assert.equal(res.status, 0, `Bun import ./dist/tui.js failed: ${res.stderr}`);
    }
  });

  // 10. task/completion-gate "in progress" reply with mutation does NOT falsely verify remediation
  test("task/completion-gate 'in progress' reply with mutation does not mark remediation verified", async (t) => {
    const dir = tempProject(t);
    const engine = new GuardEngine({ enabled: true, rules: { "task/completion-gate": "error" } });
    const r1 = await engine.inspect("s-inprog", dir, [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the bug and run the full test suite before finishing." }] },
      { info: { id: "a1", role: "assistant" }, parts: [
        { type: "tool", tool: "write", state: { status: "completed", input: { filePath: "src/a.ts", content: "export const x = 0;" } } },
        { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test" }, metadata: { exitCode: 1 }, output: "1 failed" } },
        { type: "text", text: "Done." },
      ] },
    ]);
    assert.equal(r1.decision, "block");

    const r2 = await engine.inspect("s-inprog", dir, [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the bug and run the full test suite before finishing." }] },
      { info: { id: "a1", role: "assistant" }, parts: [
        { type: "tool", tool: "write", state: { status: "completed", input: { filePath: "src/a.ts", content: "export const x = 0;" } } },
        { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test" }, metadata: { exitCode: 1 }, output: "1 failed" } },
        { type: "text", text: "Done." },
      ] },
      { info: { id: "a2", role: "assistant" }, parts: [
        { type: "tool", tool: "write", state: { status: "completed", input: { filePath: "src/a.ts", content: "export const x = 1;" } } },
        { type: "text", text: "Working on it, still in progress." },
      ] },
    ]);
    assert.notEqual(r2.remediationStatus, "verified");
  });

  // 11. VerificationSnapshotStore preserving both editIntegrity and fingerprint on same callID
  test("VerificationSnapshotStore preserves both editIntegrity and fingerprint on same callID", (t) => {
    const dir = tempProject(t);
    const beforeCode = "export function alpha() { return 1; }\nexport function beta() { return 2; }\n";
    const afterCode = "export function alpha() { return 1; }\n";
    fs.writeFileSync(path.join(dir, "app.ts"), beforeCode);
    const store = new VerificationSnapshotStore();
    store.observeBefore("s1", "c1", "write_file", { path: "app.ts", content: afterCode }, dir);
    fs.writeFileSync(path.join(dir, "app.ts"), afterCode);
    store.observe("s1", "c1", "write_file", { path: "app.ts", content: afterCode }, "ok", {}, dir);
    store.observe("s1", "c1", "bash", { command: "npm test" }, "ok", { exitCode: 0 }, dir);
    const snaps = store.snapshots("s1");
    const snap = snaps.get("c1");
    assert.ok(snap?.editIntegrity, "editIntegrity must be preserved");
    assert.ok(snap?.fingerprint, "fingerprint must be preserved on the same callID");
  });

  // 12. Multi-stage splitShellStages in package install / lazy commit preflight
  test("preflight inspects multi-stage shell commands for hallucinated packages and lazy commits", () => {
    assert.equal(evaluatePreflight("bash", { command: "npm i ok && npm i react-official" }), "hallucinated-or-malformed-package");
    assert.equal(evaluatePreflight("bash", { command: "bun add react-official" }), "hallucinated-or-malformed-package");
    assert.equal(evaluatePreflight("bash", { command: "pnpm add react-official" }), "hallucinated-or-malformed-package");
    assert.equal(evaluatePreflight("bash", { command: "echo ok && git commit -m 'wip'" }), "lazy-commit-message");
  });

  // 13. telemetryConfigRegistry cleanup on early throw/return in setup()
  test("telemetryConfigRegistry is cleaned up on early throw in setup()", async (t) => {
    const dir = tempProject(t, { enabled: true, telemetry: { level: "off" }, secrets: { enabled: true } });
    // secrets: true without tool/session hooks throws during setup()
    await assert.rejects(() => Guardian.setup({
      location: { directory: dir },
      event: { subscribe: () => (async function* () {})() },
      session: { context: async () => [], synthetic: async () => {} },
    }));
    // Subsequent setup with telemetry: all should not be stuck with stale 'off'
    const dir2 = tempProject(t, { enabled: true, telemetry: { level: "all" }, secrets: { enabled: false } });
    const cleanup = await Guardian.setup({
      location: { directory: dir2 },
      event: { subscribe: () => (async function* () {})() },
      session: { context: async () => [], synthetic: async () => {} },
    });
    await cleanup?.();
    assert.equal(readGuardianStatus(dir2).preflight, "disabled");
  });
});

describe("OpenCode v2.3.x Compatibility", () => {
  function makeTempDir(prefix) {
    return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  }

  test("v2.3.1 backgrounded/timed-out shell command is never treated as completed success or completed mutation", () => {
    const evidence = collectTurnEvidence([
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "shell",
            callID: "c1",
            state: {
              status: "completed",
              input: { command: "npm test && rm -f tmp.txt" },
              output:
                "Command moved to the background (shell ID: sh_1).\n" +
                "The command did not finish within its timeout of 120 seconds and was moved to the background.",
              metadata: { status: "running", shellID: "sh_1", pid: 4242 },
            },
          },
        ],
      },
    ]);

    assert.equal(evidence.successfulVerifications.length, 0);
    assert.equal(evidence.failures.length, 0);
    assert.equal(evidence.records.find((r) => r.kind === "test")?.status, "unknown");
    assert.equal(evidence.fileMutations[0]?.status, "unknown");
  });

  test("v2.3.1 synthetic shell completion notification produces verifiable test evidence", () => {
    const passMessages = normalizeV2Messages([
      { id: "u1", type: "user", text: "Run tests and fix." },
      {
        id: "s1",
        type: "synthetic",
        text: '<shell id="job_1" state="completed" command="npm test">\n✔ all 5 tests passed\n</shell>',
        description: "npm test",
        metadata: { source: "shell", shellID: "sh_1", jobID: "job_1", state: "completed", exit: 0 },
      },
      {
        id: "a1",
        type: "assistant",
        content: [{ type: "text", text: "All tests passed." }],
      },
    ]);

    const evidence = collectTurnEvidence(passMessages);
    assert.equal(evidence.successfulVerifications.length, 1);
    assert.equal(evidence.successfulVerifications[0]?.kind, "test");

    const claimResult = noUnverifiedClaimsRule.inspect({
      sessionID: "sess-1",
      directory: process.cwd(),
      messages: passMessages,
      currentTurn: passMessages,
      evidence,
      ruleConfig: {},
    });
    assert.equal(claimResult.decision, "pass");

    const failMessages = normalizeV2Messages([
      { id: "u2", type: "user", text: "Run tests." },
      {
        id: "s2",
        type: "synthetic",
        text: '<shell id="job_2" state="error" command="npm test">\n1 test failed\n</shell>',
        metadata: { source: "shell", shellID: "sh_2", state: "error", exit: 1 },
      },
    ]);
    const failEvidence = collectTurnEvidence(failMessages);
    assert.equal(failEvidence.failures.length, 1);
    assert.equal(failEvidence.failures[0]?.exitCode, 1);
  });

  test("v2.3.1 shell message with status 'running' is normalized as running, not error", () => {
    const messages = normalizeV2Messages([
      { id: "u1", type: "user", text: "Run long build." },
      { id: "sh1", type: "shell", shellID: "sh_run", command: "npm run build", status: "running" },
      { id: "a1", type: "assistant", content: [{ type: "text", text: "Build is running in the background." }] },
    ]);

    assert.equal(messages[1]?.parts[0]?.state?.status, "running");
    assert.equal(messages[1]?.parts[0]?.state?.metadata?.status, "running");
    const evidence = collectTurnEvidence(messages);
    assert.equal(evidence.failures.length, 0);

    const report = classifyAgentReport("Build is running in the background.");
    assert.equal(report.isInProgress, true);

    const gate = taskCompletionRule.inspect({
      sessionID: "s-run",
      directory: process.cwd(),
      messages,
      currentTurn: messages,
      evidence,
      ruleConfig: {},
    });
    assert.equal(gate.decision, "pass");
  });

  test("v2.3.1 Code Mode execute expands metadata.toolCalls and catches metadata.error failures", () => {
    const secret = "sk-proj-codemode_secret_key_1234567890abcd";
    const messages = normalizeV2Messages([
      { id: "u1", type: "user", text: "Write config via code mode." },
      {
        id: "a1",
        type: "assistant",
        content: [
          {
            type: "tool",
            id: "exec_1",
            name: "execute",
            state: {
              status: "completed",
              input: { code: "await tools.write({ path: 'cfg.ts', content: '...' })" },
              content: "Error in script",
              metadata: {
                error: true,
                toolCalls: [
                  {
                    tool: "write",
                    status: "completed",
                    input: { path: "cfg.ts", content: `export const k = "${secret}";` },
                  },
                  {
                    tool: "shell",
                    status: "completed",
                    input: { command: "npm test" },
                  },
                ],
              },
            },
          },
        ],
      },
    ]);

    const evidence = collectTurnEvidence(messages);
    assert.ok(evidence.failures.some((f) => f.toolName === "execute"), "metadata.error must record failure");
    assert.ok(
      evidence.successfulVerifications.some((v) => v.kind === "test" && v.toolName === "shell"),
      "nested Code Mode shell call must produce test evidence"
    );

    const secretCheck = noSecretsRule.inspect({
      sessionID: "s-cm",
      directory: process.cwd(),
      messages,
      currentTurn: messages,
      evidence,
      ruleConfig: {},
    });
    assert.equal(secretCheck.decision, "block", "Code Mode write toolCall must be inspected by no-secrets");
  });

  test("v2.3.0+ experimental.idle with active background jobs suppresses premature idle remediation", async (t) => {
    const dir = makeTempDir("guardian-exp-idle-");
    t.after(() => {
      clearGuardianTelemetryConfig();
      fs.rmSync(dir, { recursive: true, force: true });
    });
    fs.writeFileSync(
      path.join(dir, "opencode-guardian.json"),
      JSON.stringify({ enabled: true, telemetry: { level: "off" } })
    );

    let expIdleCb;
    const synthetic = [];
    let pushEvent;
    const stream = {
      async *[Symbol.asyncIterator]() {
        while (true) {
          const next = await new Promise((resolve) => {
            pushEvent = resolve;
          });
          if (!next) break;
          yield next;
        }
      },
    };

    const dispose = await plugin.setup({
      location: { directory: dir },
      event: { subscribe: () => stream },
      tool: { hook: () => ({ dispose() {} }) },
      session: {
        hook: async (name, cb) => {
          if (name === "experimental.idle") expIdleCb = cb;
          return { dispose() {} };
        },
        get: async () => ({ id: "s-bg", location: { directory: dir } }),
        context: async () => [
          { id: "u1", type: "user", text: "Fix and run tests." },
          { id: "a1", type: "assistant", content: [{ type: "text", text: "I apologize for the error." }] },
        ],
        synthetic: async (payload) => {
          synthetic.push(payload);
        },
      },
    });
    t.after(async () => {
      pushEvent?.(null);
      await dispose?.();
    });

    assert.equal(typeof expIdleCb, "function");
    await expIdleCb({
      sessionID: "s-bg",
      background: [{ kind: "codemode", sessionID: "s-bg", jobID: "j1" }],
    });
    pushEvent({ type: "session.idle", data: { sessionID: "s-bg" } });
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(synthetic.length, 0, "Must not remediate while background job is active");

    await expIdleCb({ sessionID: "s-bg", background: [] });
    pushEvent({ type: "session.idle", data: { sessionID: "s-bg" } });
    for (let i = 0; i < 40 && synthetic.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    assert.equal(synthetic.length, 1, "Must inspect normally once background jobs clear");
  });

  test("v2.3.1 read tool string content and structured output are parsed, while directory listings are not source reviews", () => {
    const msgs = normalizeV2Messages([
      {
        id: "a1",
        type: "assistant",
        content: [
          {
            type: "tool",
            id: "r1",
            name: "read",
            state: {
              status: "completed",
              input: { path: "src" },
              output: { type: "directory", entries: ["index.ts", "engine.ts"] },
              content: "Read directory src, entries 1-2\nindex.ts\nengine.ts",
            },
          },
          {
            type: "tool",
            id: "r2",
            name: "read",
            state: {
              status: "completed",
              input: { path: "src/index.ts" },
              output: { type: "text", content: "export const x = 1;", offset: 1, lineCount: 1 },
              content: "Read file src/index.ts, lines 1-1\n1: export const x = 1;",
            },
          },
        ],
      },
    ]);

    const evidence = collectTurnEvidence(msgs);
    assert.equal(evidence.records.length, 2);
    assert.equal(isSourceReviewEvidence(evidence.records[0]), false, "directory read must not satisfy source review");
    assert.equal(isSourceReviewEvidence(evidence.records[1]), true, "file text read must satisfy source review");
  });

  test("resolveV2AgentCapability merges agent.list base permissions with session.permissions", async () => {
    const profile = await resolveV2AgentCapability(
      {
        session: {
          get: async () => ({
            id: "child-1",
            agent: "coder",
            permissions: [{ permission: "read", resource: "*", effect: "allow" }],
          }),
        },
        agent: {
          list: async () => [
            {
              id: "coder",
              name: "coder",
              permissions: [{ permission: "edit", resource: "*", effect: "allow" }],
            },
          ],
        },
      },
      "child-1"
    );

    assert.equal(profile.capability, "write-allowed");
    assert.equal(profile.evidence.edit, "allow");
  });

  test("SENSITIVE_KEY_REGEX ignores 'pass' counters and sanitizeObject preserves null/boolean/number fields", () => {
    assert.equal(isSensitiveKey("pass"), false);
    assert.equal(isSensitiveKey("PASSWORD"), true);
    assert.equal(isSensitiveKey("API_PASSPHRASE"), true);

    const sanitized = sanitizeObject({
      pass: 12,
      fail: 0,
      hasPassword: false,
      token: null,
      secretCount: 3,
      apiKey: "sk-proj-real_secret_value_1234567890",
    }).sanitized;

    assert.equal(sanitized.pass, 12);
    assert.equal(sanitized.hasPassword, false);
    assert.equal(sanitized.token, null);
    assert.equal(sanitized.secretCount, 3);
    assert.equal(sanitized.apiKey, "[REDACTED]");
  });
});

describe("OpenCode v2.4.0 Code Mode & Background Jobs", () => {
  function createV2TestHost(projectDir, overrides = {}) {
    const registeredHooks = new Map();
    const disposed = [];
    const synthetics = [];
    const eventQueue = [];
    let wakeEvent = null;

    const pushEvent = async (ev) => {
      eventQueue.push(ev);
      wakeEvent?.();
      await new Promise((r) => setImmediate(r));
    };

    const context = {
      location: { directory: projectDir },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              if (!eventQueue.length) {
                await new Promise((resolve) => {
                  wakeEvent = resolve;
                  signal.addEventListener("abort", resolve, { once: true });
                });
              }
              if (signal.aborted) break;
              const next = eventQueue.shift();
              if (next === null) break;
              if (next) yield next;
            }
          })();
        },
      },
      session: {
        async get({ sessionID }) {
          if (overrides.sessionGet) return overrides.sessionGet({ sessionID });
          return { id: sessionID, parentID: undefined, location: { directory: projectDir } };
        },
        async context({ sessionID }) {
          if (overrides.sessionContext) return overrides.sessionContext({ sessionID });
          return [];
        },
        async synthetic(req) {
          synthetics.push(req);
          return { id: "syn-1" };
        },
        async wait() {
          return { status: "idle" };
        },
        async hook(kind, cb) {
          const list = registeredHooks.get(`session.${kind}`) ?? [];
          list.push(cb);
          registeredHooks.set(`session.${kind}`, list);
          return {
            dispose() {
              disposed.push(`session.${kind}`);
              const idx = list.indexOf(cb);
              if (idx >= 0) list.splice(idx, 1);
            },
          };
        },
      },
      tool: {
        async hook(kind, cb) {
          const list = registeredHooks.get(`tool.${kind}`) ?? [];
          list.push(cb);
          registeredHooks.set(`tool.${kind}`, list);
          return {
            dispose() {
              disposed.push(`tool.${kind}`);
              const idx = list.indexOf(cb);
              if (idx >= 0) list.splice(idx, 1);
            },
          };
        },
      },
      shell: {
        async hook(kind, cb) {
          const list = registeredHooks.get(`shell.${kind}`) ?? [];
          list.push(cb);
          registeredHooks.set(`shell.${kind}`, list);
          return {
            dispose() {
              disposed.push(`shell.${kind}`);
              const idx = list.indexOf(cb);
              if (idx >= 0) list.splice(idx, 1);
            },
          };
        },
      },
      agent: {
        async list() {
          if (overrides.agentList) return overrides.agentList();
          return [];
        },
      },
    };

    return { context, registeredHooks, disposed, synthetics, pushEvent };
  }

  test("1. Code Mode (execute) moved to background is treated as unfinished until codemode synthetic completion", () => {
    const runningTurn = normalizeV2Messages([
      { id: "u1", type: "user", text: "Run the long verification script." },
      {
        id: "a1",
        type: "assistant",
        content: [
          {
            type: "tool",
            id: "call_cm_1",
            name: "execute",
            state: {
              status: "completed",
              input: { code: "await tools.shell({ command: 'npm test' })" },
              content: [{ type: "text", text: "Execution moved to the background (job job_cm_1)." }],
              metadata: { jobID: "job_cm_1", status: "running" },
            },
          },
        ],
      },
    ]);

    assert.equal(hasUnfinishedBackgroundTool(runningTurn), true);

    const evidenceWhileRunning = collectTurnEvidence(runningTurn);
    assert.equal(evidenceWhileRunning.successfulVerifications.length, 0);
    const executeRecord = evidenceWhileRunning.records.find((r) => r.toolName === "execute");
    assert.equal(executeRecord?.status, "unknown");

    const completedTurn = normalizeV2Messages([
      { id: "u1", type: "user", text: "Run the long verification script." },
      {
        id: "a1",
        type: "assistant",
        content: [
          {
            type: "tool",
            id: "call_cm_1",
            name: "execute",
            state: {
              status: "completed",
              input: { code: "await tools.shell({ command: 'npm test' })" },
              content: [{ type: "text", text: "Execution moved to the background (job job_cm_1)." }],
              metadata: { jobID: "job_cm_1", status: "running" },
            },
          },
        ],
      },
      {
        id: "syn_cm_1",
        type: "synthetic",
        text: "Code Mode background job job_cm_1 completed.",
        metadata: {
          source: "codemode",
          jobID: "job_cm_1",
          state: "completed",
        },
      },
    ]);

    assert.equal(hasUnfinishedBackgroundTool(completedTurn), false);
  });

  test("2. experimental.job.updated clears backgroundSessions lock when job finishes or is cancelled", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v240-job-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      updateNotice: { enabled: false },
    }));

    const { context, registeredHooks, synthetics, pushEvent } = createV2TestHost(dir, {
      sessionContext: () => [
        { id: "u1", type: "user", text: "Fix the bug." },
        { id: "a1", type: "assistant", content: [{ type: "text", text: "This test failure is unrelated to my changes." }] },
      ],
    });

    const cleanup = await Guardian.setup(context);
    t.after(async () => cleanup?.());

    const expIdleCbs = registeredHooks.get("session.experimental.idle") ?? [];
    assert.ok(expIdleCbs.length > 0, "experimental.idle hook must be registered");

    // Host reports active v2.4.0 video & codemode background jobs for this session
    for (const cb of expIdleCbs) {
      await cb({
        sessionID: "ses-bg-job",
        background: [
          { kind: "video", sessionID: "ses-bg-job", path: "/tmp/out.mp4" },
          { kind: "codemode", sessionID: "ses-bg-job", jobID: "job_123" },
        ],
      });
    }

    // While background jobs are running, session.idle must NOT trigger remediation
    await pushEvent({ type: "session.idle", data: { sessionID: "ses-bg-job" } });
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(synthetics.length, 0, "must stay suppressed while background jobs are running");

    // Now job_123 is cancelled and video job completes via experimental.job.updated
    await pushEvent({
      type: "experimental.job.updated",
      data: {
        info: {
          id: "job_123",
          sessionID: "ses-bg-job",
          status: "cancelled",
          kind: "codemode",
        },
      },
    });
    await pushEvent({
      type: "experimental.job.updated",
      data: {
        info: {
          id: "job_vid_1",
          sessionID: "ses-bg-job",
          status: "completed",
          kind: "video",
          path: "/tmp/out.mp4",
        },
      },
    });

    // Subsequent idle must inspect and remediate instead of staying locked in backgroundSessions
    await pushEvent({ type: "session.idle", data: { sessionID: "ses-bg-job" } });
    for (let i = 0; i < 40 && synthetics.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 15));
    }
    assert.ok(synthetics.length >= 1, "expected remediation after experimental.job.updated cleared background lock");
  });

  test("3. Top-level dotted Code Mode tool calls (tools.ns.fn) expose nested toolCalls to evidence", () => {
    const normalized = normalizeV2Messages([
      { id: "u1", type: "user", text: "Run tests via codemode" },
      {
        id: "a1",
        type: "assistant",
        content: [
          {
            type: "tool",
            id: "call_dotted_1",
            name: "tools.opencode.shell",
            state: {
              status: "completed",
              input: { command: "npm test" },
              content: [{ type: "text", text: "10 passed\nExit code: 0" }],
              metadata: {
                codemode: true,
                toolCalls: [
                  {
                    id: "call_inner_1",
                    tool: "shell",
                    status: "completed",
                    input: { command: "npm test" },
                    output: "10 passed\nExit code: 0",
                    exitCode: 0,
                  },
                ],
              },
            },
          },
        ],
      },
    ]);

    const assistantParts = normalized[1]?.parts ?? [];
    assert.ok(
      assistantParts.some((p) => p.tool === "shell" && p.callID === "call_inner_1"),
      "expected nested shell toolCall to be extracted from dotted Code Mode call"
    );
  });

  test("4. Automation subagent run sessions (ses_aut_*) are treated as subagents and respect read-only capability", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v240-aut-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      updateNotice: { enabled: false },
    }));

    const { context, synthetics, pushEvent } = createV2TestHost(dir, {
      sessionGet: ({ sessionID }) => ({
        id: sessionID,
        // Even if parentID is omitted or present, ses_aut_ is an automation child run
        agent: "readonly-auditor",
        location: { directory: dir },
      }),
      agentList: () => [
        {
          name: "readonly-auditor",
          tools: { read: true, edit: false, shell: false, bash: false },
          permissions: [
            { action: "edit", resource: "*", effect: "deny" },
            { action: "shell", resource: "*", effect: "deny" },
          ],
        },
      ],
      sessionContext: () => [
        { id: "u1", type: "user", text: "Audit status." },
        { id: "a1", type: "assistant", content: [{ type: "text", text: "This failure is unrelated to our task." }] },
      ],
    });

    const cleanup = await Guardian.setup(context);
    t.after(async () => cleanup?.());

    await pushEvent({ type: "session.idle", data: { sessionID: "ses_aut_123_0" } });
    await new Promise((r) => setTimeout(r, 60));
    assert.equal(synthetics.length, 0, "read-only ses_aut_* automation run must not receive remediation");
  });

  test("5. plugin.updated clears agent capability cache and hot-reload setup -> dispose -> setup leaves no stale state", async (t) => {
    clearAllAgentCapabilities();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v240-reload-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      preflight: { enabled: true },
      updateNotice: { enabled: false },
    }));

    const { context, registeredHooks, disposed, pushEvent } = createV2TestHost(dir);
    const cleanup1 = await Guardian.setup(context);

    cacheAgentCapability("ses-cache-1", {
      capability: "read-only",
      evidence: { agentName: "stale", reasons: ["cached"] },
    });
    assert.ok(getCachedAgentCapability("ses-cache-1"));

    await pushEvent({ type: "plugin.updated", data: { id: "opencode-guardian" } });
    await new Promise((r) => setTimeout(r, 25));
    assert.equal(getCachedAgentCapability("ses-cache-1"), undefined, "plugin.updated must invalidate capability cache");

    await cleanup1?.();
    assert.ok(disposed.length >= 7, "all registered hooks must dispose on reload");

    // Re-initialize fresh instance (simulating v2.4.0 floating-specifier hot-reload)
    const cleanup2 = await Guardian.setup(context);
    assert.ok((registeredHooks.get("tool.execute.before")?.length ?? 0) === 1, "reloaded setup must register exactly one handler");
    await cleanup2?.();
  });
});

describe("OpenCode v2.4.1 Audit Regressions", () => {
  function createV2Host(projectDir, overrides = {}) {
    const registeredHooks = new Map();
    const synthetics = [];
    const eventQueue = [];
    let wakeEvent = null;

    const pushEvent = async (ev) => {
      eventQueue.push(ev);
      wakeEvent?.();
      await new Promise((r) => setImmediate(r));
    };

    const context = {
      location: { directory: projectDir },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              if (!eventQueue.length) {
                await new Promise((resolve) => {
                  wakeEvent = resolve;
                  signal.addEventListener("abort", resolve, { once: true });
                });
              }
              if (signal.aborted) break;
              const next = eventQueue.shift();
              if (next === null) break;
              if (next) yield next;
            }
          })();
        },
      },
      session: {
        async get({ sessionID }) {
          if (overrides.sessionGet) return overrides.sessionGet({ sessionID });
          return { id: sessionID, parentID: undefined, location: { directory: projectDir } };
        },
        async context({ sessionID }) {
          if (overrides.sessionContext) return overrides.sessionContext({ sessionID });
          return [];
        },
        async synthetic(req) {
          synthetics.push(req);
          return { id: "syn-1" };
        },
        async wait() {
          return { status: "idle" };
        },
        async hook(kind, cb) {
          const list = registeredHooks.get(`session.${kind}`) ?? [];
          list.push(cb);
          registeredHooks.set(`session.${kind}`, list);
          return {
            dispose() {
              const idx = list.indexOf(cb);
              if (idx >= 0) list.splice(idx, 1);
            },
          };
        },
      },
      tool: {
        async hook(kind, cb) {
          const list = registeredHooks.get(`tool.${kind}`) ?? [];
          list.push(cb);
          registeredHooks.set(`tool.${kind}`, list);
          return {
            dispose() {
              const idx = list.indexOf(cb);
              if (idx >= 0) list.splice(idx, 1);
            },
          };
        },
      },
      shell: {
        async hook(kind, cb) {
          const list = registeredHooks.get(`shell.${kind}`) ?? [];
          list.push(cb);
          registeredHooks.set(`shell.${kind}`, list);
          return {
            dispose() {
              const idx = list.indexOf(cb);
              if (idx >= 0) list.splice(idx, 1);
            },
          };
        },
      },
    };

    return { context, registeredHooks, synthetics, pushEvent };
  }

  test("1. experimental.job.updated running + experimental.idle share canonical keys for shell/subagent/video", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v241-jobkey-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      updateNotice: { enabled: false },
    }));

    const { context, registeredHooks, synthetics, pushEvent } = createV2Host(dir, {
      sessionContext: () => [
        { id: "u1", type: "user", text: "Fix the bug." },
        { id: "a1", type: "assistant", content: [{ type: "text", text: "This test failure is unrelated to my changes." }] },
      ],
    });

    const cleanup = await Guardian.setup(context);
    t.after(async () => cleanup?.());

    const expIdleCbs = registeredHooks.get("session.experimental.idle") ?? [];

    // 1) experimental.idle reports a running shell job (no `id` field, only `shellID`)
    for (const cb of expIdleCbs) {
      await cb({
        sessionID: "ses-key-1",
        background: [{ kind: "shell", sessionID: "ses-key-1", shellID: "sh_99", command: "npm test" }],
      });
    }

    // 2) experimental.job.updated reports the SAME shell job as running (has both `id` and `shellID`)
    await pushEvent({
      type: "experimental.job.updated",
      data: {
        info: {
          id: "job_opaque_99",
          sessionID: "ses-key-1",
          status: "running",
          kind: "shell",
          shellID: "sh_99",
          command: "npm test",
        },
      },
    });

    // 3) Now a second completion event arrives carrying ONLY shellID (or matching canonical key)
    await pushEvent({
      type: "experimental.job.updated",
      data: {
        info: {
          id: "job_different_or_restarted",
          sessionID: "ses-key-1",
          status: "completed",
          kind: "shell",
          shellID: "sh_99",
          command: "npm test",
        },
      },
    });

    // Because both running events mapped to canonical key `sh_99`, completing `sh_99` must unlock idle!
    await pushEvent({ type: "session.idle", data: { sessionID: "ses-key-1" } });
    for (let i = 0; i < 40 && synthetics.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 15));
    }
    assert.ok(synthetics.length >= 1, "expected idle inspection to unlock once canonical shell job completed");
  });

  test("2. session.deleted calls forgetMeshSession so deleted sessions do not leak mesh interventions", async (t) => {
    resetMeshStateForTests();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v241-meshdel-"));
    t.after(() => {
      resetMeshStateForTests();
      fs.rmSync(dir, { recursive: true, force: true });
    });
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      updateNotice: { enabled: false },
    }));

    const { context, pushEvent } = createV2Host(dir);
    const cleanup = await Guardian.setup(context);
    t.after(async () => cleanup?.());

    recordMeshIntervention({
      sessionID: "ses-del-mesh",
      directory: dir,
      owner: "opencode-guardian",
      kind: "post-remediation",
      ruleIds: ["discipline/no-evasion"],
      deterministic: false,
      active: true,
      updatedAt: Date.now(),
    });
    assert.ok(getLatestMeshIntervention("ses-del-mesh"));

    await pushEvent({ type: "session.deleted", data: { sessionID: "ses-del-mesh" } });
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(
      getLatestMeshIntervention("ses-del-mesh"),
      undefined,
      "session.deleted must forget mesh state for the deleted session"
    );
  });

  test("3. TUI subscribes to plugin.updated and config.updated for v2.4.x non-blocking startup & hot-reload recovery", async () => {
    const listeners = new Map();
    let unsubscribed = 0;
    let rpcCalls = 0;

    const cleanup = TuiPlugin.setup({
      location: { directory: process.cwd() },
      ui: {
        slot() {
          return () => {};
        },
        router: {
          current: () => ({ type: "session", sessionID: "ses-tui-1" }),
        },
      },
      data: {
        session: {
          get: (sid) => (sid === "ses-tui-1" ? { id: sid, location: { directory: process.cwd() } } : undefined),
        },
        on(type, cb) {
          listeners.set(type, cb);
          return () => {
            unsubscribed += 1;
            listeners.delete(type);
          };
        },
      },
      client: {
        rpc() {
          return {
            async latest() {
              rpcCalls += 1;
              return { active: false, title: "", message: "", variant: "info", duration: 0 };
            },
            async clear() {
              return { cleared: true };
            },
          };
        },
      },
    });

    assert.equal(typeof listeners.get("plugin.updated"), "function", "TUI must subscribe to plugin.updated");
    assert.equal(typeof listeners.get("config.updated"), "function", "TUI must subscribe to config.updated");

    await new Promise((r) => setTimeout(r, 20));
    const beforeCalls = rpcCalls;
    listeners.get("plugin.updated")?.({ type: "plugin.updated", data: {} });
    await new Promise((r) => setTimeout(r, 20));
    assert.ok(rpcCalls > beforeCalls, "plugin.updated must immediately trigger an intervention RPC refresh");

    cleanup?.();
    assert.ok(unsubscribed >= 4, "all data.on listeners (session.deleted, session.moved, plugin.updated, config.updated) must unsubscribe");
  });
});

describe("OpenCode v2.4.1 Execution Lifecycle", () => {
  function createEventHost(dir, messagesProvider, options = {}) {
    const eventQueue = [];
    let wake = null;
    const synthetics = [];
    const sessionHooks = new Map();

    const host = {
      location: { directory: dir },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              if (!eventQueue.length) {
                await new Promise((resolve) => {
                  wake = resolve;
                  signal.addEventListener("abort", resolve, { once: true });
                });
              }
              const next = eventQueue.shift();
              if (next === null) break;
              if (next) yield next;
            }
          })();
        },
      },
      session: {
        async get({ sessionID }) {
          return {
            id: sessionID,
            parentID: options.parentID,
            location: { directory: dir },
          };
        },
        async context({ sessionID }) {
          return messagesProvider(sessionID);
        },
        async synthetic(req) {
          synthetics.push(req);
          return { id: `syn-${synthetics.length}` };
        },
        async wait() {
          return { status: "idle" };
        },
        async hook(kind, cb) {
          const list = sessionHooks.get(kind) ?? [];
          list.push(cb);
          sessionHooks.set(kind, list);
          return {
            dispose() {
              const idx = list.indexOf(cb);
              if (idx >= 0) list.splice(idx, 1);
            },
          };
        },
      },
      tool: {
        async hook() {
          return { dispose() {} };
        },
      },
      shell: {
        async hook() {
          return { dispose() {} };
        },
      },
    };

    const pushEvent = async (ev) => {
      eventQueue.push(ev);
      wake?.();
      await new Promise((r) => setTimeout(r, 35));
    };

    const fireSessionHook = async (kind, payload) => {
      for (const cb of sessionHooks.get(kind) ?? []) {
        await cb(payload);
      }
    };

    return { host, synthetics, pushEvent, fireSessionHook };
  }

  test("1. Server inspects and remediates on OpenCode v2.4.1 session.execution.succeeded without session.idle", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v241-exec-ok-"));
    t.after(() => {
      clearGuardianTelemetryConfig_6();
      fs.rmSync(dir, { recursive: true, force: true });
    });
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      updateNotice: { enabled: false },
      telemetry: { level: "violations" },
    }));

    const messages = [
      { id: "u1", type: "user", text: "Fix the failing unit test." },
      {
        id: "a1",
        type: "assistant",
        agent: "build",
        content: [{ type: "text", text: "The test failure is unrelated to this change and pre-existing." }],
      },
    ];
    const { host, synthetics, pushEvent } = createEventHost(dir, () => messages);
    const cleanup = await Guardian.setup(host);
    t.after(async () => cleanup?.());

    // OpenCode v2.4.1 publishes session.execution.succeeded (never session.idle / session.status).
    await pushEvent({
      type: "session.execution.succeeded",
      location: { directory: dir },
      data: { sessionID: "ses-v241-root" },
    });

    assert.equal(synthetics.length, 1, "Guardian must queue remediation on session.execution.succeeded");
    const status = readGuardianStatus(dir);
    assert.equal(status.remediations, 1, "telemetry must record post-remediation");

    // Duplicate session.idle for the same assistant message must not double-remediate.
    await pushEvent({
      type: "session.idle",
      location: { directory: dir },
      data: { sessionID: "ses-v241-root" },
    });
    assert.equal(synthetics.length, 1, "duplicate idle event for same assistant message must be deduplicated");
  });

  test("2. hasUnfinishedBackgroundTool tracks background subagent start, completion, and warm child session reuse", () => {
    const childID = "ses_child_worker_1";

    // (a) Background subagent launched, not yet completed -> still unfinished
    const inFlightRaw = [
      { id: "u1", type: "user", text: "Delegate and verify." },
      {
        id: "a1",
        type: "assistant",
        agent: "hi-manager",
        content: [
          {
            type: "tool",
            id: "call_sub_1",
            name: "subagent",
            state: {
              status: "completed",
              input: { agent: "hi-coder", background: true },
              metadata: { sessionID: childID, status: "running", truncated: false },
            },
          },
          { type: "text", text: "Worker started." },
        ],
      },
    ];
    assert.equal(
      hasUnfinishedBackgroundTool(normalizeV2Messages(inFlightRaw, "ses-root")),
      true,
      "in-flight background subagent must defer root inspection"
    );

    // (b) Subagent completion synthetic arrives -> finished!
    const completedRaw = [
      ...inFlightRaw,
      {
        id: "syn1",
        type: "synthetic",
        text: `<background-result kind="subagent" sessionID="${childID}" state="completed">done</background-result>`,
        metadata: {
          source: "subagent",
          childID,
          agent: "hi-coder",
          state: "completed",
        },
      },
      {
        id: "a2",
        type: "assistant",
        agent: "hi-manager",
        content: [{ type: "text", text: "All done." }],
      },
    ];
    assert.equal(
      hasUnfinishedBackgroundTool(normalizeV2Messages(completedRaw, "ses-root")),
      false,
      "completed background subagent must NOT permanently block root inspection"
    );

    // (c) Warm reuse of the same child session -> must block while 2nd run is in-flight, unblock on 2nd completion
    const reusedInFlightRaw = [
      ...completedRaw,
      {
        id: "a3",
        type: "assistant",
        agent: "hi-manager",
        content: [
          {
            type: "tool",
            id: "call_sub_2",
            name: "subagent",
            state: {
              status: "completed",
              input: { agent: "hi-coder", sessionID: childID, background: true },
              metadata: { sessionID: childID, status: "running", truncated: false },
            },
          },
          { type: "text", text: "Sent follow-up to warm worker." },
        ],
      },
    ];
    assert.equal(
      hasUnfinishedBackgroundTool(normalizeV2Messages(reusedInFlightRaw, "ses-root")),
      true,
      "reused warm child session running a second time must defer root inspection"
    );

    const reusedCompletedRaw = [
      ...reusedInFlightRaw,
      {
        id: "syn2",
        type: "synthetic",
        text: `<background-result kind="subagent" sessionID="${childID}" state="completed">round 2 done</background-result>`,
        metadata: {
          source: "subagent",
          childID,
          agent: "hi-coder",
          state: "completed",
        },
      },
      {
        id: "a4",
        type: "assistant",
        agent: "hi-manager",
        content: [{ type: "text", text: "Round 2 verified." }],
      },
    ];
    assert.equal(
      hasUnfinishedBackgroundTool(normalizeV2Messages(reusedCompletedRaw, "ses-root")),
      false,
      "second completion of reused warm child session must unblock root inspection"
    );
  });

  test("3. End-to-end root session with background subagent defers while running and inspects once child finishes", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v241-subagent-e2e-"));
    t.after(() => {
      clearGuardianTelemetryConfig_6();
      fs.rmSync(dir, { recursive: true, force: true });
    });
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      updateNotice: { enabled: false },
      telemetry: { level: "violations" },
    }));

    const rootID = "ses-root-hi";
    const childID = "ses-child-coder";
    let messages = [
      { id: "u1", type: "user", text: "Fix the failing tests." },
      {
        id: "a1",
        type: "assistant",
        agent: "hi-manager",
        content: [
          {
            type: "tool",
            id: "call_sub_1",
            name: "subagent",
            state: {
              status: "completed",
              input: { agent: "hi-coder", background: true },
              metadata: { sessionID: childID, status: "running" },
            },
          },
          { type: "text", text: "The test failure is unrelated to this change; worker dispatched." },
        ],
      },
    ];

    const { host, synthetics, pushEvent, fireSessionHook } = createEventHost(dir, () => messages);
    const cleanup = await Guardian.setup(host);
    t.after(async () => cleanup?.());

    // Step 1: Child is still running -> experimental.idle reports background job -> execution.succeeded defers
    await fireSessionHook("experimental.idle", {
      sessionID: rootID,
      background: [{ kind: "subagent", sessionID: rootID, childSessionID: childID, agent: "hi-coder", description: "fix" }],
    });
    await pushEvent({
      type: "session.execution.succeeded",
      location: { directory: dir },
      data: { sessionID: rootID },
    });
    assert.equal(synthetics.length, 0, "must defer while background subagent is active");

    // Step 2: Child finishes, synthetic notice delivered, manager gives final violating answer
    messages = [
      ...messages,
      {
        id: "syn1",
        type: "synthetic",
        text: `<background-result kind="subagent" sessionID="${childID}" state="completed">done</background-result>`,
        metadata: { source: "subagent", childID, agent: "hi-coder", state: "completed" },
      },
      {
        id: "a2",
        type: "assistant",
        agent: "hi-manager",
        content: [{ type: "text", text: "The test failure is unrelated to this change and pre-existing." }],
      },
    ];
    await fireSessionHook("experimental.idle", {
      sessionID: rootID,
      background: [],
    });
    await pushEvent({
      type: "session.execution.succeeded",
      location: { directory: dir },
      data: { sessionID: rootID },
    });

    assert.equal(synthetics.length, 1, "Guardian must inspect and remediate root once background subagent completes");
  });

  test("4. TUI subscribes to session.execution.* events and refreshes immediately on session.execution.succeeded", async () => {
    const listeners = new Map();
    let rpcCalls = 0;

    const cleanup = TuiPlugin.setup({
      location: { directory: process.cwd() },
      ui: {
        slot() {
          return () => {};
        },
        router: {
          current: () => ({ type: "session", sessionID: "ses-tui-exec-1" }),
        },
      },
      data: {
        session: {
          get: (sid) => (sid === "ses-tui-exec-1" ? { id: sid, location: { directory: process.cwd() } } : undefined),
          status: () => "idle",
        },
        on(type, cb) {
          listeners.set(type, cb);
          return () => listeners.delete(type);
        },
      },
      client: {
        rpc() {
          return {
            async latest() {
              rpcCalls += 1;
              return { active: false, title: "", message: "", variant: "info", duration: 0 };
            },
            async clear() {
              return { cleared: true };
            },
          };
        },
      },
    });

    try {
      await new Promise((r) => setTimeout(r, 25));
      assert.equal(rpcCalls, 1, "initial RPC fetch");

      for (const evType of [
        "session.execution.started",
        "session.execution.succeeded",
        "session.execution.failed",
        "session.execution.interrupted",
      ]) {
        assert.equal(typeof listeners.get(evType), "function", `TUI must subscribe to ${evType}`);
      }

      listeners.get("session.execution.succeeded")?.({
        type: "session.execution.succeeded",
        data: { sessionID: "ses-tui-exec-1" },
      });
      await new Promise((r) => setTimeout(r, 30));
      assert.equal(rpcCalls, 2, "session.execution.succeeded must immediately trigger RPC intervention refresh");
    } finally {
      cleanup?.();
    }

    for (const evType of [
      "session.execution.started",
      "session.execution.succeeded",
      "session.execution.failed",
      "session.execution.interrupted",
    ]) {
      assert.equal(listeners.has(evType), false, `TUI cleanup must unsubscribe from ${evType}`);
    }
  });

  test("5. manifest/no-ghost-deps ignores URI scheme imports (data:, file:, http:, https:, bun:) while still blocking real ghost packages", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v241-ghost-uri-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({
      name: "uri-test-pkg",
      version: "1.0.0",
      dependencies: {},
    }));

    const engine = new GuardEngine({ enabled: true });

    // URI scheme imports must NOT trigger manifest/no-ghost-deps
    const cleanResult = await engine.inspect("ses-uri-ok", dir, [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Add dynamic module helper." }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "write",
            name: "write",
            state: {
              status: "completed",
              input: {
                filePath: path.join(dir, "loader.mjs"),
                content: [
                  'const a = await import("data:text/javascript,export default 1");',
                  'const b = await import("file:///tmp/example.mjs");',
                  'const c = await import("https://example.com/mod.mjs");',
                  'const d = await import("bun:sqlite");',
                  "export { a, b, c, d };",
                ].join("\n"),
              },
            },
          },
          { type: "text", text: "Added loader.mjs with URI imports." },
        ],
      },
    ]);
    const ghostFindingsClean = cleanResult.results.find((r) => r.ruleId === "manifest/no-ghost-deps")?.findings ?? [];
    assert.deepEqual(ghostFindingsClean, [], "URI scheme imports must not be flagged as undeclared npm packages");

    // Real undeclared npm package MUST still be caught
    const badResult = await engine.inspect("ses-uri-bad", dir, [
      { info: { id: "u2", role: "user" }, parts: [{ type: "text", text: "Add helper." }] },
      {
        info: { id: "a2", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "write",
            name: "write",
            state: {
              status: "completed",
              input: {
                filePath: path.join(dir, "bad.mjs"),
                content: 'import ghost from "totally-nonexistent-ghost-pkg";\nexport default ghost;\n',
              },
            },
          },
          { type: "text", text: "Added bad.mjs." },
        ],
      },
    ]);
    const ghostFindingsBad = badResult.results.find((r) => r.ruleId === "manifest/no-ghost-deps")?.findings ?? [];
    assert.equal(ghostFindingsBad.length > 0, true, "real undeclared package must still be flagged");
  });
});

describe("Multi-Location Single-Owner Deduplication", () => {
  function createSharedGlobalBus() {
    const subscribers = new Set();
    return {
      subscribe({ signal }) {
        const queue = [];
        let wake = null;
        const sub = {
          push(ev) {
            queue.push(ev);
            wake?.();
          },
        };
        subscribers.add(sub);
        const onAbort = () => {
          subscribers.delete(sub);
          wake?.();
        };
        signal.addEventListener("abort", onAbort, { once: true });
        return (async function* () {
          try {
            while (!signal.aborted) {
              if (!queue.length) {
                await new Promise((resolve) => {
                  wake = resolve;
                });
              }
              while (queue.length && !signal.aborted) {
                yield queue.shift();
              }
            }
          } finally {
            subscribers.delete(sub);
          }
        })();
      },
      async broadcast(ev, settleMs = 60) {
        for (const sub of Array.from(subscribers)) {
          sub.push(ev);
        }
        await new Promise((r) => setTimeout(r, settleMs));
      },
    };
  }

  function makeHost({ dir, bus, sessionsById, synthetics, interrupts = [] }) {
    return {
      location: { directory: dir },
      event: {
        subscribe: (opts) => bus.subscribe(opts),
      },
      session: {
        async get({ sessionID }) {
          const meta = sessionsById.get(sessionID);
          return {
            id: sessionID,
            parentID: meta?.parentID,
            location: { directory: meta?.directory ?? dir },
          };
        },
        async context({ sessionID }) {
          return sessionsById.get(sessionID)?.messages ?? [];
        },
        async synthetic(req) {
          synthetics.push({ ...req, viaDirectory: dir });
          return { id: `syn-${synthetics.length}` };
        },
        async interrupt({ sessionID }) {
          interrupts.push({ sessionID, viaDirectory: dir });
        },
        async wait() {
          return { status: "idle" };
        },
        async hook() {
          return { dispose() {} };
        },
      },
      tool: {
        async hook() {
          return { dispose() {} };
        },
      },
      shell: {
        async hook() {
          return { dispose() {} };
        },
      },
    };
  }

  test("1. Multi-location server: 3 Guardian instances on shared global event bus remediate a session EXACTLY ONCE", async (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-multiloc-"));
    const globalCfgDir = path.join(root, "global-opencode");
    const dirHi = path.join(root, "opencode-hi");
    const dirGuardian = path.join(root, "opencode-guardian");
    const dirRoot = path.join(root, "root-home");
    for (const d of [globalCfgDir, dirHi, dirGuardian, dirRoot]) {
      fs.mkdirSync(d, { recursive: true });
    }
    // Global install (same as real ~/.config/opencode/opencode.json with opencode-guardian@latest)
    fs.writeFileSync(
      path.join(globalCfgDir, "opencode.json"),
      JSON.stringify({ plugin: ["opencode-guardian@latest"] })
    );
    for (const d of [dirHi, dirGuardian, dirRoot]) {
      fs.writeFileSync(
        path.join(d, "opencode-guardian.json"),
        JSON.stringify({ enabled: true, updateNotice: { enabled: false }, telemetry: { level: "violations" } })
      );
    }

    const prevConfigDir = process.env.OPENCODE_CONFIG_DIR;
    process.env.OPENCODE_CONFIG_DIR = globalCfgDir;
    t.after(() => {
      if (prevConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
      else process.env.OPENCODE_CONFIG_DIR = prevConfigDir;
      clearGuardianTelemetryConfig_7();
      fs.rmSync(root, { recursive: true, force: true });
    });

    const bus = createSharedGlobalBus();
    const synthetics = [];
    const sessionsById = new Map([
      [
        "ses-hi-root",
        {
          directory: dirHi,
          messages: [
            { id: "u1", type: "user", text: "Fix the failing unit test." },
            {
              id: "a1",
              type: "assistant",
              agent: "hi-manager",
              content: [{ type: "text", text: "The test failure is unrelated to this change and pre-existing." }],
            },
          ],
        },
      ],
    ]);

    const cleanups = [];
    t.after(async () => {
      for (const c of cleanups.reverse()) await c?.();
    });

    // Boot 3 locations inside the same server process (mimics real opencode.exe serve --service)
    cleanups.push(await Guardian.setup(makeHost({ dir: dirHi, bus, sessionsById, synthetics })));
    cleanups.push(await Guardian.setup(makeHost({ dir: dirGuardian, bus, sessionsById, synthetics })));
    cleanups.push(await Guardian.setup(makeHost({ dir: dirRoot, bus, sessionsById, synthetics })));

    // Broadcast ONE session.execution.succeeded to ALL 3 instances (with event.location)
    await bus.broadcast({
      type: "session.execution.succeeded",
      location: { directory: dirHi },
      data: { sessionID: "ses-hi-root" },
    });

    assert.equal(
      synthetics.length,
      1,
      `expected exactly 1 remediation across 3 server locations, got ${synthetics.length}`
    );
    assert.equal(
      synthetics[0].viaDirectory,
      dirHi,
      "the owning location instance must perform the remediation"
    );
    assert.equal(readGuardianStatus(dirHi).remediations, 1, "telemetry must record exactly 1 remediation");
  });

  test("2. Overlapping reload instances for the SAME directory remediate EXACTLY ONCE and hand off cleanly on dispose", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-overlap-"));
    t.after(() => {
      clearGuardianTelemetryConfig_7();
      fs.rmSync(dir, { recursive: true, force: true });
    });
    fs.writeFileSync(
      path.join(dir, "opencode-guardian.json"),
      JSON.stringify({ enabled: true, updateNotice: { enabled: false }, telemetry: { level: "violations" } })
    );

    const bus = createSharedGlobalBus();
    const synthetics = [];
    const sessionsById = new Map([
      [
        "ses-overlap-1",
        {
          directory: dir,
          messages: [
            { id: "u1", type: "user", text: "Fix the failing test." },
            {
              id: "a1",
              type: "assistant",
              content: [{ type: "text", text: "The test failure is unrelated to this change and pre-existing." }],
            },
          ],
        },
      ],
    ]);

    const cleanup1 = await Guardian.setup(makeHost({ dir, bus, sessionsById, synthetics }));
    const cleanup2 = await Guardian.setup(makeHost({ dir, bus, sessionsById, synthetics }));
    t.after(async () => {
      await cleanup2?.();
      await cleanup1?.();
    });

    // Event without event.location (forces session.get lookup path too)
    await bus.broadcast({
      type: "session.execution.succeeded",
      data: { sessionID: "ses-overlap-1" },
    });
    assert.equal(synthetics.length, 1, `overlapping same-dir instances must send 1 remediation, got ${synthetics.length}`);

    // Dispose old instance; new instance must continue inspecting new turns
    await cleanup1?.();
    sessionsById.set("ses-overlap-2", {
      directory: dir,
      messages: [
        { id: "u2", type: "user", text: "Fix the other test." },
        {
          id: "a2",
          type: "assistant",
          content: [{ type: "text", text: "The test failure is unrelated to this change and pre-existing." }],
        },
      ],
    });
    await bus.broadcast({
      type: "session.execution.succeeded",
      location: { directory: dir },
      data: { sessionID: "ses-overlap-2" },
    });
    assert.equal(synthetics.length, 2, "surviving instance must handle subsequent sessions after old instance disposes");
  });

  test("3. Multi-location StreamLoopWatcher interrupts a looping session EXACTLY ONCE across 3 instances", async (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-multiloc-stream-"));
    const globalCfgDir = path.join(root, "global-opencode");
    const dirA = path.join(root, "proj-a");
    const dirB = path.join(root, "proj-b");
    const dirC = path.join(root, "proj-c");
    for (const d of [globalCfgDir, dirA, dirB, dirC]) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(path.join(globalCfgDir, "opencode.json"), JSON.stringify({ plugin: ["opencode-guardian@latest"] }));
    for (const d of [dirA, dirB, dirC]) {
      fs.writeFileSync(path.join(d, "opencode-guardian.json"), JSON.stringify({ enabled: true, updateNotice: { enabled: false } }));
    }

    const prevConfigDir = process.env.OPENCODE_CONFIG_DIR;
    process.env.OPENCODE_CONFIG_DIR = globalCfgDir;
    t.after(() => {
      if (prevConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
      else process.env.OPENCODE_CONFIG_DIR = prevConfigDir;
      clearGuardianTelemetryConfig_7();
      fs.rmSync(root, { recursive: true, force: true });
    });

    const bus = createSharedGlobalBus();
    const synthetics = [];
    const interrupts = [];
    const sessionsById = new Map([["ses-loop-a", { directory: dirA, messages: [] }]]);

    const cleanups = [];
    t.after(async () => {
      for (const c of cleanups.reverse()) await c?.();
    });
    cleanups.push(await Guardian.setup(makeHost({ dir: dirA, bus, sessionsById, synthetics, interrupts })));
    cleanups.push(await Guardian.setup(makeHost({ dir: dirB, bus, sessionsById, synthetics, interrupts })));
    cleanups.push(await Guardian.setup(makeHost({ dir: dirC, bus, sessionsById, synthetics, interrupts })));

    await bus.broadcast(
      {
        type: "session.reasoning.delta",
        location: { directory: dirA },
        data: {
          sessionID: "ses-loop-a",
          assistantMessageID: "msg-loop-1",
          ordinal: 0,
          delta: "Hmm... ".repeat(35),
        },
      },
      80
    );

    assert.equal(interrupts.length, 1, `expected exactly 1 stream interrupt across 3 locations, got ${interrupts.length}`);
    assert.equal(interrupts[0].viaDirectory, dirA, "interrupt must be issued by the owning location instance");
  });

  test("4. Single global Guardian instance still supervises a second directory when no dedicated instance exists there", async (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-single-global-"));
    const globalCfgDir = path.join(root, "global-opencode");
    const dirA = path.join(root, "proj-a");
    const dirB = path.join(root, "proj-b");
    for (const d of [globalCfgDir, dirA, dirB]) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(path.join(globalCfgDir, "opencode.json"), JSON.stringify({ plugin: ["opencode-guardian@latest"] }));
    fs.writeFileSync(path.join(dirA, "opencode-guardian.json"), JSON.stringify({ enabled: true, updateNotice: { enabled: false } }));

    const prevConfigDir = process.env.OPENCODE_CONFIG_DIR;
    process.env.OPENCODE_CONFIG_DIR = globalCfgDir;
    t.after(() => {
      if (prevConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
      else process.env.OPENCODE_CONFIG_DIR = prevConfigDir;
      clearGuardianTelemetryConfig_7();
      fs.rmSync(root, { recursive: true, force: true });
    });

    const bus = createSharedGlobalBus();
    const synthetics = [];
    const sessionsById = new Map([
      [
        "ses-in-b",
        {
          directory: dirB,
          messages: [
            { id: "u1", type: "user", text: "Fix the bug." },
            {
              id: "a1",
              type: "assistant",
              content: [{ type: "text", text: "The test failure is unrelated to this change and pre-existing." }],
            },
          ],
        },
      ],
    ]);

    const cleanup = await Guardian.setup(makeHost({ dir: dirA, bus, sessionsById, synthetics }));
    t.after(async () => cleanup?.());

    await bus.broadcast({
      type: "session.execution.succeeded",
      location: { directory: dirB },
      data: { sessionID: "ses-in-b" },
    });

    assert.equal(synthetics.length, 1, "single global instance must still supervise projectB when no instance owns projectB");
  });

  test("5. TUI sidebar header stays clean next to version and conversation banner shows distinct intervention type badges", () => {
    const source = fs.readFileSync(new URL("../src/tui.tsx", import.meta.url), "utf8");
    const runtime = fs.readFileSync(new URL("../dist/tui-runtime.js", import.meta.url), "utf8");

    // Sidebar header must NOT cram inline `· ${statusLabel()}` next to the version
    assert.doesNotMatch(source, /· \$\{statusLabel\(\)\}/, "status/warning text must not clutter the version header row");

    // Conversation banner must clearly distinguish every intervention type
    for (const badge of ["⊘ BLOCKED", "↻ REMEDIATION", "⏹ STREAM STOP", "▲ WARNING"]) {
      assert.ok(source.includes(badge), `src/tui.tsx must define distinct badge ${badge}`);
      assert.ok(runtime.includes(badge), `dist/tui-runtime.js must emit distinct badge ${badge}`);
    }
  });
});

describe("Disabled Adapter No-Op Guarantees", () => {
  function disabledDirectory(t) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-disabled-adapter-"));
    const oldState = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"),
      JSON.stringify({ enabled: false, preflight: { enabled: true } }));
    t.after(() => {
      if (oldState === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = oldState;
      fs.rmSync(directory, { recursive: true, force: true });
    });
    return directory;
  }

  test("disabled V2 plugin does not subscribe or register hooks", async (t) => {
    const directory = disabledDirectory(t);
    const cleanup = await Guardian.setup({ location: { directory },
      event: { subscribe() { assert.fail("disabled plugin must not subscribe"); } },
      session: {
        async context() { assert.fail("disabled plugin must not inspect context"); },
        async synthetic() { assert.fail("disabled plugin must not send remediation"); },
        async hook() { assert.fail("disabled plugin must not install task hooks"); },
      },
      tool: { async hook() { assert.fail("disabled plugin must not install preflight"); } },
    });
    assert.equal(cleanup, undefined);
    assert.equal(readGuardianStatus().preflight, "disabled");
  });
});

describe("Session Cancellation & Error Redaction", () => {
  function directory(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-debug-fixture-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    return root;
  }

  const options = { notifications: { enabled: false }, updateNotice: { enabled: false }, secrets: { enabled: false } };

  test('V2 native session.deleted clears cached capability and task guidance', async (t) => {
    const root = directory(t);
    let promptHook;
    let contextHook;
    let emitEvent;
    const host = {
      location: { directory: root },
      options,
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              const next = await new Promise((resolve) => { emitEvent = resolve; });
              if (next === null) break;
              yield next;
            }
          })();
        },
      },
      session: {
        async context() { return []; },
        async synthetic() {},
        async hook(name, handler) {
          if (name === 'prompt') promptHook = handler;
          if (name === 'context') contextHook = handler;
          return { dispose() {} };
        },
      },
    };
    const cleanup = await Guardian.setup(host);
    t.after(() => cleanup());
    await promptHook({
      sessionID: 'deleted',
      prompt: { text: 'Implement the change, run all tests and review the source.' },
    });
    cacheAgentCapability('deleted', { capability: 'write-allowed', evidence: { reasons: [] } });
    const before = { system: [] };
    await contextHook({ sessionID: 'deleted', system: before.system });
    assert.ok(before.system.length > 0, 'fixture must first establish task guidance');
    emitEvent({ type: 'session.deleted', data: { sessionID: 'deleted' } });
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(getCachedAgentCapability('deleted'), undefined);
    const after = { system: [] };
    await contextHook({ sessionID: 'deleted', system: after.system });
    assert.deepEqual(after.system, []);
    emitEvent(null);
  });

  for (const cancellation of ['session.deleted', 'new human prompt', 'attachment-only prompt']) {
    test(`V2 ${cancellation} cancels an in-flight idle inspection`, async (t) => {
      const root = directory(t);
      const entered = Promise.withResolvers();
      const release = Promise.withResolvers();
      const prompts = [];
      let promptHook;
      let emitEvent;
      const host = {
        location: { directory: root },
        options,
        event: {
          subscribe({ signal }) {
            return (async function* () {
              while (!signal.aborted) {
                const next = await new Promise((resolve) => { emitEvent = resolve; });
                if (next === null) break;
                yield next;
              }
            })();
          },
        },
        session: {
          async get() { return { id: 'session', parentID: undefined }; },
          async context() { entered.resolve(); return release.promise; },
          async synthetic(input) { prompts.push(input); },
          async hook(name, handler) {
            if (name === 'prompt') promptHook = handler;
            return { dispose() {} };
          },
        },
      };
      const cleanup = await Guardian.setup(host);
      t.after(() => cleanup());
      emitEvent({ type: 'session.idle', data: { sessionID: 'session' } });
      await entered.promise;
      if (cancellation === 'session.deleted') {
        emitEvent({ type: 'session.deleted', data: { sessionID: 'session' } });
        await new Promise((r) => setTimeout(r, 20));
      } else {
        await promptHook({
          sessionID: 'session',
          prompt: cancellation === 'attachment-only prompt'
            ? { text: '' }
            : { text: 'Continue with the new task.' },
        });
      }
      release.resolve([
        { id: 'old-human', type: 'user', text: 'Complete this task.' },
        { id: 'old-assistant', type: 'assistant', content: [{ type: 'text', text: 'I am sorry.' }] },
      ]);
      await new Promise((r) => setTimeout(r, 40));
      assert.deepEqual(prompts, [], 'stale assistant output must not trigger a new model turn');
      emitEvent(null);
    });
  }

  for (const prompt of [
    { label: 'text', text: 'Explain the architecture.' },
    { label: 'empty', text: '' },
  ]) {
    test(`V2 new ${prompt.label} prompt clears guidance from the previous human task`, async (t) => {
      const root = directory(t);
      let promptHook;
      let contextHook;
      const host = {
        location: { directory: root },
        options,
        event: { subscribe: () => (async function* () {})() },
        session: {
          async context() { return []; },
          async synthetic() {},
          async hook(name, handler) {
            if (name === 'prompt') promptHook = handler;
            if (name === 'context') contextHook = handler;
            return { dispose() {} };
          },
        },
      };
      const cleanup = await Guardian.setup(host);
      t.after(() => cleanup());
      await promptHook({
        sessionID: 'session',
        prompt: { text: 'Implement the change, run all tests and review the source.' },
      });
      await promptHook({ sessionID: 'session', prompt: { text: prompt.text } });
      const output = { system: [] };
      await contextHook({ sessionID: 'session', system: output.system });
      assert.deepEqual(output.system, []);
    });
  }

  test('V2 session deletion prevents a suspended capability query from reviving its cache', async (t) => {
    const root = directory(t);
    const entered = Promise.withResolvers();
    const release = Promise.withResolvers();
    let emitEvent;
    const host = {
      location: { directory: root },
      options,
      agent: { async list() { entered.resolve(); return release.promise; } },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              const next = await new Promise((resolve) => { emitEvent = resolve; });
              if (next === null) break;
              yield next;
            }
          })();
        },
      },
      session: {
        async get() { return { id: 'child', parentID: 'parent' }; },
        async context() {
          return [
            { id: 'human', type: 'user', text: 'Complete the task.' },
            { id: 'assistant', type: 'assistant', agent: 'worker', content: [{ type: 'text', text: 'I am sorry.' }] },
          ];
        },
        async synthetic() { assert.fail('deleted child must not receive remediation'); },
      },
    };
    const cleanup = await Guardian.setup(host);
    t.after(() => cleanup());
    emitEvent({ type: 'session.idle', data: { sessionID: 'child' } });
    await entered.promise;
    emitEvent({ type: 'session.deleted', data: { sessionID: 'child' } });
    await new Promise((r) => setTimeout(r, 20));
    release.resolve([{ name: 'worker', permission: [{ permission: 'edit', pattern: '*', action: 'allow' }] }]);
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(getCachedAgentCapability('child'), undefined);
    emitEvent(null);
  });

  for (const field of ['password', 'metadata', 'cause', 'errors']) {
    test(`nested Error.${field} cannot leak credentials through tool output`, () => {
      const credential = 'synthetic-error-credential-493827';
      const nested = field === 'password' ? credential
        : field === 'errors' ? [{ password: credential }] : { password: credential };
      const error = Object.assign(new Error('Request failed'), { [field]: nested });
      const result = sanitizeToolResult({ output: 'failed', error }, { includeRuntimeEnv: false });
      assert.equal(JSON.stringify(result).includes(credential), false);
      assert.equal(result.error instanceof Error, true, 'sanitization must preserve Error semantics');
    });
  }

  test('Error cause is redacted even when it is non-enumerable', () => {
    const credential = 'synthetic-cause-credential-284619';
    const error = new Error('Request failed', { cause: { password: credential } });
    const result = sanitizeObject({ error }, { includeRuntimeEnv: false }).sanitized;
    assert.equal(JSON.stringify(result.error.cause).includes(credential), false);
  });

  test('reserved JSON keys remain own properties after object sanitization', () => {
    const input = JSON.parse('{"__proto__":{"password":"synthetic-password-1234"},"output":"ok"}');
    const result = sanitizeObject(input, { includeRuntimeEnv: false }).sanitized;
    assert.equal(Object.hasOwn(result, '__proto__'), true);
    assert.equal(Object.getPrototypeOf(result), Object.prototype);
    assert.deepEqual(JSON.parse(JSON.stringify(result)), JSON.parse('{"__proto__":{"password":"[REDACTED]"},"output":"ok"}'));
  });

  for (const wrap of [value => value, value => Object.assign(new Error('Request failed'), value)]) {
    test('tool serialization cannot execute an untrusted toJSON callback', () => {
      const credential = 'synthetic-serializer-credential-483921';
      const result = sanitizeToolResult({ output: 'failed', detail: wrap({
        toJSON() { return { password: credential }; },
      }) }, { includeRuntimeEnv: false });
      assert.equal(JSON.stringify(result).includes(credential), false);
    });
  }

  test('Broad allow map does not override a file mutation channel deny', () => {
    const profile = evaluateAgentMutationProfile({
      tools: { write_file: true },
      permission: { '*': 'allow', edit: 'deny', bash: 'deny' },
    });
    assert.notEqual(profile.capability, 'write-allowed');
  });

  for (const permission of ['deny', 'ask', { '*': 'deny' }]) {
    test(`Mutating tool permission map ${JSON.stringify(permission)} cannot grant autonomous writes`, () => {
      const profile = evaluateAgentMutationProfile({
        tools: { write_file: true },
        permission: { edit: 'deny', bash: 'deny', write_file: permission },
      });
      assert.notEqual(profile.capability, 'write-allowed');
      if (permission === 'ask') assert.equal(profile.capability, 'write-requires-approval');
    });
  }
});

describe("Deep Runtime & Config Merge Regressions", () => {
  async function loadTuiInVm() {
    const states = [];
    const realm = vm.createContext({
      console,
      URL,
      AbortController,
      process,
      setInterval,
      clearInterval,
      setTimeout,
      clearTimeout,
    });
    const url = new URL("../dist/tui-runtime.js", import.meta.url);
    const mod = new vm.SourceTextModule(fs.readFileSync(url, "utf8"), {
      context: realm,
      identifier: url.href,
      initializeImportMeta(meta) {
        meta.url = url.href;
      },
    });
    const renderer = {
      createComponent: (component, props) => ({ component: component.name, props }),
      createElement: (name) => ({ name }),
      createTextNode: (text) => ({ text }),
      insertNode() {},
      insert() {},
      setProp() {},
      effect() {},
      memo: (fn) => fn,
    };
    const solid = {
      createEffect(fn) {
        fn();
      },
      createSignal: (value) => {
        const record = { value };
        states.push(record);
        return [
          () => record.value,
          (next) => {
            record.value = typeof next === "function" ? next(record.value) : next;
          },
        ];
      },
      onCleanup() {},
      Show: (props) => props,
    };
    await mod.link(async (specifier, ref) => {
      let exports;
      if (specifier === "opentui:runtime-module:solid-js") exports = solid;
      else if (specifier === "opentui:runtime-module:%40opentui%2Fsolid") exports = renderer;
      else
        exports = await import(
          specifier.startsWith(".") ? new URL(specifier, ref.identifier).href : specifier
        );
      const keys = Object.keys(exports);
      return new vm.SyntheticModule(
        keys,
        function () {
          for (const k of keys) this.setExport(k, exports[k]);
        },
        { context: realm }
      );
    });
    await mod.evaluate();
    return { TuiPlugin: mod.namespace.default, states };
  }

  test("1. TUI RPC polling does not reset local TTL or resurrect click-dismissed intervention banners", async (t) => {
    if (typeof vm.SourceTextModule !== "function") {
      const child = spawnSync(
        process.execPath,
        [
          "--experimental-vm-modules",
          "--test",
          "--test-name-pattern=TUI RPC polling",
          fileURLToPath(import.meta.url),
        ],
        { encoding: "utf8", timeout: 10000 }
      );
      assert.equal(child.status, 0, `TUI VM test failed:\n${child.stdout}\n${child.stderr}`);
      return;
    }
    const { TuiPlugin } = await loadTuiInVm();
    const prevTtl = process.env.OPENCODE_GUARDIAN_INTERVENTION_TTL_MS;
    process.env.OPENCODE_GUARDIAN_INTERVENTION_TTL_MS = "1000";
    t.after(() => {
      if (prevTtl === undefined) delete process.env.OPENCODE_GUARDIAN_INTERVENTION_TTL_MS;
      else process.env.OPENCODE_GUARDIAN_INTERVENTION_TTL_MS = prevTtl;
    });

    // Server returns active snapshot even for 700ms after click-to-dismiss (simulating async clear latency)
    let serverActive = true;
    let clearResolve;
    const slots = [];
    const disposeTui = await TuiPlugin.setup({
      location: { directory: "/tmp/proj-tui-race" },
      client: {
        rpc: () => ({
          latest: async () =>
            serverActive
              ? {
                  active: true,
                  title: "GUARDIAN · WARNING",
                  message: "Advisory Rule Triggered: discipline/no-apology",
                  variant: "warning",
                  duration: 1000,
                }
              : { active: false, title: "", message: "", variant: "info", duration: 0 },
          clear: async () => {
            await new Promise((r) => {
              clearResolve = r;
            });
            serverActive = false;
            return { cleared: true };
          },
        }),
      },
      data: {
        session: {
          get: (id) => ({ id, location: { directory: "/tmp/proj-tui-race" } }),
        },
        on: () => () => {},
      },
      ui: {
        slot: (claim) => {
          slots.push(claim);
          return () => {};
        },
        router: {
          current: () => ({ type: "session", sessionID: "s-race" }),
        },
        toast: { show: () => {} },
      },
      command: { register: () => () => {} },
      keymap: { layer: () => () => {} },
    });
    t.after(() => disposeTui?.());

    await new Promise((r) => setTimeout(r, 50));
    const composerSlot = slots.find((s) => s.append === "session.composer.top");
    assert.ok(composerSlot, "expected session.composer.top slot");

    const rendered1 = composerSlot.render({ sessionID: "s-race" });
    assert.ok(rendered1?.props?.payload, "banner should initially be visible");

    // User clicks banner to dismiss while clear RPC is still in-flight on server
    rendered1.props.onDismiss();
    assert.equal(composerSlot.render({ sessionID: "s-race" })?.props?.payload, undefined, "banner dismissed immediately");

    // Wait 600ms so the 500ms TUI rpcPoll ticks while serverActive is still true
    await new Promise((r) => setTimeout(r, 600));
    const afterPoll = composerSlot.render({ sessionID: "s-race" });
    clearResolve?.();
    assert.equal(
      afterPoll?.props?.payload,
      undefined,
      "500ms RPC poll must NOT resurrect a banner the user already clicked to dismiss"
    );
  });

  test("2. Paired V2 idle events (session.status: idle + session.idle) do not wipe active remediation lease or mesh intervention", async (t) => {
    resetMeshStateForTests();
    t.after(() => resetMeshStateForTests());

    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-paired-idle-"));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));

    const eventQueue = [];
    let wake = null;
    const pushEvent = async (ev) => {
      eventQueue.push(ev);
      wake?.();
    };

    const cleanup = await Guardian.setup({
      location: { directory: root },
      options: {
        enabled: true,
        secrets: { enabled: false },
        rules: { "discipline/no-apology": "error" },
      },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              if (!eventQueue.length) {
                await new Promise((resolve) => {
                  wake = resolve;
                  signal.addEventListener("abort", resolve, { once: true });
                });
              }
              const next = eventQueue.shift();
              if (!next || signal.aborted) break;
              yield next;
            }
          })();
        },
      },
      tool: { hook: async () => ({ dispose() {} }) },
      session: {
        get: async ({ sessionID }) => ({ id: sessionID, location: { directory: root } }),
        context: async () => [
          { id: "u1", type: "user", text: "Fix the bug" },
          {
            id: "a1",
            type: "assistant",
            content: [{ type: "text", text: "I deeply apologize, I am terribly sorry for the mistake." }],
          },
        ],
        synthetic: async () => {},
        hook: async () => ({ dispose() {} }),
      },
    });
    t.after(async () => {
      eventQueue.push(null);
      wake?.();
      await cleanup?.();
    });

    await pushEvent({ type: "session.status", data: { sessionID: "s-paired", status: { type: "idle" } } });
    await new Promise((r) => setTimeout(r, 25));
    assert.equal(isSessionRemediating("s-paired"), true, "remediation lease active after first idle event");
    assert.equal(getLatestMeshIntervention("s-paired")?.active, true, "mesh intervention active after first idle event");

    // Second paired event arrives before assistant has produced a new message
    await pushEvent({ type: "session.idle", data: { sessionID: "s-paired" } });
    await new Promise((r) => setTimeout(r, 30));

    assert.equal(
      isSessionRemediating("s-paired"),
      true,
      "duplicate session.idle on same assistant message must NOT release active remediation lease"
    );
    assert.equal(
      getLatestMeshIntervention("s-paired")?.active,
      true,
      "duplicate session.idle on same assistant message must NOT clear active mesh intervention"
    );
  });

  test("3. remediationStatus 'verified' with a new post-warning on the same turn still clears on next human prompt", async (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-verified-warn-"));
    const fileA = path.join(root, "a.ts");
    fs.writeFileSync(fileA, "export function run() { throw new Error('not implemented'); }\n");
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));

    const eventQueue = [];
    let wake = null;
    const pushEvent = async (ev) => {
      eventQueue.push(ev);
      wake?.();
      await new Promise((r) => setTimeout(r, 30));
    };

    let rpcHandler;
    const hooks = new Map();
    let turnMessages = [
      { id: "u1", type: "user", text: "Implement run()" },
      {
        id: "a1",
        type: "assistant",
        content: [
          {
            type: "tool",
            id: "c1",
            name: "write",
            state: {
              status: "completed",
              input: { path: "a.ts", content: "export function run() { throw new Error('not implemented'); }\n" },
            },
          },
        ],
      },
    ];

    const cleanup = await Guardian.setup({
      location: { directory: root },
      options: {
        enabled: true,
        secrets: { enabled: false },
        rules: {
          "integrity/no-stubs": "error",
          "discipline/no-apology": "warn",
        },
      },
      rpc: {
        register: async (def, handler) => {
          if (def.id === GUARDIAN_INTERVENTION_RPC_DEFINITION.id) {
            rpcHandler = handler;
          }
          return { dispose() {} };
        },
      },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              if (!eventQueue.length) {
                await new Promise((resolve) => {
                  wake = resolve;
                  signal.addEventListener("abort", resolve, { once: true });
                });
              }
              const next = eventQueue.shift();
              if (!next || signal.aborted) break;
              yield next;
            }
          })();
        },
      },
      tool: { hook: async () => ({ dispose() {} }) },
      session: {
        get: async ({ sessionID }) => ({ id: sessionID, location: { directory: root } }),
        context: async () => turnMessages,
        synthetic: async (payload) => {
          turnMessages.push({
            id: "g1",
            type: "user",
            text: payload.text,
            metadata: payload.metadata,
          });
        },
        hook: async (name, cb) => {
          hooks.set(name, cb);
          return { dispose() {} };
        },
      },
    });
    t.after(async () => {
      eventQueue.push(null);
      wake?.();
      await cleanup?.();
    });

    // Round 1: blocks on integrity/no-stubs
    await pushEvent({ type: "session.idle", data: { sessionID: "s-vw" } });

    // Round 2: fixes the stub on disk (verified!) BUT emits an apology warning
    fs.writeFileSync(fileA, "export function run() { return 42; }\n");
    turnMessages.push({
      id: "a2",
      type: "assistant",
      content: [
        {
          type: "tool",
          id: "c2",
          name: "write",
          state: {
            status: "completed",
            input: { path: "a.ts", content: "export function run() { return 42; }\n" },
          },
        },
        {
          type: "text",
          text: "I deeply apologize, I am terribly sorry for the earlier stub.",
        },
      ],
    });
    await pushEvent({ type: "session.idle", data: { sessionID: "s-vw" } });

    const snapAfterWarn = await rpcHandler[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID: "s-vw" });
    assert.equal(snapAfterWarn.active, true);
    assert.equal(snapAfterWarn.variant, "warning");

    // User submits a new prompt -> warning banner MUST clear immediately
    await hooks.get("prompt")({
      sessionID: "s-vw",
      messageID: "u2",
      prompt: { text: "Next task" },
    });
    const snapAfterPrompt = await rpcHandler[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID: "s-vw" });
    assert.equal(
      snapAfterPrompt.active,
      false,
      "New human prompt must clear warning emitted on a remediation-verified turn"
    );
  });

  test("4. shell.hook('create.before') uses env.OPENCODE_SESSION_ID and cannot be bypassed via cwd: '/tmp'", async (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-shell-cwd-"));
    fs.mkdirSync(path.join(root, ".git"), { recursive: true });
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));

    const origConfigDir = process.env.OPENCODE_CONFIG_DIR;
    process.env.OPENCODE_CONFIG_DIR = path.join(root, "isolated-global");
    t.after(() => {
      if (origConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
      else process.env.OPENCODE_CONFIG_DIR = origConfigDir;
    });

    let shellBeforeCb;
    const cleanup = await Guardian.setup({
      location: { directory: root },
      options: {
        enabled: true,
        preflight: { enabled: true },
        secrets: { enabled: false },
      },
      event: { subscribe: () => (async function* () {})() },
      tool: { hook: async () => ({ dispose() {} }) },
      shell: {
        hook: async (name, cb) => {
          if (name === "create.before") shellBeforeCb = cb;
          return { dispose() {} };
        },
      },
      session: {
        get: async ({ sessionID }) => ({ id: sessionID, location: { directory: root } }),
        context: async () => [],
        synthetic: async () => {},
        hook: async () => ({ dispose() {} }),
      },
    });
    t.after(async () => await cleanup?.());

    await assert.rejects(
      () =>
        shellBeforeCb({
          command: "rm -rf /",
          cwd: "/tmp",
          timeout: 120000,
          shell: "/bin/bash",
          env: { OPENCODE_SESSION_ID: "ses-cwd" },
        }),
      /Tool execution rejected/,
      "shell.create.before must not allow bypassing preflight by setting cwd to /tmp"
    );
  });

  test("5. experimental.idle ignores descendant-owned background jobs and hasUnfinishedBackgroundTool detects v2.3.1 timed-out-to-background shells", async (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-bg-descendant-"));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));

    const eventQueue = [];
    let wake = null;
    const pushEvent = async (ev) => {
      eventQueue.push(ev);
      wake?.();
      await new Promise((r) => setTimeout(r, 30));
    };

    const synthetics = [];
    const hooks = new Map();
    const cleanup = await Guardian.setup({
      location: { directory: root },
      options: {
        enabled: true,
        secrets: { enabled: false },
        rules: { "discipline/no-apology": "error" },
      },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              if (!eventQueue.length) {
                await new Promise((resolve) => {
                  wake = resolve;
                  signal.addEventListener("abort", resolve, { once: true });
                });
              }
              const next = eventQueue.shift();
              if (!next || signal.aborted) break;
              yield next;
            }
          })();
        },
      },
      tool: { hook: async () => ({ dispose() {} }) },
      session: {
        get: async ({ sessionID }) => ({ id: sessionID, location: { directory: root } }),
        context: async () => [
          { id: "u1", type: "user", text: "Fix it" },
          { id: "a1", type: "assistant", content: [{ type: "text", text: "I deeply apologize, I am terribly sorry." }] },
        ],
        synthetic: async (p) => synthetics.push(p),
        hook: async (name, cb) => {
          hooks.set(name, cb);
          return { dispose() {} };
        },
      },
    });
    t.after(async () => {
      eventQueue.push(null);
      wake?.();
      await cleanup?.();
    });

    // Descendant subagent owns the background job, NOT parent "s-parent"
    hooks.get("experimental.idle")({
      sessionID: "s-parent",
      background: [{ kind: "shell", sessionID: "s-child-descendant", shellID: "sh_1", command: "sleep 10" }],
    });
    await pushEvent({ type: "session.idle", data: { sessionID: "s-parent" } });
    assert.equal(
      synthetics.length,
      1,
      "descendant-owned background jobs in experimental.idle must not permanently suppress parent session.idle"
    );
  });

  test("6. question_presented handoff waits for user reply without falling through to re-block, and consumes handoff on user reply", async () => {
    resetMeshStateForTests();
    const engine = new GuardEngine({
      enabled: true,
      remediationBudget: 2,
      rules: { "runtime/circuit-breaker": "error" },
    });

    const turn1 = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Deploy the service" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          { type: "tool", tool: "bash", state: { status: "error", input: { command: "deploy" }, error: "401 Unauthorized: missing API key" } },
          { type: "tool", tool: "bash", state: { status: "error", input: { command: "deploy" }, error: "401 Unauthorized: missing API key" } },
          { type: "tool", tool: "bash", state: { status: "error", input: { command: "deploy" }, error: "401 Unauthorized: missing API key" } },
        ],
      },
    ];

    const r1 = await engine.inspect("s-q", "/tmp", turn1);
    assert.equal(r1.decision, "block");
    assert.ok(getActiveMeshHandoff("s-q"), "mesh handoff should be active");

    const turn2 = [
      ...turn1,
      {
        info: { id: "g1", role: "user" },
        parts: [{ type: "text", text: r1.combinedRemediationPrompt, synthetic: true }],
      },
      {
        info: { id: "a2", role: "assistant" },
        parts: [{ type: "tool", tool: "ask_question", state: { status: "completed", input: { question: "What is the API key?" } } }],
      },
    ];

    const r2 = await engine.inspect("s-q", "/tmp", turn2);
    assert.equal(r2.decision, "pass");

    // Second idle inspection while still waiting on user reply (with a new assistant part or re-inspection)
    const turn2b = [
      ...turn2.slice(0, -1),
      {
        info: { id: "a2-followup", role: "assistant" },
        parts: [{ type: "text", text: "Waiting for your answer to the question above." }],
      },
    ];
    const r2b = await engine.inspect("s-q", "/tmp", turn2b);
    assert.equal(
      r2b.decision,
      "pass",
      "While question_presented is awaiting user reply, engine must not fall through and re-block"
    );
    resetMeshStateForTests();
  });

  test("7. splitShellStages does not split 2>&1 redirections, and evaluatePreflight blocks 'git 2>&1 reset --hard', PowerShell '-ec', and multi-stage 'true && printenv'", () => {
    assert.deepEqual(splitShellStages("git 2>&1 reset --hard"), [["git 2>&1 reset --hard"]]);
    assert.equal(evaluatePreflight("bash", { command: "git 2>&1 reset --hard" }), "destructive-command");
    assert.equal(
      evaluatePreflight("process_start", { executable: "powershell", args: ["-ec", "cm0gLXJmIC8="] }),
      "uninspectable-shell-input"
    );
    assert.equal(evaluatePreflight("bash", { command: "true && printenv" }), "high-risk-environment-dump");
    assert.equal(
      evaluatePreflight("bash", { command: 'git commit -m "fix: avoid docker inspect in tests"' }),
      undefined,
      "quoted commit message mentioning docker inspect must not trigger high-risk-environment-dump"
    );
  });

  test("8. evaluateFileMutationPreflight allows deletion-only patches and respects per-file markdown exemptions in apply_patch, and Rust lifetimes do not hide stubs/truncation", () => {
    const deleteLinePatch = [
      "*** Begin Patch",
      "*** Update File: src/a.ts",
      "@@",
      "-const unused = 1;",
      " const used = 2;",
      "*** End Patch",
    ].join("\n");
    assert.equal(
      evaluatePreflight("apply_patch", { patch: deleteLinePatch }),
      undefined,
      "deletion-only patch must not be rejected as uninspectable-file-input"
    );

    const markdownPatch = [
      "*** Begin Patch",
      "*** Update File: README.md",
      "@@",
      "+// ... existing code ...",
      "*** End Patch",
    ].join("\n");
    assert.equal(
      evaluatePreflight("apply_patch", { patch: markdownPatch }),
      undefined,
      "apply_patch on README.md must preserve markdown filePath exemption"
    );

    const rustWithLifetime = "pub fn label<'a>(s: &'a str) -> &'static str {\n  // ... existing code ...\n}\n";
    assert.equal(
      evaluatePreflight("write", { path: "src/lib.rs", content: rustWithLifetime }),
      "truncation-placeholder-in-file-write",
      "Rust lifetime apostrophes must not mask subsequent truncation placeholders"
    );
  });

  test("9. sanitizeObject and sanitizeMessages handle circular references, preserve Error subclasses & Date instances, protect valid mesh tokens, and redact forged mesh tokens in JSON strings", () => {
    // 1. Circular object reference does not stack overflow into fail-safe string
    const cyclic = { name: "ok", apiKey: "sk-proj-1234567890abcdefghijklmnop" };
    cyclic.self = cyclic;
    const cyclicRes = sanitizeObject(cyclic);
    assert.equal(typeof cyclicRes.sanitized, "object");
    assert.equal(cyclicRes.sanitized.apiKey, "[REDACTED]");
    assert.equal(cyclicRes.sanitized.self, cyclicRes.sanitized);

    // 2. Error subclass prototype & Date instance preserved
    const typeErr = new TypeError("token=my_secret_token_12345");
    const sanErr = sanitizeObject(typeErr).sanitized;
    assert.equal(sanErr instanceof TypeError, true, "Error subclass prototype must be preserved");
    const dateObj = { at: new Date("2026-11-22T00:00:00.000Z") };
    const sanDate = sanitizeObject(dateObj).sanitized;
    assert.equal(sanDate.at instanceof Date, true);
    assert.equal(sanDate.at.toISOString(), "2026-11-22T00:00:00.000Z");

    // 3. Top-level opencode-mesh UUID token preserved in sanitizeMessages when parts array exists
    const uuidToken = "550e8400-e29b-41d4-a716-446655440000";
    const msgs = sanitizeMessages([
      {
        info: { id: "m1", role: "user" },
        parts: [{ type: "text", text: "hello" }],
        "opencode-mesh": { v: 2, owner: "opencode-guardian", kind: "remediation", token: uuidToken },
      },
    ]);
    assert.equal(msgs[0]["opencode-mesh"].token, uuidToken);

    // 4. Arbitrary non-UUID secret inside "opencode-mesh.token" in JSON tool output is still redacted
    const forgedJson = JSON.stringify({
      "opencode-mesh": { token: "custom_secret_api_token_value" },
      password: "my_password_123",
    });
    const sanJson = JSON.parse(sanitizeString(forgedJson).sanitized);
    assert.equal(sanJson["opencode-mesh"].token, "[REDACTED]");

    // 5. YAML block header with empty value is not corrupted, and URL query honors safeValues
    assert.equal(sanitizeString("credentials:\n  host: localhost").sanitized, "credentials:\n  host: localhost");
    assert.equal(
      sanitizeString("https://example.com/api?token=SAFE_TOK", { safeValues: ["SAFE_TOK"] }).sanitized,
      "https://example.com/api?token=SAFE_TOK"
    );
  });

  test("10. Rules & Evidence precision: fixed edit does not trigger 'unresolved generic failure', multi-stage destructive authorization checks every stage, research-only constraint avoids 'no changes to public API' false positive, and multi-file secrets are all reported", async () => {
    // 10a. Failed edit followed by successful edit on same file must not leave an unresolved generic failure
    const editTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Update src/a.ts" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "edit",
            callID: "e1",
            state: { status: "error", input: { filePath: "src/a.ts", old_string: "bad", new_string: "ok" }, error: "old_string not found" },
          },
          {
            type: "tool",
            tool: "edit",
            callID: "e2",
            state: { status: "completed", input: { filePath: "src/a.ts", old_string: "good", new_string: "ok" } },
          },
          {
            type: "tool",
            tool: "read",
            callID: "r1",
            state: { status: "completed", input: { filePath: "src/a.ts" }, output: "const x = 'ok';\n" },
          },
          { type: "text", text: "Updated src/a.ts." },
        ],
      },
    ];
    const engine = new GuardEngine({ enabled: true });
    const editInspect = await engine.inspect("s-edit-fix", "/tmp", editTurn);
    assert.equal(
      editInspect.results.find((r) => r.ruleId === "task/completion-gate")?.decision,
      "pass",
      "resolved file edit must not block completion-gate as unresolved generic failure"
    );

    // 10b. Multi-stage command where stage 1 is authorized must STILL block unauthorized stage 2
    const destructiveEngine = new GuardEngine({
      enabled: true,
      rules: { "safety/destructive-operations": "error" },
    });
    const compoundTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Please hard reset the repo." }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          { type: "tool", tool: "bash", state: { status: "completed", input: { command: "git reset --hard && rm -rf /" }, exitCode: 0 } },
        ],
      },
    ];
    const compoundRes = await destructiveEngine.inspect("s-compound", "/tmp", compoundTurn);
    assert.equal(
      compoundRes.decision,
      "block",
      "authorizing 'git reset --hard' must not authorize chained '&& rm -rf /'"
    );

    // 10c. "no changes to the public API" must not trigger research-only scope violation
    assert.equal(
      hasResearchOnlyConstraint("Refactor src/app.ts so there are no changes to the public API."),
      false
    );

    // 10d. Multi-file secrets in the same turn must record both files and detect postgresql://
    const secretsTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Add config files" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "write",
            state: { status: "completed", input: { path: "src/a.ts", content: 'const k = "sk-proj-111111111111111111111111";' } },
          },
          {
            type: "tool",
            tool: "write",
            state: { status: "completed", input: { path: "src/b.ts", content: 'const db = "postgresql://admin:SuperSecret123@db.internal:5432/app";' } },
          },
        ],
      },
    ];
    const secretsRes = await engine.inspect("s-sec", "/tmp", secretsTurn);
    const secretFindings = secretsRes.results.find((r) => r.ruleId === "security/no-secrets")?.findings ?? [];
    const secretFiles = secretFindings.map((f) => f.filePath).sort();
    assert.deepEqual(secretFiles, ["src/a.ts", "src/b.ts"]);
  });

  test("11. Code Mode execute nested toolCalls preserve callID, output, error, and non-zero exitCode, and synthetic shell prefers meta.command over description", () => {
    const normalized = normalizeV2Messages([
      { id: "u1", type: "user", text: "Run checks" },
      {
        id: "a1",
        type: "assistant",
        content: [
          {
            type: "tool",
            id: "exec-1",
            name: "execute",
            state: {
              status: "completed",
              input: { code: "..." },
              metadata: {
                toolCalls: [
                  {
                    id: "inner-read-1",
                    tool: "read",
                    status: "completed",
                    input: { filePath: "src/index.ts" },
                    output: "export const ok = true;\n",
                  },
                  {
                    id: "inner-shell-1",
                    tool: "shell",
                    status: "completed",
                    input: { command: "npm test" },
                    output: "FAIL\nExit code: 1",
                    exitCode: 1,
                  },
                ],
              },
            },
          },
        ],
      },
      {
        id: "syn-1",
        type: "synthetic",
        description: "Run project unit test suite",
        text: '<shell command="npm test">\n✔ 10 tests passed\nExit code: 0\n</shell>',
        metadata: { source: "shell", state: "completed", shellID: "sh-99", exit: 0 },
      },
    ]);

    const assistantParts = normalized[1].parts;
    assert.equal(assistantParts[1].callID, "inner-read-1");
    assert.equal(assistantParts[1].state.output, "export const ok = true;\n");
    assert.equal(assistantParts[2].callID, "inner-shell-1");
    assert.equal(assistantParts[2].state.exitCode, 1);

    const syntheticShellPart = normalized[2].parts[0];
    assert.equal(syntheticShellPart.state.input.command, "npm test");
  });

  test("12. testing/no-cheat detects Go t.SkipNow() and scopes file deletion authorization to finding.filePath, no-evasion checks subsequent matches, and guardianCommandReport('rules') resolves default severity for option-only rule overrides", async (t) => {
    const engine = new GuardEngine({
      enabled: true,
      rules: {
        "testing/no-cheat": { blockStructuralTestChanges: true },
        "discipline/no-evasion": "error",
      },
    });

    // 12a. Go t.SkipNow() must be detected
    const goSkipTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the Go test" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "write",
            state: { status: "completed", input: { path: "auth_test.go", content: "func TestAuth(t *testing.T) {\n  t.SkipNow()\n}\n" } },
          },
        ],
      },
    ];
    const goRes = await engine.inspect("s-go-skip", "/tmp", goSkipTurn);
    assert.equal(
      goRes.results.find((r) => r.ruleId === "testing/no-cheat")?.decision,
      "block",
      "Go t.SkipNow() must be detected by testing/no-cheat"
    );

    // 12b. Authorizing deletion of old.test.ts must NOT authorize deleting auth.test.ts
    const delTestTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Please delete test file old.test.ts" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "file_op",
            state: { status: "completed", input: { action: "delete", path: "auth.test.ts" } },
          },
        ],
      },
    ];
    const delRes = await engine.inspect("s-del-test", "/tmp", delTestTurn);
    assert.equal(
      delRes.results.find((r) => r.ruleId === "testing/no-cheat")?.decision,
      "block",
      "Deleting auth.test.ts when only old.test.ts was authorized must block"
    );

    // 12c. no-evasion: supported first match must not skip unsupported second match of same pattern
    const evasionTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Check failures" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "bash",
            state: { status: "completed", input: { command: "git show main:src/a.ts" }, exitCode: 0, output: "broken" },
          },
          {
            type: "text",
            text: "The failure in `./src/a.ts` is a pre-existing issue. Also, the failure in `./src/b.ts` is a pre-existing issue.",
          },
        ],
      },
    ];
    const evRes = await engine.inspect("s-ev", "/tmp", evasionTurn);
    assert.equal(
      evRes.results.find((r) => r.ruleId === "discipline/no-evasion")?.decision,
      "block",
      "Unsupported second pre-existing issue claim for ./src/b.ts must block"
    );

    // 12d. guardianCommandReport('rules') resolves effective severity when rule override object omits severity
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-cmd-rules-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const report = await guardianCommandReport("rules", dir, "0.16.1", {
      rules: { "testing/no-cheat": { blockStructuralTestChanges: true } },
    });
    assert.match(report.message, /testing\/no-cheat: error/);
  });

  test("13. violations telemetry mode tracks in-memory inspection & redaction counters without disk I/O and reports telemetry mode transparently", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-live-mem-telem-"));
    t.after(() => {
      clearGuardianTelemetryConfig_10();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    configureGuardianTelemetry(dir, { enabled: true, level: "violations" });
    recordGuardianEvent({ kind: "preflight-allowed", tool: "bash" }, dir);
    recordGuardianEvent({ kind: "post-inspected" }, dir);
    assert.equal(typeof GuardianIndex.recordGuardianRedaction, "function", "recordGuardianRedaction must be exported");
    GuardianIndex.recordGuardianRedaction(2, dir);

    // Zero disk writes for benign inspections or redactions in violations mode
    assert.equal(fs.existsSync(guardianEventPath(dir)), false);

    const status = readGuardianStatus(dir);
    assert.equal(status.inspected, 2, "in-memory inspections should be reflected in readGuardianStatus");
    assert.equal(status.redacted, 2, "in-memory secret redactions should be reflected in readGuardianStatus");

    const report = await guardianCommandReport("status", dir, "0.17.0");
    assert.match(report.message, /Telemetry mode: violations/);
    assert.match(report.message, /Secret redactions \(in-memory\): 2/);
  });

  test("14. loadConfig merges global and project configs and enforces allowProjectOverrides: false against untrusted repo downgrades", (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-global-lock-"));
    const globalDir = path.join(root, "global-config");
    const projDir = path.join(root, "untrusted-repo");
    fs.mkdirSync(globalDir, { recursive: true });
    fs.mkdirSync(projDir, { recursive: true });

    const origConfigDir = process.env.OPENCODE_CONFIG_DIR;
    process.env.OPENCODE_CONFIG_DIR = globalDir;
    t.after(() => {
      if (origConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
      else process.env.OPENCODE_CONFIG_DIR = origConfigDir;
      fs.rmSync(root, { recursive: true, force: true });
    });

    // 14a. Locked global config prevents untrusted repo from disabling Guardian, preflight, secrets, or rules
    fs.writeFileSync(
      path.join(globalDir, "opencode-guardian.json"),
      JSON.stringify({
        enabled: true,
        allowProjectOverrides: false,
        preflight: { enabled: true, mode: "strict" },
        secrets: { enabled: true },
        rules: { "security/no-secrets": "error", "safety/destructive-operations": "error" },
      })
    );
    fs.writeFileSync(
      path.join(projDir, "opencode-guardian.json"),
      JSON.stringify({
        enabled: false,
        preflight: { enabled: false, mode: "critical" },
        secrets: { enabled: false },
        rules: { "security/no-secrets": "off", "safety/destructive-operations": "warn" },
      })
    );

    const lockedEffective = resolveEffectiveConfig(loadConfig(projDir));
    assert.equal(lockedEffective.enabled, true, "untrusted project must not disable globally locked Guardian");
    assert.equal(lockedEffective.preflight?.enabled, true, "untrusted project must not disable globally locked preflight");
    assert.equal(lockedEffective.preflight?.mode, "strict", "untrusted project must not downgrade strict preflight mode");
    assert.equal(lockedEffective.secrets?.enabled, true, "untrusted project must not disable globally locked secret redaction");
    assert.equal(lockedEffective.rules?.["security/no-secrets"], "error", "untrusted project must not turn off globally locked error rule");
    assert.equal(lockedEffective.rules?.["safety/destructive-operations"], "error");

    // 14b. When allowProjectOverrides is not false, project config inherits global config and overrides specific fields
    fs.writeFileSync(
      path.join(globalDir, "opencode-guardian.json"),
      JSON.stringify({
        enabled: true,
        preflight: { enabled: true, mode: "critical" },
      })
    );
    fs.writeFileSync(
      path.join(projDir, "opencode-guardian.json"),
      JSON.stringify({
        remediationBudget: 2,
      })
    );
    const mergedEffective = resolveEffectiveConfig(loadConfig(projDir));
    assert.equal(mergedEffective.preflight?.enabled, true, "project config should inherit global preflight.enabled");
    assert.equal(mergedEffective.preflight?.mode, "critical", "project config should inherit global preflight.mode");
    assert.equal(mergedEffective.remediationBudget, 2, "project config should apply its own remediationBudget");
  });

  test("15. preflight 'critical' mode blocks catastrophic destructive commands and secret writes while allowing everyday rm, printenv/docker inspect, and WIP commits", () => {
    // Catastrophic operations MUST still be blocked in 'critical' mode
    assert.equal(evaluatePreflight("bash", { command: "rm -rf /" }, [], "critical"), "destructive-command");
    assert.equal(evaluatePreflight("bash", { command: "git reset --hard HEAD~1" }, [], "critical"), "destructive-command");
    assert.equal(evaluatePreflight("bash", { command: "git push --force origin main" }, [], "critical"), "destructive-command");
    assert.equal(evaluatePreflight("bash", { command: "git clean -fdx" }, [], "critical"), "destructive-command");
    assert.equal(
      evaluatePreflight("write", { path: "src/a.ts", content: 'const k = "sk-proj-111111111111111111111111";' }, [], "critical"),
      "hardcoded-secret-in-file-write"
    );
    assert.equal(
      evaluatePreflight("write", { path: "src/a.ts", content: "// ... existing code ...\n" }, [], "critical"),
      "truncation-placeholder-in-file-write"
    );

    // Everyday low-friction actions MUST be allowed in 'critical' mode (while blocked in 'strict' mode)
    assert.equal(evaluatePreflight("bash", { command: "rm /tmp/scratch.txt" }, [], "critical"), undefined);
    assert.equal(evaluatePreflight("bash", { command: "rm /tmp/scratch.txt" }, [], "strict"), "destructive-command");

    assert.equal(evaluatePreflight("bash", { command: "printenv" }, [], "critical"), undefined);
    assert.equal(evaluatePreflight("bash", { command: "printenv" }, [], "strict"), "high-risk-environment-dump");

    assert.equal(evaluatePreflight("bash", { command: "docker inspect app-container" }, [], "critical"), undefined);
    assert.equal(evaluatePreflight("bash", { command: "docker inspect app-container" }, [], "strict"), "high-risk-environment-dump");

    assert.equal(evaluatePreflight("bash", { command: 'git commit -m "wip"' }, [], "critical"), undefined);
    assert.equal(evaluatePreflight("bash", { command: 'git commit -m "wip"' }, [], "strict"), "lazy-commit-message");
  });

  test("16. Dalga 1 (G-01, G-02): allowProjectOverrides:false locks default rules, exceptions, secrets, budgets, and default strict preflight mode", (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-global-lock-floor-"));
    const globalDir = path.join(root, "global-config");
    const projDir = path.join(root, "untrusted-repo");
    fs.mkdirSync(globalDir, { recursive: true });
    fs.mkdirSync(projDir, { recursive: true });

    const origConfigDir = process.env.OPENCODE_CONFIG_DIR;
    process.env.OPENCODE_CONFIG_DIR = globalDir;
    t.after(() => {
      if (origConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
      else process.env.OPENCODE_CONFIG_DIR = origConfigDir;
      fs.rmSync(root, { recursive: true, force: true });
    });

    // Global config locks overrides WITHOUT repeating all 14 built-in rules or explicit preflight.mode
    fs.writeFileSync(
      path.join(globalDir, "opencode-guardian.json"),
      JSON.stringify({
        enabled: true,
        allowProjectOverrides: false,
        preflight: { enabled: true },
        secrets: { enabled: true, safeKeyNames: ["GLOBAL_SAFE"] },
        rules: { "discipline/no-evasion": { severity: "error", exceptions: ["global-ok"] } },
      })
    );
    // Untrusted project attempts to weaken unlisted defaults, preflight mode, exceptions, secrets, and budgets
    fs.writeFileSync(
      path.join(projDir, "opencode-guardian.json"),
      JSON.stringify({
        remediationBudget: 0,
        iterationBudget: 0,
        preflight: { mode: "critical" },
        secrets: {
          includeRuntimeEnv: false,
          safeKeyNames: ["API_KEY", "SECRET_TOKEN"],
          safeValues: ["sk-live-secret"],
        },
        rules: {
          "security/no-secrets": "off",
          "safety/destructive-operations": "off",
          "discipline/no-evasion": { severity: "warn", exceptions: ["untrusted-bypass"] },
        },
      })
    );

    const effective = resolveEffectiveConfig(loadConfig(projDir));
    assert.equal(effective.rules?.["security/no-secrets"], "error", "default error rule must not be downgraded when locked");
    assert.equal(effective.rules?.["safety/destructive-operations"], "warn", "default warn rule must not be downgraded when locked");
    assert.deepEqual(
      effective.rules?.["discipline/no-evasion"],
      { severity: "error", exceptions: ["global-ok"] },
      "project must not inject rule exceptions or downgrade severity when locked"
    );
    assert.equal(effective.preflight?.mode, "strict", "omitted global preflight.mode defaults to strict and must stay locked");
    assert.equal(effective.secrets?.includeRuntimeEnv, true, "project must not disable includeRuntimeEnv when locked");
    assert.deepEqual(effective.secrets?.safeKeyNames, ["GLOBAL_SAFE"], "project must not expand safeKeyNames when locked");
    assert.equal(effective.secrets?.safeValues, undefined, "project must not inject safeValues when locked");
    assert.equal(effective.remediationBudget, 1, "project must not reduce remediationBudget below default when locked");
    assert.equal(effective.iterationBudget, 3, "project must not reduce iterationBudget below default when locked");
  });

  test("17. Dalga 1 (G-13): event loop retries resubscribe when a transient subscribe call throws", async (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-resub-retry-"));
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      preflight: { enabled: false },
      secrets: { enabled: false },
    }));
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
    t.after(() => {
      if (origStateDir === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      fs.rmSync(directory, { recursive: true, force: true });
    });

    let subscribeCalls = 0;
    let inspected = 0;
    const host = {
      location: { directory },
      event: {
        subscribe({ signal }) {
          subscribeCalls++;
          if (subscribeCalls === 1) {
            // Initial stream fails mid-iteration
            return (async function* () { throw new Error("initial drop"); })();
          }
          if (subscribeCalls === 2) {
            // First resubscribe attempt throws synchronously
            throw new Error("transient resubscribe failure");
          }
          // Second resubscribe attempt succeeds and delivers idle event
          return (async function* () {
            yield { type: "session.idle", data: { sessionID: "resub-recovered-session" } };
            await new Promise((resolve) => {
              if (signal.aborted) resolve();
              else signal.addEventListener("abort", resolve, { once: true });
            });
          })();
        },
      },
      session: {
        async context() { inspected++; return []; },
        async synthetic() {},
      },
    };

    const cleanup = await Guardian.setup(host);
    try {
      const deadline = Date.now() + 2500;
      while (inspected === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(subscribeCalls, 3, "event loop must use remaining retry attempts after a failed resubscribe");
      assert.equal(inspected, 1, "recovered event stream must resume inspecting idle sessions");
    } finally {
      await cleanup?.();
    }
  });

  test("18. Dalga 1 (G-17): experimental.job.updated clears backgroundSessions when job is keyed by jobID !== id", async (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-jobid-clear-"));
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      preflight: { enabled: false },
      secrets: { enabled: false },
    }));
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
    t.after(() => {
      if (origStateDir === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      fs.rmSync(directory, { recursive: true, force: true });
    });

    const queue = [];
    let notify = null;
    const pushEvent = (ev) => {
      queue.push(ev);
      if (notify) { const fn = notify; notify = null; fn(); }
    };
    const synthetics = [];
    const host = {
      location: { directory },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              if (queue.length === 0) {
                await new Promise((resolve) => {
                  notify = resolve;
                  signal.addEventListener("abort", resolve, { once: true });
                });
                continue;
              }
              yield queue.shift();
            }
          })();
        },
      },
      session: {
        async get({ sessionID: sid }) {
          return { id: sid, location: { directory } };
        },
        async context() {
          return [
            { id: "u1", type: "user", text: "Fix the bug" },
            { id: "a1", type: "assistant", content: [{ type: "text", text: "This test failure is unrelated to my changes." }] },
          ];
        },
        async synthetic(input) { synthetics.push(input); },
      },
    };

    const cleanup = await Guardian.setup(host);
    try {
      const sessionID = "sess-jobid-mismatch";
      pushEvent({
        type: "experimental.job.updated",
        data: { info: { id: "rec-1", jobID: "job-canonical-99", sessionID, status: "running", kind: "shell" } },
      });
      await new Promise((r) => setTimeout(r, 30));
      pushEvent({
        type: "experimental.job.updated",
        data: { info: { id: "rec-1", jobID: "job-canonical-99", sessionID, status: "completed", kind: "shell" } },
      });
      await new Promise((r) => setTimeout(r, 30));
      pushEvent({ type: "session.execution.succeeded", data: { sessionID } });

      const deadline = Date.now() + 1500;
      while (synthetics.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 20));
      }
      assert.ok(synthetics.length >= 1, "completed job keyed by jobID must unlock backgroundSessions for post-turn inspection");
    } finally {
      await cleanup?.();
    }
  });

  test("19. Dalga 2 (G-03, G-04): runtimeForDirectory fails closed when secondary project enables preflight without tool.execute.before, and missing shell.hook records visible degradation", async (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-preflight-ready-"));
    const startupDir = path.join(root, "startup");
    const subDir = path.join(startupDir, "child-strict");
    fs.mkdirSync(subDir, { recursive: true });
    fs.writeFileSync(path.join(startupDir, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      preflight: { enabled: false },
      secrets: { enabled: false },
    }));
    fs.writeFileSync(path.join(subDir, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      preflight: { enabled: true },
      secrets: { enabled: false },
    }));
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(root, "state");
    t.after(() => {
      if (origStateDir === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      fs.rmSync(root, { recursive: true, force: true });
    });

    // Host has NO tool.hook at all (startup had preflight:false, so setup succeeds),
    // then child-strict session triggers shell.create.before -> must fail closed!
    let shellBeforeHook;
    const host1 = {
      location: { directory: startupDir },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            await new Promise((r) => signal.addEventListener("abort", r, { once: true }));
          })();
        },
      },
      shell: {
        hook(kind, fn) {
          if (kind === "create.before") shellBeforeHook = fn;
          return { dispose() {} };
        },
      },
      session: {
        async get() { return { id: "s-sub", location: { directory: subDir } }; },
        async context() { return []; },
        async synthetic() {},
      },
    };
    const cleanup1 = await Guardian.setup(host1);
    try {
      await assert.rejects(
        () => shellBeforeHook({ sessionID: "s-sub", command: "echo ok", location: { directory: subDir } }),
        /preflight/i,
        "secondary project with preflight:true must fail closed when tool.execute.before is unavailable"
      );
    } finally {
      await cleanup1?.();
    }

    // G-04: Host has tool.hook but NO shell.hook while preflight:true -> must record shell-preflight-unavailable
    const strictDir = path.join(root, "strict-no-shell");
    fs.mkdirSync(strictDir, { recursive: true });
    fs.writeFileSync(path.join(strictDir, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      preflight: { enabled: true },
      secrets: { enabled: false },
    }));
    const host2 = {
      location: { directory: strictDir },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            await new Promise((r) => signal.addEventListener("abort", r, { once: true }));
          })();
        },
      },
      tool: { hook() { return { dispose() {} }; } },
      session: {
        async context() { return []; },
        async synthetic() {},
      },
    };
    const cleanup2 = await Guardian.setup(host2);
    try {
      const logContent = fs.readFileSync(guardianEventPath(strictDir), "utf8");
      assert.ok(
        logContent.includes("shell-preflight-unavailable"),
        "missing context.shell.hook under strict preflight must emit a visible shell-preflight-unavailable audit event"
      );
    } finally {
      await cleanup2?.();
    }
  });

  test("20. Dalga 2 (G-05): failed session.get lookup does not run startup-project post-turn remediation or telemetry for an unverified session", async (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-unverified-dir-"));
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      preflight: { enabled: false },
      secrets: { enabled: false },
      telemetry: { enabled: true, level: "all" },
    }));
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
    t.after(() => {
      if (origStateDir === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      fs.rmSync(directory, { recursive: true, force: true });
    });

    const queue = [];
    let notify = null;
    const pushEvent = (ev) => {
      queue.push(ev);
      if (notify) { const fn = notify; notify = null; fn(); }
    };
    const synthetics = [];
    const host = {
      location: { directory },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              if (queue.length === 0) {
                await new Promise((r) => {
                  notify = r;
                  signal.addEventListener("abort", r, { once: true });
                });
                continue;
              }
              yield queue.shift();
            }
          })();
        },
      },
      session: {
        async get() { throw new Error("session lookup unavailable"); },
        async context() {
          return [
            { id: "u1", type: "user", text: "Fix bug" },
            { id: "a1", type: "assistant", content: [{ type: "text", text: "This test failure is unrelated to my changes." }] },
          ];
        },
        async synthetic(input) { synthetics.push(input); },
      },
    };

    const cleanup = await Guardian.setup(host);
    try {
      pushEvent({ type: "session.idle", data: { sessionID: "unknown-foreign-session" } });
      await new Promise((r) => setTimeout(r, 120));
      assert.equal(synthetics.length, 0, "unverified session directory must not trigger startup-project remediation");
      const status = readGuardianStatus(directory);
      assert.equal(status.inspected, 0, "unverified session must not record post-inspected telemetry under startup project");
    } finally {
      await cleanup?.();
    }
  });

  test("21. Dalga 2 (G-15, G-16): premature session.idle does not clear foreground handoff before execute.after, and failed execute.after disposes orphan execute.before when preflight/secrets are off", async (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-g15-g16-"));
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      preflight: { enabled: false },
      secrets: { enabled: false },
    }));
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
    t.after(() => {
      if (origStateDir === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      fs.rmSync(directory, { recursive: true, force: true });
    });

    // G-16: secrets:false, preflight:false, execute.after fails -> before must be disposed!
    let beforeDisposed = 0;
    const host16 = {
      location: { directory },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            await new Promise((r) => signal.addEventListener("abort", r, { once: true }));
          })();
        },
      },
      tool: {
        hook(kind) {
          if (kind === "execute.before") return { dispose() { beforeDisposed++; } };
          throw new Error("after unavailable");
        },
      },
      session: {
        async context() { return []; },
        async synthetic() {},
      },
    };
    const cleanup16 = await Guardian.setup(host16);
    try {
      assert.equal(beforeDisposed, 1, "orphan execute.before must be disposed when execute.after fails and preflight/secrets are off");
    } finally {
      await cleanup16?.();
    }

    // G-15: premature session.idle between execute.before and execute.after must NOT drop foreground handoff
    const queue = [];
    let notify = null;
    const pushEvent = (ev) => {
      queue.push(ev);
      if (notify) { const fn = notify; notify = null; fn(); }
    };
    let toolBefore;
    let toolAfter;
    const childMsgs = [
      { id: "cu1", type: "user", text: "Summarize" },
      { id: "ca1", type: "assistant", content: [{ type: "text", text: "Final verified child summary." }] },
    ];
    const host15 = {
      location: { directory },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              if (queue.length === 0) {
                await new Promise((r) => {
                  notify = r;
                  signal.addEventListener("abort", r, { once: true });
                });
                continue;
              }
              yield queue.shift();
            }
          })();
        },
      },
      tool: {
        hook(kind, fn) {
          if (kind === "execute.before") toolBefore = fn;
          if (kind === "execute.after") toolAfter = fn;
          return { dispose() {} };
        },
      },
      session: {
        async get({ sessionID: sid }) {
          return { id: sid, parentID: sid === "child-g15" ? "parent-g15" : undefined, location: { directory } };
        },
        async context({ sessionID: sid }) { return sid === "child-g15" ? childMsgs : []; },
        async synthetic() {},
        async wait() {},
      },
    };
    const cleanup15 = await Guardian.setup(host15);
    try {
      await toolBefore({ id: "call-g15", sessionID: "parent-g15", tool: "subagent", input: { prompt: "Summarize", background: false } });
      // Premature parent idle arrives before execute.after
      pushEvent({ type: "session.idle", data: { sessionID: "parent-g15" } });
      await new Promise((r) => setTimeout(r, 50));

      const afterEvent = {
        id: "call-g15",
        sessionID: "parent-g15",
        tool: "subagent",
        status: "completed",
        input: { prompt: "Summarize", background: false },
        result: {
          output: { sessionID: "child-g15", status: "completed", output: "Stale summary" },
          content: "<subagent sessionID=\"child-g15\" state=\"completed\">\nStale summary\n</subagent>",
          metadata: { sessionID: "child-g15", status: "completed" },
        },
      };
      await toolAfter(afterEvent);
      assert.equal(
        afterEvent.result.output.output,
        "Final verified child summary.",
        "premature session.idle must not clear foreground handoff before execute.after finalizes child result"
      );
    } finally {
      await cleanup15?.();
    }
  });

  test("22. Dalga 2 (G-18): config.updated preserves active GuardEngine session state instead of wiping runtimeByDirectory", async (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-config-reload-state-"));
    const configFile = path.join(directory, "opencode-guardian.json");
    fs.writeFileSync(configFile, JSON.stringify({
      enabled: true,
      preflight: { enabled: false },
      secrets: { enabled: false },
      remediationBudget: 1,
    }));
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
    t.after(() => {
      if (origStateDir === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      fs.rmSync(directory, { recursive: true, force: true });
    });

    const queue = [];
    let notify = null;
    const pushEvent = (ev) => {
      queue.push(ev);
      if (notify) { const fn = notify; notify = null; fn(); }
    };
    const synthetics = [];
    let messages = [
      { id: "u1", type: "user", text: "Fix the bug" },
      { id: "a1", type: "assistant", content: [{ type: "text", text: "This test failure is unrelated to my changes." }] },
    ];
    const host = {
      location: { directory },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              if (queue.length === 0) {
                await new Promise((r) => {
                  notify = r;
                  signal.addEventListener("abort", r, { once: true });
                });
                continue;
              }
              yield queue.shift();
            }
          })();
        },
      },
      session: {
        async get({ sessionID: sid }) { return { id: sid, location: { directory } }; },
        async context() { return messages; },
        async synthetic(input) { synthetics.push(input); },
      },
    };

    const cleanup = await Guardian.setup(host);
    try {
      // Turn 1 triggers remediation (records pendingRemediation in GuardEngine's SessionStateStore)
      pushEvent({ type: "session.idle", data: { sessionID: "s-reload" } });
      const deadline1 = Date.now() + 1000;
      while (synthetics.length === 0 && Date.now() < deadline1) {
        await new Promise((r) => setTimeout(r, 20));
      }
      assert.equal(synthetics.length, 1);

      // Now config.updated fires mid-turn (updating e.g. iterationBudget)
      fs.writeFileSync(configFile, JSON.stringify({
        enabled: true,
        preflight: { enabled: false },
        secrets: { enabled: false },
        remediationBudget: 1,
        iterationBudget: 4,
      }));
      pushEvent({ type: "config.updated", data: {} });
      await new Promise((r) => setTimeout(r, 50));

      // Agent finishes remediating cleanly -> GuardEngine MUST still remember pendingRemediation and record remediation-verified!
      messages = [
        ...messages,
        { id: "g1", type: "synthetic", text: synthetics[0].text, metadata: synthetics[0].metadata },
        { id: "a2", type: "assistant", content: [{ type: "text", text: "Fixed the root cause directly in src/app.ts." }] },
      ];
      pushEvent({ type: "session.idle", data: { sessionID: "s-reload" } });
      const deadline2 = Date.now() + 1000;
      while (readGuardianStatus(directory).unverified === 0 && readGuardianStatus(directory).verified === 0 && Date.now() < deadline2) {
        await new Promise((r) => setTimeout(r, 20));
      }
      const reloadStatus = readGuardianStatus(directory);
      assert.ok(
        reloadStatus.verified + reloadStatus.unverified >= 1,
        "config.updated must preserve pendingRemediation in GuardEngine so remediation outcome is recorded"
      );
    } finally {
      await cleanup?.();
    }
  });

  test("23. R3 Dalga 1 (R3-001, R3-002): allowProjectOverrides:false locks implicit severity on global rule objects, preserves customPhrases against scalar overrides, and locks tightening booleans", () => {
    const globalCfg = {
      enabled: true,
      allowProjectOverrides: false,
      rules: {
        "integrity/no-unverified-claims": { blockUnverified: true },
        "quality/no-shortcuts": { severity: "error", customPhrases: ["global-banned-phrase"] },
        "manifest/no-ghost-deps": { severity: "error", productionOnly: true, blockPythonGhostDeps: true },
      },
    };
    const projectOverlay = {
      rules: {
        // R3-001: global object omitted severity (effective default "error"), project tries to turn it off
        "integrity/no-unverified-claims": { severity: "off", blockUnverified: false },
        // R3-002a: project scalar string tries to drop global customPhrases
        "quality/no-shortcuts": "error",
        // R3-002b: project object tries to flip tightening booleans to false
        "manifest/no-ghost-deps": { severity: "error", productionOnly: false, blockPythonGhostDeps: false },
      },
    };
    const effective = resolveEffectiveConfig(globalCfg, projectOverlay);
    const claimsRule = effective.rules?.["integrity/no-unverified-claims"];
    assert.equal(typeof claimsRule === "object" ? claimsRule.severity : claimsRule, "error", "R3-001: implicit default severity on global rule object must stay locked at error");
    assert.equal(typeof claimsRule === "object" ? claimsRule.blockUnverified : undefined, true, "R3-002: blockUnverified:true must stay locked");

    const shortcutsRule = effective.rules?.["quality/no-shortcuts"];
    assert.equal(typeof shortcutsRule, "object", "R3-002: scalar project overlay must not wipe global rule object");
    assert.deepEqual(shortcutsRule.customPhrases, ["global-banned-phrase"], "R3-002: global customPhrases must survive scalar project override");

    const ghostRule = effective.rules?.["manifest/no-ghost-deps"];
    assert.equal(ghostRule?.productionOnly, true, "R3-002: productionOnly:true must stay locked");
    assert.equal(ghostRule?.blockPythonGhostDeps, true, "R3-002: blockPythonGhostDeps:true must stay locked");
  });

  test("24. R3 Dalga 1 (R3-003): cached directory with omitted enabled field must not bypass fail-closed hook readiness after config.updated", async (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-r3-003-"));
    const cfgPath = path.join(directory, "opencode-guardian.json");
    // Omit `enabled` (defaults to active) and start with preflight: false so setup succeeds without tool.hook
    fs.writeFileSync(cfgPath, JSON.stringify({
      preflight: { enabled: false },
      secrets: { enabled: false },
    }));
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
    t.after(() => {
      if (origStateDir === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      fs.rmSync(directory, { recursive: true, force: true });
    });

    const queue = [];
    let notify = null;
    const pushEvent = (ev) => {
      queue.push(ev);
      if (notify) { const fn = notify; notify = null; fn(); }
    };
    let shellBeforeHook;
    const host = {
      location: { directory },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              if (queue.length === 0) {
                await new Promise((r) => {
                  notify = r;
                  signal.addEventListener("abort", r, { once: true });
                });
                continue;
              }
              yield queue.shift();
            }
          })();
        },
      },
      shell: {
        hook(kind, fn) {
          if (kind === "create.before") shellBeforeHook = fn;
          return { dispose() {} };
        },
      },
      session: {
        async get() { return { id: "s-r3-003", location: { directory } }; },
        async context() { return []; },
        async synthetic() {},
      },
    };
    const cleanup = await Guardian.setup(host);
    try {
      // Reload config enabling preflight while still omitting `enabled`
      fs.writeFileSync(cfgPath, JSON.stringify({
        preflight: { enabled: true },
        secrets: { enabled: false },
      }));
      pushEvent({ type: "config.updated", data: {} });
      await new Promise((r) => setTimeout(r, 40));

      await assert.rejects(
        () => shellBeforeHook({ sessionID: "s-r3-003", command: "echo hi", location: { directory } }),
        /preflight/i,
        "omitted enabled (undefined) must NOT bypass fail-closed preflight readiness check on cached runtime"
      );
    } finally {
      await cleanup?.();
    }
  });

  test("25. R3 Dalga 2 (R3-013, R3-024): finalizeSubagentHandoff interrupts child on timeout and multi-instance telemetry ownership survives single-instance teardown", async (t) => {
    const { finalizeSubagentHandoff, resolveTelemetrySettings } = await import("../dist/index.js");

    // R3-013: deadline timeout must invoke interrupt callback so child doesn't continue orphaned
    let interrupted = 0;
    const engine = new GuardEngine({ enabled: true, remediationBudget: 1 });
    await assert.rejects(
      () => finalizeSubagentHandoff({
        sessionID: "child-r3-013-timeout",
        directory: process.cwd(),
        engine,
        leaseTtlMs: 80,
        remediationTimeoutMs: 60,
        interrupt: () => { interrupted++; },
        resolveCapability: async () => ({ capability: "write-allowed", evidence: { reasons: ["test"] } }),
        fetchMessages: async () => [
          { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix bug" }] },
          { info: { id: "a1", role: "assistant" }, parts: [{ type: "text", text: "This test failure is unrelated to my changes." }] },
        ],
        sendAndWait: () => new Promise(() => {}), // hangs forever
      }),
      /could not complete subagent remediation/i
    );
    assert.equal(interrupted, 1, "R3-013: deadline timeout must invoke interrupt callback");

    // R3-024: two instances on the same directory — disposing instance 1 must NOT erase instance 2's telemetry config
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-r3-024-"));
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      preflight: { enabled: false },
      secrets: { enabled: false },
      telemetry: { enabled: true, level: "all" },
    }));
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(dir, "state");
    t.after(() => {
      if (origStateDir === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      fs.rmSync(dir, { recursive: true, force: true });
    });

    const mkHost = () => ({
      location: { directory: dir },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            await new Promise((r) => signal.addEventListener("abort", r, { once: true }));
          })();
        },
      },
      session: { async context() { return []; }, async synthetic() {} },
    });
    const cleanup1 = await Guardian.setup(mkHost());
    const cleanup2 = await Guardian.setup(mkHost());
    try {
      await cleanup1();
      assert.equal(
        resolveTelemetrySettings(dir).level,
        "all",
        "R3-024: disposing instance 1 must not wipe telemetry config owned by active instance 2"
      );
    } finally {
      await cleanup2();
    }
  });

  test("R4 Wave 1 (R4-003): nested Code Mode tool call with missing status or failed parent must not synthesize completed exitCode 0", async () => {
    const { normalizeV2Messages } = await import("../dist/index.js");
    const msgs = normalizeV2Messages([
      {
        id: "a1",
        type: "assistant",
        content: [
          {
            type: "tool",
            name: "execute",
            id: "c-parent",
            state: {
              status: "completed",
              input: { code: "tools.shell({ command: 'npm test' })" },
              output: "done",
              metadata: {
                toolCalls: [
                  { tool: "shell", input: { command: "npm test" }, output: "ok" },
                ],
              },
            },
          },
          {
            type: "tool",
            name: "execute",
            id: "c-parent-err",
            state: {
              status: "error",
              input: { code: "tools.shell({ command: 'npm test' })" },
              error: "script threw",
              metadata: {
                toolCalls: [
                  { tool: "shell", status: "completed", input: { command: "npm test" }, output: "ok" },
                ],
              },
            },
          },
        ],
      },
    ]);
    const toolParts = msgs[0].parts.filter((p) => p.type === "tool" && p.tool === "shell");
    assert.equal(toolParts.length, 2);
    assert.notEqual(toolParts[0].state.status, "completed", "R4-003: nested call with missing status must stay unknown, not completed");
    assert.equal(toolParts[0].state.exitCode, undefined, "R4-003: nested call with missing status must not synthesize exitCode 0");
    assert.equal(toolParts[1].state.exitCode, undefined, "R4-003: nested call under errored parent must not synthesize exitCode 0");
  });

  test("R4 Wave 2 (R4-009, R4-017, R4-018, R4-022, R4-025): RPC owner clear, post-restart remediationStatus failed, interrupt grace await, prompt scope guard, and config reload error event", async (t) => {
    const { GuardEngine, REMEDIATION_MARKER } = await import("../dist/engine.js");
    const { finalizeSubagentHandoff, default: Guardian } = await import("../dist/index.js");
    const { recordMeshIntervention, getLatestMeshIntervention, forgetMeshSession } = await import("../dist/bridge.js");
    const { GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD } = await import("../dist/intervention-rpc.js");

    // R4-017: post-restart budget exhaustion with unresolved blocking finding must report remediationStatus: "failed" even when pendingRules is empty
    const engine17 = new GuardEngine({ enabled: true, remediationBudget: 1 });
    const postRestartMsgs = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix bug" }] },
      { info: { id: "a1", role: "assistant" }, parts: [{ type: "text", text: "This failure is unrelated to this change." }] },
      { info: { id: "g1", role: "user" }, parts: [{ type: "text", text: REMEDIATION_MARKER + "\nResolve evasion.", synthetic: true, metadata: { "opencode-guardian": true } }] },
      { info: { id: "a2", role: "assistant" }, parts: [{ type: "text", text: "Still unrelated to this change." }] },
    ];
    const res17 = await engine17.inspect("s-r4-017", process.cwd(), postRestartMsgs);
    assert.equal(res17.decision, "pass");
    assert.equal(res17.remediationStatus, "failed", "R4-017: post-restart budget exhaustion with unresolved blocking results must report remediationStatus: failed");

    // R4-018: timeout must await async interrupt (bounded grace) before rejecting & releasing lease
    let interruptResolved = false;
    await assert.rejects(
      finalizeSubagentHandoff({
        sessionID: "s-r4-018",
        directory: process.cwd(),
        engine: new GuardEngine({ enabled: true, remediationBudget: 1 }),
        leaseTtlMs: 500,
        remediationTimeoutMs: 40,
        interrupt: async () => {
          await new Promise((r) => setTimeout(r, 30));
          interruptResolved = true;
        },
        resolveCapability: async () => ({ capability: "write-allowed", evidence: { reasons: ["test"] } }),
        fetchMessages: async () => [
          { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix bug" }] },
          { info: { id: "a1", role: "assistant" }, parts: [{ type: "text", text: "This failure is unrelated to this change." }] },
        ],
        sendAndWait: () => new Promise(() => {}),
      }),
      /could not complete subagent remediation/i
    );
    assert.equal(interruptResolved, true, "R4-018: deadline timeout must await bounded interrupt completion before rejecting");

    // R4-009, R4-022, R4-025: RPC clear owner-scope, prompt hook scope order, and invalid config.updated audit event
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-r4-w2-"));
    const stateDir = path.join(dir, "state");
    const cfgPath = path.join(dir, "opencode-guardian.json");
    fs.writeFileSync(cfgPath, JSON.stringify({ enabled: true, preflight: { enabled: false }, secrets: { enabled: false }, telemetry: { enabled: true, level: "violations" } }));
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = stateDir;
    t.after(() => {
      if (origStateDir === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      fs.rmSync(dir, { recursive: true, force: true });
    });

    const rpcHandlers = {};
    let promptHook;
    let emitEvent;
    const cleanup = await Guardian.setup({
      location: { directory: dir },
      rpc: {
        async register(_def, handlers) {
          Object.assign(rpcHandlers, handlers);
          return { dispose() {} };
        },
      },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              const ev = await new Promise((resolve) => {
                emitEvent = resolve;
                signal.addEventListener("abort", () => resolve(null), { once: true });
              });
              if (!ev) break;
              yield ev;
            }
          })();
        },
      },
      session: {
        async get({ sessionID }) {
          if (sessionID === "sess-disabled-proj") {
            return { id: sessionID, location: { directory: path.join(dir, "disabled-child") } };
          }
          return { id: sessionID, location: { directory: dir } };
        },
        async context() { return []; },
        async synthetic() {},
        async hook(name, fn) {
          if (name === "prompt") promptHook = fn;
          return { dispose() {} };
        },
      },
    });
    t.after(async () => { await cleanup?.(); });

    // R4-009: Guardian RPC clear for sessionID must NOT wipe sibling peer's intervention
    const sid09 = "sess-r4-009";
    t.after(() => forgetMeshSession(sid09));
    recordMeshIntervention({
      sessionID: sid09,
      directory: dir,
      owner: "opencode-hi",
      kind: "post-warning",
      ruleIds: ["hi/test"],
      deterministic: false,
      active: true,
      updatedAt: Date.now(),
    });
    await rpcHandlers[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD]({ sessionID: sid09 });
    assert.equal(getLatestMeshIntervention(sid09)?.owner, "opencode-hi", "R4-009: Guardian RPC clear must be owner-scoped");

    // R4-022: prompt hook on a disabled project must NOT wipe sibling peer intervention
    const disabledChild = path.join(dir, "disabled-child");
    fs.mkdirSync(disabledChild, { recursive: true });
    fs.writeFileSync(path.join(disabledChild, "opencode-guardian.json"), JSON.stringify({ enabled: false }));
    const sid22 = "sess-disabled-proj";
    t.after(() => forgetMeshSession(sid22));
    recordMeshIntervention({
      sessionID: sid22,
      directory: disabledChild,
      owner: "opencode-hi",
      kind: "post-warning",
      ruleIds: ["hi/test"],
      deterministic: false,
      active: true,
      updatedAt: Date.now(),
    });
    await promptHook({ sessionID: sid22, messageID: "u-dis", prompt: { text: "hello" } });
    assert.equal(getLatestMeshIntervention(sid22)?.owner, "opencode-hi", "R4-022: prompt hook must check scope/enabled before mutating mesh state");

    // R4-025: invalid config.updated must record inspection-error config-reload-failed event
    fs.writeFileSync(cfgPath, "{ invalid json");
    emitEvent({ type: "config.updated", data: {} });
    await new Promise((r) => setTimeout(r, 40));
    const logFile = path.join(stateDir, "guardian-events.jsonl");
    assert.ok(fs.existsSync(logFile), "R4-025: invalid config.updated must write audit log");
    const logContent = fs.readFileSync(logFile, "utf8");
    assert.ok(logContent.includes("config-reload-failed"), `R4-025: expected config-reload-failed in audit log, got: ${logContent}`);
  });

  test("Re-audit closure: sanitizeV2ModelRequest enforces project-local scope and finalizeSubagentHandoff guards aborted signal & unhandled rejections", async (t) => {
    const { finalizeSubagentHandoff } = await import("../dist/index.js");
    const { GuardEngine } = await import("../dist/engine.js");
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-reaudit-scope-"));
    const proj = path.join(root, "proj");
    const foreign = path.join(root, "foreign");
    fs.mkdirSync(path.join(proj, ".opencode", "plugins", "opencode-guardian"), { recursive: true });
    fs.mkdirSync(foreign, { recursive: true });
    fs.writeFileSync(path.join(proj, "opencode-guardian.json"), JSON.stringify({
      enabled: true, preflight: { enabled: false }, secrets: { enabled: true }, updateNotice: { enabled: false },
    }));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));

    let contextHook;
    const cleanup = await Guardian.setup({
      location: { directory: proj },
      event: { subscribe: () => (async function* () {})() },
      tool: { async hook() { return { dispose() {} }; } },
      shell: { async hook() { return { dispose() {} }; } },
      session: {
        async get({ sessionID }) {
          if (sessionID === "ses-unverified") throw new Error("lookup failed");
          return { id: sessionID, location: { directory: foreign } };
        },
        async context() { return []; },
        async synthetic() {},
        async hook(kind, cb) {
          if (kind === "context") contextHook = cb;
          return { dispose() {} };
        },
      },
    });
    t.after(async () => { await cleanup?.(); });
    assert.equal(typeof contextHook, "function");

    // Foreign & unverified sessions must NOT be modified by project-local Guardian instance
    const secret = "sk-proj-" + "m".repeat(36);
    const foreignEvent = { sessionID: "ses-foreign", messages: [{ role: "user", content: secret }], system: [] };
    await contextHook(foreignEvent);
    assert.equal(foreignEvent.messages[0].content, secret, "project-local Guardian must not mutate foreign project session.context");

    const unverifiedEvent = { sessionID: "ses-unverified", messages: [{ role: "user", content: secret }], system: [] };
    await contextHook(unverifiedEvent);
    assert.equal(unverifiedEvent.messages[0].content, secret, "project-local Guardian must not mutate unverified session.context");

    // finalizeSubagentHandoff: late rejection after deadline must not trigger unhandledRejection
    let unhandled = 0;
    const onUnhandled = () => { unhandled++; };
    process.on("unhandledRejection", onUnhandled);
    t.after(() => process.off("unhandledRejection", onUnhandled));

    const engine = new GuardEngine({ enabled: true, remediationBudget: 1 });
    await assert.rejects(
      finalizeSubagentHandoff({
        sessionID: "ses-handoff-deadline",
        directory: proj,
        engine,
        remediationTimeoutMs: 25,
        resolveCapability: async () => ({ capability: "write-allowed", evidence: { reasons: ["test"] } }),
        fetchMessages: async () => [
          { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the bug." }] },
          { info: { id: "a1", role: "assistant" }, parts: [{ type: "text", text: "The test failure is unrelated to this change." }] },
        ],
        sendAndWait: () => new Promise((_res, rej) => {
          setTimeout(() => rej(new Error("late host error")), 60);
        }),
      }),
      /could not complete subagent remediation|exceeded deadline/i
    );
    await new Promise((r) => setTimeout(r, 90));
    assert.equal(unhandled, 0, "late sendAndWait rejection after deadline must be absorbed without unhandledRejection");

    // Pass-2 re-audit: resolveV2AgentCapability must retain "context.agent.list query failed" even when sessionPermissions is non-empty
    const { resolveV2AgentCapability } = await import("../dist/agent-capability.js");
    const capProfile = await resolveV2AgentCapability(
      {
        session: {
          async get() {
            return { id: "ses-cap-fail", agent: "explore", permissions: [{ permission: "read", effect: "allow" }] };
          },
        },
        agent: {
          async list() {
            throw new Error("agent list down");
          },
        },
      },
      "ses-cap-fail",
      []
    );
    assert.equal(capProfile.capability, "unknown");
    assert.ok(
      capProfile.evidence.reasons.some((r) => /agent\.list.*failed/i.test(r)),
      `expected context.agent.list query failed in reasons, got: ${JSON.stringify(capProfile.evidence.reasons)}`
    );

    // Pass-2 re-audit: finalizeSubagentHandoff must rollback remediationBudget when blocked by a mesh user_interaction lease
    const { acquireSessionLease } = await import("../dist/bridge.js");
    const releaseLease = acquireSessionLease({
      sessionID: "ses-lease-rb",
      owner: "opencode-smart-questions",
      kind: "user_interaction",
      ttlMs: 30_000,
    });
    t.after(() => releaseLease());
    const leaseEngine = new GuardEngine({ enabled: true, remediationBudget: 1 });
    await finalizeSubagentHandoff({
      sessionID: "ses-lease-rb",
      directory: proj,
      engine: leaseEngine,
      resolveCapability: async () => ({ capability: "write-allowed", evidence: { reasons: ["test"] } }),
      fetchMessages: async () => [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the bug." }] },
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "text", text: "The test failure is unrelated to this change." }] },
      ],
      sendAndWait: async () => { throw new Error("must not send while leased"); },
    });
    assert.equal(
      leaseEngine.sessionState.getTurnRemediationCount("ses-lease-rb", "u1"),
      0,
      "lease-blocked finalizeSubagentHandoff must roll back consumed remediation budget"
    );

    // R5-004: finalizeSubagentHandoff must re-resolve capability on each round so mid-handoff revocation blocks round 1
    let capRound = 0;
    let sendCalls = 0;
    const capDowngradeEngine = new GuardEngine({ enabled: true, remediationBudget: 2 });
    const downgradedOut = await finalizeSubagentHandoff({
      sessionID: "ses-r5-004",
      directory: proj,
      engine: capDowngradeEngine,
      resolveCapability: async () => {
        capRound++;
        return {
          capability: capRound === 1 ? "write-allowed" : "read-only",
          evidence: { reasons: ["round-" + capRound] },
        };
      },
      fetchMessages: async () => [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the bug." }] },
        { info: { id: `a${capRound}`, role: "assistant" }, parts: [{ type: "text", text: "The test failure is unrelated to this change." }] },
      ],
      sendAndWait: async () => { sendCalls++; },
    });
    assert.equal(sendCalls, 1, "R5-004: round 1 must not dispatch remediation after capability downgraded to read-only");
    assert.ok(capRound >= 2, "R5-004: resolveCapability must be re-evaluated on round 1");
    assert.equal(typeof downgradedOut, "string");

    // R5-009: renewSessionLease must reject stale leaseToken
    const { renewSessionLease } = await import("../dist/bridge.js");
    const relA = acquireSessionLease({ sessionID: "ses-r5-009", owner: "opencode-guardian", kind: "active_remediation", ttlMs: 10_000 });
    const relB = acquireSessionLease({ sessionID: "ses-r5-009", owner: "opencode-guardian", kind: "active_remediation", ttlMs: 10_000 });
    t.after(() => { relA(); relB(); });
    assert.equal(renewSessionLease({ sessionID: "ses-r5-009", owner: "opencode-guardian", kind: "active_remediation", leaseToken: relA.leaseToken }), false, "R5-009: stale leaseToken must not renew newer lease");
    assert.equal(renewSessionLease({ sessionID: "ses-r5-009", owner: "opencode-guardian", kind: "active_remediation", leaseToken: relB.leaseToken }), true, "R5-009: active leaseToken must renew cleanly");

    // Pass-1 Part A #2 & #3: trailing [TASK OUTCOME] check ignores mid-body quoted lines and handles long trailing whitespace in linear time
    const outcomeEngine = new GuardEngine({ enabled: true, remediationBudget: 1 });
    const quotedWithRealTail = [
      "The log quoted a previous line:",
      "[TASK OUTCOME] status=failed",
      "Real summary after investigation.",
      "[TASK OUTCOME] status=blocked" + " ".repeat(50_000),
    ].join("\n");
    const tStart = Date.now();
    const outcomeRes = await finalizeSubagentHandoff({
      sessionID: "ses-part-a-outcome",
      directory: proj,
      engine: outcomeEngine,
      resolveCapability: async () => ({ capability: "read-only", evidence: { reasons: ["ro"] } }),
      fetchMessages: async () => [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Investigate." }] },
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "text", text: quotedWithRealTail }] },
      ],
      sendAndWait: async () => { throw new Error("read-only must not send"); },
      initialOutput: quotedWithRealTail,
    });
    assert.ok(Date.now() - tStart < 1000, "trailing outcome parsing must be O(N), not quadratic");
    assert.ok(
      outcomeRes.trimEnd().endsWith("[TASK OUTCOME] status=blocked"),
      `must preserve genuine trailing status=blocked instead of matching mid-body quote, got tail: ${outcomeRes.slice(-120)}`
    );
  });

  test("Pass-1 re-audit: mid-handoff agent switch, keyless background job, and preflight-blocked execute.before", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-pass1-rt-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    fs.writeFileSync(path.join(dir, "app.ts"), "export const v = 1;\n");

    let currentChildAgent = "builder";
    let childMsgCount = 0;
    const childSent = [];
    const parentSent = [];
    let executeBefore;
    let executeAfter;
    let emitEvent;

    const cleanup = await Guardian.setup({
      location: { directory: dir },
      options: {
        enabled: true,
        remediationBudget: 2,
        preflight: { enabled: true, mode: "strict" },
        secrets: { enabled: false },
        updateNotice: { enabled: false },
        rules: {
          "discipline/no-evasion": "error",
          "task/completion-gate": "error",
        },
      },
      agent: {
        async list() {
          return [
            { name: "builder", permissions: [{ permission: "edit", pattern: "*", effect: "allow" }] },
            { name: "reviewer", permissions: [{ permission: "edit", pattern: "*", effect: "deny" }, { permission: "bash", pattern: "*", effect: "deny" }] },
          ];
        },
      },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              const ev = await new Promise((resolve) => {
                emitEvent = resolve;
                signal.addEventListener("abort", () => resolve(null), { once: true });
              });
              if (!ev) break;
              yield ev;
            }
          })();
        },
      },
      tool: {
        async hook(name, cb) {
          if (name === "execute.before") executeBefore = cb;
          if (name === "execute.after") executeAfter = cb;
          return { dispose() {} };
        },
      },
      shell: { async hook() { return { dispose() {} }; } },
      session: {
        async get({ sessionID }) {
          if (sessionID === "ses-child-switch") {
            return { id: sessionID, parentID: "ses-parent-switch", agent: currentChildAgent, location: { directory: dir } };
          }
          return { id: sessionID, location: { directory: dir } };
        },
        async context({ sessionID }) {
          if (sessionID === "ses-child-switch") {
            childMsgCount++;
            return [
              { id: "cu1", type: "user", text: "Fix the bug." },
              {
                id: `ca${childMsgCount}`,
                type: "assistant",
                agent: currentChildAgent,
                content: [{ type: "text", text: "The test failure is unrelated to this change." }],
              },
            ];
          }
          if (sessionID === "ses-bg-anon") {
            return [
              { id: "bu1", type: "user", text: "Fix the bug." },
              { id: "ba1", type: "assistant", content: [{ type: "text", text: "The test failure is unrelated to this change." }] },
            ];
          }
          if (sessionID === "ses-preflight-clean") {
            return [
              { id: "pu1", type: "user", text: "Update app.ts and run tests." },
              {
                id: "pa1",
                type: "assistant",
                content: [
                  {
                    type: "tool",
                    id: "tc-write",
                    name: "write",
                    state: { status: "completed", input: { filePath: "app.ts", content: "export const v = 2;\n" } },
                  },
                  {
                    type: "tool",
                    id: "tc-test",
                    name: "bash",
                    state: { status: "completed", input: { command: "npm test" }, output: "1 passing" },
                  },
                  { type: "text", text: "Updated app.ts and ran npm test cleanly." },
                ],
              },
            ];
          }
          return [];
        },
        async synthetic(payload) {
          if (payload.sessionID === "ses-child-switch") {
            childSent.push(payload);
            // Mid-handoff agent switches from builder -> reviewer before Round 1
            currentChildAgent = "reviewer";
            emitEvent?.({ type: "session.agent.selected", data: { sessionID: "ses-child-switch", agent: "reviewer" } });
          } else {
            parentSent.push(payload);
          }
        },
        async wait() {
          await new Promise((r) => setTimeout(r, 20));
        },
        async hook() { return { dispose() {} }; },
      },
    });
    t.after(async () => {
      emitEvent?.(null);
      await cleanup?.();
    });

    // Part A #1: live context.session.get agent lookup in finalizeSubagentHandoff stops Round 1 after agent switches to read-only reviewer
    await executeBefore({
      id: "call-sub-switch",
      sessionID: "ses-parent-switch",
      tool: "subagent",
      input: { agent: "builder", prompt: "Fix the bug." },
    });
    const taskAfterEvent = {
      id: "call-sub-switch",
      sessionID: "ses-parent-switch",
      tool: "subagent",
      status: "completed",
      input: { agent: "builder", prompt: "Fix the bug." },
      result: {
        output: "The test failure is unrelated to this change.",
        metadata: { sessionID: "ses-child-switch" },
      },
    };
    await executeAfter(taskAfterEvent);
    assert.equal(childSent.length, 1, "Part A #1: Round 1 must NOT send remediation after child agent switched to read-only reviewer");

    // Part A #4: keyless experimental.job.updated running suppresses immediate session.idle until completion
    emitEvent({ type: "experimental.job.updated", data: { info: { sessionID: "ses-bg-anon", status: "running" } } });
    await new Promise((r) => setTimeout(r, 20));
    emitEvent({ type: "session.idle", data: { sessionID: "ses-bg-anon" } });
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(
      parentSent.filter((p) => p.sessionID === "ses-bg-anon").length,
      0,
      "Part A #4: keyless running background job must suppress session.idle remediation"
    );
    emitEvent({ type: "experimental.job.updated", data: { info: { sessionID: "ses-bg-anon", status: "completed" } } });
    await new Promise((r) => setTimeout(r, 20));
    emitEvent({ type: "session.idle", data: { sessionID: "ses-bg-anon" } });
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(
      parentSent.filter((p) => p.sessionID === "ses-bg-anon").length,
      1,
      "Part A #4: once keyless background job completes, session.idle remediation must resume"
    );

    // Part B #1: preflight-rejected mutating tool must NOT leave stale inFlightMutations poisoning subsequent verification snapshot
    await assert.rejects(
      executeBefore({
        id: "call-pf-blocked",
        sessionID: "ses-preflight-clean",
        tool: "bash",
        input: { command: "rm -rf /" },
      }),
      /rejected/i
    );
    // Now run a clean write + npm test in the same session and verify session.idle passes without false overlap invalidation
    fs.writeFileSync(path.join(dir, "app.ts"), "export const v = 2;\n");
    await executeBefore({ id: "call-pf-w", sessionID: "ses-preflight-clean", tool: "write", input: { filePath: "app.ts", content: "export const v = 2;\n" } });
    await executeAfter({
      id: "call-pf-w",
      sessionID: "ses-preflight-clean",
      tool: "write",
      status: "completed",
      input: { filePath: "app.ts", content: "export const v = 2;\n" },
      result: { output: "ok" },
    });
    await executeBefore({ id: "call-pf-t", sessionID: "ses-preflight-clean", tool: "bash", input: { command: "npm test" } });
    await executeAfter({
      id: "call-pf-t",
      sessionID: "ses-preflight-clean",
      tool: "bash",
      status: "completed",
      input: { command: "npm test" },
      result: { output: "1 passing" },
    });
    emitEvent({ type: "session.idle", data: { sessionID: "ses-preflight-clean" } });
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(
      parentSent.filter((p) => p.sessionID === "ses-preflight-clean").length,
      0,
      "Part B #1: preflight-blocked command must not poison inFlightMutations and invalidate subsequent passing test snapshot"
    );
  });
});
