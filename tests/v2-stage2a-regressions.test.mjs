import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import Guardian, {
  GuardEngine,
  VerificationSnapshotStore,
  collectTurnEvidence,
  evaluatePreflight,
  normalizeV2Messages,
  readGuardianStatus,
  resolveV2AgentCapability,
  sanitizeMessages,
  sanitizeObject,
  GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD,
  GUARDIAN_INTERVENTION_RPC_DEFINITION,
  GUARDIAN_INTERVENTION_RPC_METHOD,
} from "../dist/index.js";
import { StreamLoopWatcher } from "../dist/stream-loop.js";
import TuiPlugin from "../dist/tui.js";

function tempProject(t, config = { enabled: true, secrets: { enabled: false }, updateNotice: { enabled: false } }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-stage2a-"));
  const oldState = process.env.OPENCODE_GUARDIAN_STATE_DIR;
  process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(dir, "state");
  fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify(config));
  t.after(() => {
    if (oldState === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    else process.env.OPENCODE_GUARDIAN_STATE_DIR = oldState;
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
});

// 4. OpenCode v2.3.0 session.fork / session.forked + top-level location.directory + background: true subagents
test("V2 session.fork/forked treated as root, top-level location.directory honored, and background subagents isolated", async (t) => {
  const dirA = tempProject(t, { enabled: true, rules: { "integrity/no-evasion": "error" }, secrets: { enabled: false } });
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
