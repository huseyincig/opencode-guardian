import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import Guardian, {
  GuardEngine,
  loadConfig,
  resolveEffectiveConfig,
  evaluatePreflight,
  sanitizeString,
  sanitizeObject,
  sanitizeMessages,
  normalizeV2Messages,
  isSessionRemediating,
  getLatestMeshIntervention,
  getActiveMeshHandoff,
  resetMeshStateForTests,
  readGuardianStatus,
  recordGuardianEvent,
  guardianEventPath,
  configureGuardianTelemetry,
  clearGuardianTelemetryConfig,
  GUARDIAN_INTERVENTION_RPC_DEFINITION,
  GUARDIAN_INTERVENTION_RPC_METHOD,
} from "../dist/index.js";
import * as GuardianIndex from "../dist/index.js";
import { splitShellStages } from "../dist/shell-risk.js";
import { hasResearchOnlyConstraint } from "../dist/task-constraints.js";
import { guardianCommandReport } from "../dist/commands.js";

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
    clearGuardianTelemetryConfig();
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


