import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, { clearGuardianTelemetryConfig, guardianEventPath, guardianStateDirectory, readGuardianStatus, recordGuardianEvent, sanitizeToolResultWithMeta } from "../dist/index.js";
import TuiPlugin from "../dist/tui.js";

describe("Project Scope & External State Isolation", () => {
  test("state directory isolation: never writes guardian-events.jsonl inside project .opencode directory", (t) => {
    const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-no-dot-opencode-"));
    fs.mkdirSync(path.join(projectDir, ".opencode"), { recursive: true });
    t.after(() => fs.rmSync(projectDir, { recursive: true, force: true }));

    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    t.after(() => {
      if (origStateDir !== undefined) process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      else delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    });

    // 1. In NODE_TEST_CONTEXT without OPENCODE_GUARDIAN_STATE_DIR, state lives in tmpdir per-PID projects/<hash>
    const testStateDir = guardianStateDirectory(projectDir);
    assert.ok(
      testStateDir.startsWith(path.join(os.tmpdir(), `opencode-guardian-tests-${process.pid}`, "projects")),
      `Expected test state dir under tmpdir projects/, got: ${testStateDir}`
    );
    assert.equal(testStateDir.startsWith(projectDir), false);

    recordGuardianEvent({ kind: "runtime-started", runtime: "v2", preflight: "active" }, projectDir);
    recordGuardianEvent({ kind: "preflight-blocked", tool: "bash", rules: ["destructive-command"] }, projectDir);

    assert.equal(
      fs.existsSync(path.join(projectDir, ".opencode", "guardian-events.jsonl")),
      false,
      "must NEVER create .opencode/guardian-events.jsonl inside the project directory"
    );
    assert.equal(fs.existsSync(guardianEventPath(projectDir)), true);
    assert.equal(readGuardianStatus(projectDir).blocked, 1);

    // 2. Outside NODE_TEST_CONTEXT without OPENCODE_GUARDIAN_STATE_DIR, state resolves under ~/.local/state/opencode-guardian/projects/<hash>
    const origTestCtx = process.env.NODE_TEST_CONTEXT;
    delete process.env.NODE_TEST_CONTEXT;
    try {
      const prodStateDir = guardianStateDirectory(projectDir);
      const expectedBase = path.join(os.homedir(), ".local", "state", "opencode-guardian", "projects");
      assert.ok(
        prodStateDir.startsWith(expectedBase),
        `Expected production state dir under ${expectedBase}, got: ${prodStateDir}`
      );
      assert.equal(prodStateDir.startsWith(projectDir), false);
    } finally {
      if (origTestCtx !== undefined) process.env.NODE_TEST_CONTEXT = origTestCtx;
    }
  });

  test("project scope isolation: local Guardian in projectA never interferes with foreign projectB (e.g. opencode-hi)", async (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-scope-isolation-"));
    const projectA = path.join(root, "opencode-hi-suite-test");
    const projectB = path.join(root, "opencode-hi");
    fs.mkdirSync(path.join(projectA, ".opencode", "plugins", "opencode-guardian"), { recursive: true });
    fs.mkdirSync(path.join(projectA, ".opencode", "node_modules", "opencode-guardian"), { recursive: true });
    fs.mkdirSync(path.join(projectB, ".opencode", "plugins", "opencode-hi"), { recursive: true });
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));

    const origConfigDir = process.env.OPENCODE_CONFIG_DIR;
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_CONFIG_DIR = path.join(root, "isolated-global-config");
    delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    t.after(() => {
      if (origConfigDir !== undefined) process.env.OPENCODE_CONFIG_DIR = origConfigDir;
      else delete process.env.OPENCODE_CONFIG_DIR;
      if (origStateDir !== undefined) process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      else delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    });

    const eventQueue = [];
    let wake = null;
    const pushEvent = async (ev) => {
      eventQueue.push(ev);
      wake?.();
      await new Promise((r) => setTimeout(r, 25));
    };

    const interrupts = [];
    const synthetics = [];
    const hooks = new Map();

    const cleanup = await Guardian.setup({
      location: { directory: projectA },
      options: {
        enabled: true,
        preflight: { enabled: true },
        secrets: { enabled: false },
        rules: {
          "runtime/circuit-breaker": "error",
          "discipline/no-evasion": "error",
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
      tool: {
        hook: async (name, cb) => {
          hooks.set(name, cb);
          return { dispose() {} };
        },
      },
      session: {
        get: async ({ sessionID }) => ({
          id: sessionID,
          location: {
            directory: sessionID.startsWith("hi-") ? projectB : projectA,
          },
        }),
        context: async () => [
          { id: "u1", type: "user", text: "Fix the bug" },
          {
            id: "a1",
            type: "assistant",
            content: [{ type: "text", text: "The failing test is unrelated to my changes." }],
          },
        ],
        synthetic: async (payload) => {
          synthetics.push(payload);
        },
        interrupt: async ({ sessionID }) => {
          interrupts.push(sessionID);
          return true;
        },
        hook: async (name, cb) => {
          hooks.set(`session.${name}`, cb);
          return { dispose() {} };
        },
      },
    });
    t.after(async () => {
      eventQueue.push(null);
      wake?.();
      await cleanup?.();
    });

    // 1. Foreign projectB session emits repetitive stream delta -> must NOT be interrupted
    await pushEvent({
      type: "session.text.delta",
      data: {
        sessionID: "hi-coder-foreign",
        assistantMessageID: "msg-1",
        ordinal: 0,
        delta: "repeating phrase ".repeat(15),
      },
    });
    assert.deepEqual(interrupts, [], "foreign projectB stream must never be interrupted by projectA's local Guardian");

    // 2. Foreign projectB session calls a destructive bash tool -> must NOT be blocked by projectA's Guardian
    await hooks.get("execute.before")({
      id: "call-foreign",
      sessionID: "hi-coder-foreign",
      tool: "bash",
      input: { command: "rm -rf /" },
    });

    // 3. Foreign projectB session goes idle -> must NOT receive Guardian remediation or write telemetry
    await pushEvent({
      type: "session.idle",
      data: { sessionID: "hi-coder-foreign" },
    });
    assert.equal(synthetics.filter((s) => s.sessionID === "hi-coder-foreign").length, 0);
    assert.equal(fs.existsSync(path.join(projectB, ".opencode", "guardian-events.jsonl")), false);
    assert.equal(fs.existsSync(guardianEventPath(projectB)), false, "must not create any telemetry file for foreign projectB");

    // 4. Own projectA session DOES get preflight-blocked and stream-interrupted as expected
    await assert.rejects(
      () =>
        hooks.get("execute.before")({
          id: "call-local",
          sessionID: "local-session",
          tool: "bash",
          input: { command: "rm -rf /" },
        }),
      /Tool execution rejected/
    );
    await pushEvent({
      type: "session.text.delta",
      data: {
        sessionID: "local-session",
        assistantMessageID: "msg-local",
        ordinal: 0,
        delta: "repeating phrase ".repeat(15),
      },
    });
    assert.deepEqual(interrupts, ["local-session"]);
    assert.equal(fs.existsSync(path.join(projectA, ".opencode", "guardian-events.jsonl")), false);
  });

  test("global installation: Guardian installed in global ~/.config/opencode protects all projects without writing to project .opencode/", async (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-global-install-"));
    const fakeConfigDir = path.join(root, "global-opencode-config");
    const projectA = path.join(root, "project-a");
    const projectB = path.join(root, "project-b");
    fs.mkdirSync(fakeConfigDir, { recursive: true });
    fs.writeFileSync(
      path.join(fakeConfigDir, "opencode.json"),
      JSON.stringify({ plugin: ["opencode-guardian@latest"] })
    );
    fs.mkdirSync(path.join(projectA, ".git"), { recursive: true });
    fs.mkdirSync(path.join(projectB, ".opencode"), { recursive: true });
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));

    const origConfigDir = process.env.OPENCODE_CONFIG_DIR;
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_CONFIG_DIR = fakeConfigDir;
    delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    t.after(() => {
      if (origConfigDir !== undefined) process.env.OPENCODE_CONFIG_DIR = origConfigDir;
      else delete process.env.OPENCODE_CONFIG_DIR;
      if (origStateDir !== undefined) process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      else delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    });

    const hooks = new Map();
    const cleanup = await Guardian.setup({
      location: { directory: projectA },
      options: {
        enabled: true,
        preflight: { enabled: true },
        secrets: { enabled: false },
      },
      event: { subscribe: () => (async function* () {})() },
      tool: {
        hook: async (name, cb) => {
          hooks.set(name, cb);
          return { dispose() {} };
        },
      },
      session: {
        get: async ({ sessionID }) => ({
          id: sessionID,
          location: { directory: sessionID === "sess-b" ? projectB : projectA },
        }),
        context: async () => [],
        synthetic: async () => {},
      },
    });
    t.after(async () => {
      await cleanup?.();
    });

    // Global install enforces preflight on projectB too
    await assert.rejects(
      () =>
        hooks.get("execute.before")({
          id: "call-b",
          sessionID: "sess-b",
          tool: "bash",
          input: { command: "rm -rf /" },
        }),
      /Tool execution rejected/
    );

    // Neither projectA nor projectB has .opencode/guardian-events.jsonl created inside the repo
    assert.equal(fs.existsSync(path.join(projectA, ".opencode", "guardian-events.jsonl")), false);
    assert.equal(fs.existsSync(path.join(projectB, ".opencode", "guardian-events.jsonl")), false);
    // Telemetry for projectB is recorded in the external state directory keyed by projectB
    assert.equal(readGuardianStatus(projectB).blocked, 1);
  });

  test("guardianStateDirectory respects absolute XDG_STATE_HOME when OPENCODE_GUARDIAN_STATE_DIR and NODE_TEST_CONTEXT are unset", (t) => {
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    const origNodeTest = process.env.NODE_TEST_CONTEXT;
    const origXdgState = process.env.XDG_STATE_HOME;
    t.after(() => {
      if (origStateDir !== undefined) process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      else delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      if (origNodeTest !== undefined) process.env.NODE_TEST_CONTEXT = origNodeTest;
      else delete process.env.NODE_TEST_CONTEXT;
      if (origXdgState !== undefined) process.env.XDG_STATE_HOME = origXdgState;
      else delete process.env.XDG_STATE_HOME;
    });

    delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    delete process.env.NODE_TEST_CONTEXT;
    const xdgRoot = path.join(os.tmpdir(), "guardian-xdg-state-test");
    process.env.XDG_STATE_HOME = xdgRoot;

    const projectDir = path.join(os.tmpdir(), "guardian-xdg-project");
    const resolved = guardianStateDirectory(projectDir);
    assert.equal(resolved.startsWith(path.join(xdgRoot, "opencode-guardian", "projects") + path.sep), true);

    // Relative XDG_STATE_HOME is ignored per XDG Base Directory Specification
    process.env.XDG_STATE_HOME = "relative/state/path";
    const fallback = guardianStateDirectory(projectDir);
    assert.equal(
      fallback.startsWith(path.join(os.homedir(), ".local", "state", "opencode-guardian", "projects") + path.sep),
      true
    );
  });
});

describe("Runtime & TUI Performance Optimizations", () => {
  test("1. sanitizeToolResultWithMeta redacts V2 Tool.Result in a single pass and execute.after avoids JSON.stringify", async (t) => {
    const secret = "sk-proj-abcdef1234567890abcdef1234567890";
    const singlePass = sanitizeToolResultWithMeta({
      content: [{ type: "text", text: `token=${secret}` }],
      metadata: { ok: true },
    });
    assert.equal(singlePass.redactedCount > 0, true);
    assert.equal(singlePass.sanitized.content[0].text.includes(secret), false);

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-perf-stringify-"));
    t.after(() => {
      clearGuardianTelemetryConfig();
      fs.rmSync(dir, { recursive: true, force: true });
    });
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      updateNotice: { enabled: false },
    }));

    const afterHooks = [];
    const cleanup = await Guardian.setup({
      location: { directory: dir },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
          })();
        },
      },
      session: {
        async get({ sessionID }) { return { id: sessionID, location: { directory: dir } }; },
        async context() { return []; },
        async synthetic() { return { id: "s1" }; },
        async hook() { return { dispose() {} }; },
      },
      tool: {
        async hook(kind, cb) {
          if (kind === "execute.after") afterHooks.push(cb);
          return { dispose() {} };
        },
      },
      shell: { async hook() { return { dispose() {} }; } },
    });
    t.after(async () => cleanup?.());

    let toJsonCalls = 0;
    const resultWithSpy = {
      content: [{ type: "text", text: `API_KEY=${secret}` }],
      metadata: {
        nested: {
          toJSON() {
            toJsonCalls += 1;
            return {};
          },
        },
      },
    };

    const ev = {
      tool: "shell",
      sessionID: "ses-perf-1",
      id: "call-1",
      input: { command: "echo test" },
      status: "completed",
      result: resultWithSpy,
    };
    for (const cb of afterHooks) {
      await cb(ev);
    }

    assert.equal(toJsonCalls, 0, "execute.after must not call JSON.stringify on tool results");
    assert.equal(ev.result.content[0].text.includes(secret), false);
    assert.equal(readGuardianStatus(dir).redacted >= 1, true, "redaction counter must still increment");
  });

  test("2. readGuardianStatus memoizes unchanged log files and invalidates immediately on new events", (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-perf-statcache-"));
    t.after(() => {
      clearGuardianTelemetryConfig();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    recordGuardianEvent({ kind: "post-warning", rules: ["discipline/no-evasion"] }, dir);
    const first = readGuardianStatus(dir);
    assert.equal(first.warnings, 1);

    const second = readGuardianStatus(dir);
    assert.deepEqual(second, first);

    // Immediately recording another event must invalidate the cache even within the same millisecond
    recordGuardianEvent({ kind: "post-warning", rules: ["quality/no-shortcuts"] }, dir);
    const third = readGuardianStatus(dir);
    assert.equal(third.warnings, 2);
  });

  test("3. TUI adaptive RPC polling slows down while session is idle and wakes immediately on session.status / session.idle", async () => {
    const listeners = new Map();
    let rpcCalls = 0;
    let currentStatus = "idle";

    const cleanup = TuiPlugin.setup({
      location: { directory: process.cwd() },
      ui: {
        slot() {
          return () => {};
        },
        router: {
          current: () => ({ type: "session", sessionID: "ses-idle-1" }),
        },
      },
      data: {
        session: {
          get: (sid) => (sid === "ses-idle-1" ? { id: sid, location: { directory: process.cwd() } } : undefined),
          status: () => currentStatus,
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
      // Wait 1150ms while completely idle: old 500ms interval would fire 3 times (initial + 500ms + 1000ms).
      // Adaptive idle cadence (5000ms) must keep this at 1 (initial fetch only).
      await new Promise((r) => setTimeout(r, 1150));
      assert.equal(rpcCalls, 1, `expected only 1 initial RPC call while idle, got ${rpcCalls}`);

      // Event-driven wake: session.idle must immediately trigger a refresh
      assert.equal(typeof listeners.get("session.idle"), "function", "TUI must subscribe to session.idle");
      assert.equal(typeof listeners.get("session.status"), "function", "TUI must subscribe to session.status");

      listeners.get("session.idle")?.({ type: "session.idle", data: { sessionID: "ses-idle-1" } });
      await new Promise((r) => setTimeout(r, 30));
      assert.equal(rpcCalls, 2, "session.idle must immediately refresh RPC intervention");
    } finally {
      cleanup?.();
    }
  });
});
