import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, {
  guardianEventPath,
  guardianStateDirectory,
  readGuardianStatus,
  recordGuardianEvent,
} from "../dist/index.js";

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

  const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
  delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
  t.after(() => {
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

