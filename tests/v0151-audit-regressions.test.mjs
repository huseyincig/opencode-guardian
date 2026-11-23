import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import plugin from "../dist/index.js";
import tuiPlugin from "../dist/tui.js";
import { guardianCommandReport } from "../dist/commands.js";
import {
  sanitizeMessages,
  sanitizeString,
  resolveSanitizerOptions,
} from "../dist/secrets/index.js";
import {
  DEFAULT_GUARDIAN_LOG_BYTES,
  clearGuardianTelemetryConfig,
  resolveTelemetrySettings,
} from "../dist/telemetry.js";
import {
  GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD,
  GUARDIAN_INTERVENTION_RPC_DEFINITION,
  GUARDIAN_INTERVENTION_RPC_ID,
} from "../dist/intervention-rpc.js";
import { dispatchGuardianToast } from "../dist/toast.js";

function makeTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function emptyStream() {
  return {
    async *[Symbol.asyncIterator]() {
      // keep open briefly then exit cleanly
    },
  };
}

test("sanitizeMessages preserves Message/Part prototypes with parts and redacts reasoning/top-level tool fields", () => {
  class V2Part {
    constructor(data) {
      Object.assign(this, data);
    }
  }
  class V2Message {
    constructor(info, parts) {
      this.info = info;
      this.parts = parts;
    }
  }

  const secret = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";
  const textPart = new V2Part({ type: "text", text: "ok" });
  const reasoningPart = new V2Part({ type: "reasoning", text: `secret=${secret}` });
  const toolPart = new V2Part({ type: "tool", output: `Bearer ${secret}` });
  const msg = new V2Message({ id: "m1", role: "assistant", note: secret }, [
    textPart,
    reasoningPart,
    toolPart,
  ]);

  const sanitized = sanitizeMessages([msg]);
  assert.equal(sanitized.length, 1);
  assert.ok(sanitized[0] instanceof V2Message, "Message prototype must be preserved");
  assert.ok(sanitized[0].parts[0] instanceof V2Part, "Part prototype must be preserved");
  assert.equal(sanitized[0].parts[1].text.includes(secret), false, "reasoning text must be redacted");
  assert.equal(sanitized[0].parts[2].output.includes(secret), false, "top-level tool output must be redacted");
  assert.equal(sanitized[0].info.note.includes(secret), false, "message info fields must be redacted");
});

test("SanitizerOptions.safeValues exempts explicitly safe literals across string and object sanitization", () => {
  const safeToken = "sk-proj-safe_public_demo_token_1234567890";
  const realSecret = "sk-proj-real_secret_token_9876543210abcd";
  const opts = resolveSanitizerOptions({
    secrets: {
      enabled: true,
      safeValues: [safeToken],
    },
  });
  assert.ok(opts);
  assert.equal(sanitizeString(safeToken, opts).sanitized, safeToken);
  assert.notEqual(sanitizeString(realSecret, opts).sanitized, realSecret);

  const kv = sanitizeString(`API_KEY=${safeToken}`, opts);
  assert.equal(kv.sanitized, `API_KEY=${safeToken}`);
});

test("shell.hook('create.before') resolves event.cwd when sessionID and location.directory are absent", async (t) => {
  const dirA = makeTempDir("guardian-cwd-a-");
  const dirB = makeTempDir("guardian-cwd-b-");
  t.after(() => {
    clearGuardianTelemetryConfig();
    fs.rmSync(dirA, { recursive: true, force: true });
    fs.rmSync(dirB, { recursive: true, force: true });
  });

  // Project A has preflight disabled; Project B has strict preflight enabled
  fs.writeFileSync(
    path.join(dirA, "opencode-guardian.json"),
    JSON.stringify({ enabled: true, preflight: { enabled: false }, telemetry: { level: "off" } })
  );
  fs.writeFileSync(
    path.join(dirB, "opencode-guardian.json"),
    JSON.stringify({ enabled: true, preflight: { enabled: true }, telemetry: { level: "off" } })
  );

  let shellBeforeHandler;
  const dispose = await plugin.setup({
    location: { directory: dirA },
    event: { subscribe: () => emptyStream() },
    session: {
      hook: () => ({ dispose() {} }),
      context: () => ({ dispose() {} }),
      synthetic: async () => {},
    },
    tool: { hook: () => ({ dispose() {} }) },
    shell: {
      hook: async (name, cb) => {
        if (name === "create.before") shellBeforeHandler = cb;
        return { dispose() {} };
      },
    },
  });
  t.after(() => dispose?.());

  assert.equal(typeof shellBeforeHandler, "function");
  await assert.rejects(
    () => shellBeforeHandler({ command: "rm -rf /tmp/nonexistent-target", cwd: dirB }),
    /preflight|destructive/i,
    "shell.create.before must enforce dirB strict preflight using event.cwd"
  );
});

test("guardian.interventions.clear RPC honors directory/location context and resolves uncached session directories", async (t) => {
  const dirA = makeTempDir("guardian-rpc-a-");
  const dirB = makeTempDir("guardian-rpc-b-");
  t.after(() => {
    clearGuardianTelemetryConfig();
    fs.rmSync(dirA, { recursive: true, force: true });
    fs.rmSync(dirB, { recursive: true, force: true });
  });

  fs.writeFileSync(
    path.join(dirA, "opencode-guardian.json"),
    JSON.stringify({ enabled: true, preflight: { enabled: true }, telemetry: { level: "off" } })
  );
  fs.writeFileSync(
    path.join(dirB, "opencode-guardian.json"),
    JSON.stringify({ enabled: true, preflight: { enabled: true }, telemetry: { level: "off" } })
  );

  let rpcHandlers;
  let toolBefore;
  const dispose = await plugin.setup({
    location: { directory: dirA },
    event: { subscribe: () => emptyStream() },
    session: {
      hook: () => ({ dispose() {} }),
      context: () => ({ dispose() {} }),
      synthetic: async () => {},
      get: async ({ sessionID }) => ({
        id: sessionID,
        location: { directory: sessionID === "s-b" ? dirB : dirA },
      }),
    },
    tool: {
      hook: (name, cb) => {
        if (name === "execute.before") toolBefore = cb;
        return { dispose() {} };
      },
    },
    rpc: {
      register: async (_def, handlers) => {
        rpcHandlers = handlers;
        return { dispose() {} };
      },
    },
  });
  t.after(() => dispose?.());

  // Trigger a preflight block on session s-a (dirA) and s-b (dirB)
  await assert.rejects(() => toolBefore({ tool: "bash", sessionID: "s-a", input: { command: "rm -rf /" } }));
  await assert.rejects(() => toolBefore({ tool: "bash", sessionID: "s-b", input: { command: "rm -rf /" } }));

  const beforeA = await rpcHandlers.latest({ sessionID: "s-a" });
  const beforeB = await rpcHandlers.latest({ sessionID: "s-b" });
  assert.equal(beforeA.active, true);
  assert.equal(beforeB.active, true);

  // Clear dirB with {} + { location: { directory: dirB } }; s-a must stay active!
  await rpcHandlers[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD]({}, { location: { directory: dirB } });
  const afterA = await rpcHandlers.latest({ sessionID: "s-a" });
  const afterB = await rpcHandlers.latest({ sessionID: "s-b" });
  assert.equal(afterA.active, true, "dirA intervention must not be cleared when clearing dirB");
  assert.equal(afterB.active, false, "dirB intervention must be cleared");
});

test("guardianCommandReport applies V2 context.options overrides in doctor, rules, and config", async (t) => {
  const dir = makeTempDir("guardian-cmd-opts-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const options = {
    preflight: { enabled: true },
    rules: { "safety/destructive-operations": "error" },
  };
  const doctor = await guardianCommandReport("doctor", dir, "0.15.1", options);
  const rules = await guardianCommandReport("rules", dir, "0.15.1", options);
  const config = await guardianCommandReport("config", dir, "0.15.1", options);

  assert.match(doctor.message, /Strict preflight configured: enabled/);
  assert.match(rules.message, /safety\/destructive-operations: error/);
  assert.match(config.message, /Strict preflight: enabled/);
});

test("TUI ownsInterventionScope delivers same-directory preflight toast before context.data.session syncs", (t) => {
  const dir = makeTempDir("guardian-tui-scope-");
  const otherDir = makeTempDir("guardian-tui-other-");
  t.after(() => {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(otherDir, { recursive: true, force: true });
  });

  const shown = [];
  const cleanups = [];
  const dispose = tuiPlugin.setup({
    location: { directory: dir },
    ui: {
      slot: () => ({ dispose() {} }),
      toast: { show: (p) => shown.push(p) },
      dialog: { alert: async () => {}, confirm: async () => false },
    },
    lifecycle: { onCleanup: (fn) => cleanups.push(fn) },
    // Minimal/unsynced context.data.session: returns undefined for new session
    data: { session: { get: () => undefined } },
  });
  t.after(() => {
    dispose?.();
    for (const fn of cleanups) fn();
  });

  dispatchGuardianToast(
    { title: "Blocked", message: "destructive", variant: "error", duration: 3000 },
    { directory: dir, sessionID: "new-unsynced-session" }
  );
  dispatchGuardianToast(
    { title: "Other", message: "other project", variant: "error", duration: 3000 },
    { directory: otherDir, sessionID: "other-session" }
  );

  assert.equal(shown.length, 1);
  assert.equal(shown[0].title, "Blocked");
});

test("enabled: false cleans up telemetryConfigRegistry and default maxBytes is 512 KiB", async (t) => {
  const dir = makeTempDir("guardian-disabled-reg-");
  t.after(() => {
    clearGuardianTelemetryConfig();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  fs.writeFileSync(
    path.join(dir, "opencode-guardian.json"),
    JSON.stringify({ enabled: false, telemetry: { level: "off", maxBytes: 12345 } })
  );

  await plugin.setup({
    location: { directory: dir },
    event: { subscribe: () => emptyStream() },
    session: { context: () => ({ dispose() {} }), synthetic: async () => {} },
  });

  const settings = resolveTelemetrySettings(dir);
  assert.equal(settings.maxBytes, DEFAULT_GUARDIAN_LOG_BYTES);
  assert.equal(DEFAULT_GUARDIAN_LOG_BYTES, 512 * 1024);
  assert.equal(settings.level, "violations");
});

test("GUARDIAN_INTERVENTION_RPC_DEFINITION exposes RPC id and directory-scoped clear schema", () => {
  assert.equal(GUARDIAN_INTERVENTION_RPC_DEFINITION.id, GUARDIAN_INTERVENTION_RPC_ID);
  assert.equal(
    GUARDIAN_INTERVENTION_RPC_DEFINITION.methods[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD].input.properties.directory.type,
    "string"
  );
});
