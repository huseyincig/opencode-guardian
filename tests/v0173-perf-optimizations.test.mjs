import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, {
  clearGuardianTelemetryConfig,
  readGuardianStatus,
  recordGuardianEvent,
  sanitizeToolResultWithMeta,
} from "../dist/index.js";
import TuiPlugin from "../dist/tui.js";

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
