import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, {
  getLatestMeshIntervention,
  recordMeshIntervention,
  resetMeshStateForTests,
} from "../dist/index.js";
import TuiPlugin from "../dist/tui.js";

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
