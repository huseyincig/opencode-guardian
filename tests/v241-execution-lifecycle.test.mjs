import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, {
  GuardEngine,
  clearGuardianTelemetryConfig,
  hasUnfinishedBackgroundTool,
  normalizeV2Messages,
  readGuardianStatus,
} from "../dist/index.js";
import TuiPlugin from "../dist/tui.js";

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
    clearGuardianTelemetryConfig();
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
    clearGuardianTelemetryConfig();
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
