import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, {
  normalizeV2Messages,
  collectTurnEvidence,
  hasUnfinishedBackgroundTool,
  cacheAgentCapability,
  getCachedAgentCapability,
  clearAllAgentCapabilities,
} from "../dist/index.js";

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
