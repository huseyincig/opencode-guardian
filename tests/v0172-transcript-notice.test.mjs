import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, { isTrustedGuardianMetadata, loadConfig } from "../dist/index.js";
import {
  GUARDIAN_INTERVENTION_RPC_ID,
  GUARDIAN_INTERVENTION_RPC_METHOD,
} from "../dist/intervention-rpc.js";

const loop = "我想想".repeat(70);

async function harness(t, notifications) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-transcript-"));
  const isolatedGlobal = path.join(directory, "_global_cfg");
  fs.mkdirSync(isolatedGlobal, { recursive: true });
  const prevConfigDir = process.env.OPENCODE_CONFIG_DIR;
  process.env.OPENCODE_CONFIG_DIR = isolatedGlobal;
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
    ...(notifications ? { notifications } : {}),
    secrets: { enabled: false }, updateNotice: { enabled: false },
  }));
  t.after(() => {
    if (prevConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
    else process.env.OPENCODE_CONFIG_DIR = prevConfigDir;
    fs.rmSync(directory, { recursive: true, force: true });
  });
  const synthetics = [];
  const rpcHandlers = new Map();
  let wake;
  const queue = [];
  const cleanup = await Guardian.setup({
    location: { directory },
    rpc: {
      async register(def, handlers) {
        rpcHandlers.set(def.id, handlers);
        return { dispose() { rpcHandlers.delete(def.id); } };
      },
    },
    session: {
      async context() { return []; },
      async synthetic(req) { synthetics.push(req); return {}; },
      async get() { return { location: { directory } }; },
      async interrupt() {},
    },
    event: { subscribe({ signal }) { return (async function* () {
      signal.addEventListener("abort", () => wake?.(), { once: true });
      while (!signal.aborted) {
        if (!queue.length) await new Promise(resolve => { wake = resolve; });
        const entry = queue.shift();
        if (entry) { yield entry.event; entry.resolve(); }
      }
    })(); } },
  });
  t.after(cleanup);
  const send = async event => {
    await new Promise(resolve => { queue.push({ event, resolve }); wake?.(); });
    await new Promise(resolve => setImmediate(resolve));
  };
  const delta = value => send({ type: "session.text.delta",
    data: { sessionID: "s", assistantMessageID: "a", ordinal: 0, delta: value } });
  const latestIntervention = async (sessionID = "s") => {
    const handlers = rpcHandlers.get(GUARDIAN_INTERVENTION_RPC_ID);
    assert.ok(handlers, "intervention RPC must be registered");
    return handlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID });
  };
  return { directory, synthetics, delta, latestIntervention };
}

test("notifications.transcript delivers detailed banner via TUI RPC and never enqueues visible session.synthetic", async t => {
  const h = await harness(t, { transcript: true });
  await h.delta(loop);
  await new Promise(resolve => setTimeout(resolve, 30));
  const visibleSynthetics = h.synthetics.filter(
    s => isTrustedGuardianMetadata("s", s.metadata, "visible") || /\[Guardian\]/.test(s.text)
  );
  assert.equal(
    visibleSynthetics.length,
    0,
    "display-only notices must never enqueue into session_inbox via session.synthetic (prevents TrailingAssistantHistoryError)"
  );
  const snap = await h.latestIntervention("s");
  assert.equal(snap.active, true);
  assert.match(snap.message, /- runtime\/circuit-breaker:/);
  assert.match(snap.message, /Action:/);
  assert.doesNotMatch(snap.message, /我想想/, "no raw model text in the detailed notice");
  assert.ok(snap.duration > 5000, "detailed conversation notice should stay visible long enough to read");
});

test("default notifications (transcript off) keeps compact conversation banner and never enqueues visible synthetic", async t => {
  const h = await harness(t);
  await h.delta(loop);
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal(h.synthetics.filter(s => /\[Guardian\]/.test(s.text)).length, 0);
  const snap = await h.latestIntervention("s");
  assert.equal(snap.active, true);
  assert.doesNotMatch(snap.message, /Action:/, "compact banner should stay concise when transcript detail mode is off");
});

test("notifications.transcript must be a boolean", t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-transcript-cfg-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({ notifications: { transcript: "yes" } }));
  assert.throws(() => loadConfig(directory), /notifications/);
});

test("notifications.transcript delivers detailed per-finding bullets via RPC on remediation without enqueueing visible synthetic", async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-transcript-detail-"));
  const isolatedGlobal = path.join(directory, "_global_cfg");
  fs.mkdirSync(isolatedGlobal, { recursive: true });
  const prevConfigDir = process.env.OPENCODE_CONFIG_DIR;
  process.env.OPENCODE_CONFIG_DIR = isolatedGlobal;
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
    notifications: { enabled: true, transcript: true },
    updateNotice: { enabled: false },
  }));
  t.after(() => {
    if (prevConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
    else process.env.OPENCODE_CONFIG_DIR = prevConfigDir;
    fs.rmSync(directory, { recursive: true, force: true });
  });

  const synthetics = [];
  const rpcHandlers = new Map();
  let wake;
  const queue = [];
  const messages = [
    { id: "u1", type: "user", text: "Fix the failing unit test." },
    {
      id: "a1",
      type: "assistant",
      agent: "build",
      content: [
        {
          type: "tool",
          id: "c1",
          name: "write",
          state: {
            status: "completed",
            input: {
              filePath: path.join(directory, "src", "demo.ts"),
              content: "export function handle() { try { work(); } catch {} }\n",
            },
          },
        },
        { type: "text", text: "The test failure is unrelated to this change and pre-existing." },
      ],
    },
  ];
  const cleanup = await Guardian.setup({
    location: { directory },
    rpc: {
      async register(def, handlers) {
        rpcHandlers.set(def.id, handlers);
        return { dispose() { rpcHandlers.delete(def.id); } };
      },
    },
    session: {
      async context() { return messages; },
      async synthetic(req) { synthetics.push(req); return { id: `syn-${synthetics.length}` }; },
      async get({ sessionID }) { return { id: sessionID, location: { directory } }; },
      async hook() { return { dispose() {} }; },
    },
    tool: { async hook() { return { dispose() {} }; } },
    shell: { async hook() { return { dispose() {} }; } },
    event: {
      subscribe({ signal }) {
        return (async function* () {
          signal.addEventListener("abort", () => wake?.(), { once: true });
          while (!signal.aborted) {
            if (!queue.length) await new Promise(resolve => { wake = resolve; });
            const entry = queue.shift();
            if (entry) { yield entry.event; entry.resolve(); }
          }
        })();
      },
    },
  });
  t.after(cleanup);

  await new Promise(resolve => {
    queue.push({
      event: { type: "session.execution.succeeded", location: { directory }, data: { sessionID: "s-detail" } },
      resolve,
    });
    wake?.();
  });
  await new Promise(resolve => setTimeout(resolve, 50));

  // Only the actual remediation prompt may use session.synthetic — NEVER a visible display notice!
  const visibleNotices = synthetics.filter(
    s => isTrustedGuardianMetadata("s-detail", s.metadata, "visible") || s.description === "OpenCode Guardian notice"
  );
  assert.equal(visibleNotices.length, 0, "must never enqueue visible display notices into session_inbox");
  const remediations = synthetics.filter(s => isTrustedGuardianMetadata("s-detail", s.metadata, "remediation"));
  assert.equal(remediations.length, 1, "remediation prompt must still be delivered normally");

  const snap = await rpcHandlers.get(GUARDIAN_INTERVENTION_RPC_ID)[GUARDIAN_INTERVENTION_RPC_METHOD]({
    sessionID: "s-detail",
  });
  assert.equal(snap.active, true);
  assert.match(snap.title, /Remediation/);
  assert.match(snap.message, /- discipline\/no-evasion\b/, "must include bullet for triggered rule");
  assert.match(snap.message, /- integrity\/no-silent-failure\b/, "must include bullet for silent failure rule");
  assert.match(snap.message, /empty JavaScript\/TypeScript catch/i, "must include finding pattern/detail");
  assert.match(snap.message, /Action: Agent was asked to correct the issue\./, "must clearly state the action taken");
});

test("notifications.transcript redacts any secret-like tokens in finding descriptions and never leaks raw secrets", async () => {
  const { formatGuardianToast, formatGuardianTranscriptNotice } = await import("../dist/toast.js");
  const secret = "sk-proj-abcdef1234567890abcdef1234567890";
  const input = {
    kind: "remediation",
    ruleIds: ["security/no-secrets"],
    details: [{
      ruleId: "security/no-secrets",
      pattern: "OpenAI API key",
      description: `Hardcoded credential detected near ${secret}`,
      filePath: "src/client.ts",
    }],
  };
  const text = formatGuardianTranscriptNotice(input);
  assert.match(text, /\[Guardian\] ↻ REMEDIATION/);
  assert.match(text, /security\/no-secrets/);
  assert.match(text, /OpenAI API key/);
  assert.match(text, /src\/client\.ts/);
  assert.equal(text.includes(secret), false, "raw secret must never appear in detailed notice");

  const detailedToast = formatGuardianToast(input, { detailed: true });
  assert.match(detailedToast.message, /- security\/no-secrets/);
  assert.match(detailedToast.message, /OpenAI API key/);
  assert.match(detailedToast.message, /src\/client\.ts/);
  assert.equal(detailedToast.message.includes(secret), false, "raw secret must never appear in detailed TUI banner");
});

test("session.context never strips a trailing visible message if doing so would leave history ending on assistant", async t => {
  const { createGuardianMessageMetadata } = await import("../dist/provenance.js");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-trailing-asst-"));
  const isolatedGlobal = path.join(directory, "_global_cfg");
  fs.mkdirSync(isolatedGlobal, { recursive: true });
  const prevConfigDir = process.env.OPENCODE_CONFIG_DIR;
  process.env.OPENCODE_CONFIG_DIR = isolatedGlobal;
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
    notifications: { enabled: true, transcript: true },
    secrets: { enabled: false },
    updateNotice: { enabled: false },
  }));
  t.after(() => {
    if (prevConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
    else process.env.OPENCODE_CONFIG_DIR = prevConfigDir;
    fs.rmSync(directory, { recursive: true, force: true });
  });

  let contextHook;
  const cleanup = await Guardian.setup({
    location: { directory },
    session: {
      async context() { return []; },
      async synthetic() { return {}; },
      async get({ sessionID }) { return { id: sessionID, location: { directory } }; },
      async hook(kind, cb) {
        if (kind === "context") contextHook = cb;
        return { dispose() {} };
      },
    },
    tool: { async hook() { return { dispose() {} }; } },
    shell: { async hook() { return { dispose() {} }; } },
    event: { subscribe() { return (async function* () {})(); } },
  });
  t.after(cleanup);
  assert.equal(typeof contextHook, "function");

  const sid = "ses-trailing";
  const visibleMeta = createGuardianMessageMetadata(sid, "visible");

  // Case 1: trailing visible synthetic after assistant -> must NOT leave trailing assistant!
  const trailingEvent = {
    sessionID: sid,
    system: [],
    messages: [
      { role: "user", content: "hi" },
      { role: "assistant", content: "done" },
      { role: "user", content: "[Guardian] notice", metadata: visibleMeta },
    ],
  };
  await contextHook(trailingEvent);
  assert.notEqual(
    trailingEvent.messages[trailingEvent.messages.length - 1]?.role,
    "assistant",
    "session.context must never turn a non-assistant history tail into a trailing assistant turn"
  );

  // Case 2: mid-conversation visible synthetic followed by a real user message -> safely stripped!
  const midEvent = {
    sessionID: sid,
    system: [],
    messages: [
      { role: "user", content: "hi" },
      { role: "assistant", content: "done" },
      { role: "user", content: "[Guardian] notice", metadata: visibleMeta },
      { role: "user", content: "next question" },
    ],
  };
  await contextHook(midEvent);
  assert.equal(midEvent.messages.length, 3, "mid-conversation visible message is safely stripped");
  assert.equal(midEvent.messages[midEvent.messages.length - 1]?.content, "next question");
});
