import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, { isTrustedGuardianMetadata, normalizeV2Messages, loadConfig } from "../dist/index.js";

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
  let wake;
  const queue = [];
  const cleanup = await Guardian.setup({
    location: { directory },
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
  return { directory, synthetics, delta };
}

test("notifications.transcript posts a model-invisible visible notice into the chat", async t => {
  const h = await harness(t, { transcript: true });
  await h.delta(loop);
  await new Promise(resolve => setTimeout(resolve, 30));
  const notices = h.synthetics.filter(s => /\[Guardian\]/.test(s.text));
  assert.equal(notices.length, 1);
  const [notice] = notices;
  assert.equal(notice.sessionID, "s");
  assert.equal(notice.resume, false, "a notice must never wake the model");
  assert.equal(isTrustedGuardianMetadata("s", notice.metadata, "visible"), true);
  assert.doesNotMatch(notice.text, /我想想/, "no raw model text in the notice");
  assert.deepEqual(normalizeV2Messages([{ id: "n1", type: "synthetic", text: notice.text, metadata: notice.metadata }], "s"), [],
    "Guardian must not inspect its own notice");
});

test("no transcript notice unless notifications.transcript is enabled", async t => {
  const h = await harness(t);
  await h.delta(loop);
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal(h.synthetics.filter(s => /\[Guardian\]/.test(s.text)).length, 0);
});

test("notifications.transcript must be a boolean", t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-transcript-cfg-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({ notifications: { transcript: "yes" } }));
  assert.throws(() => loadConfig(directory), /notifications/);
});

test("notifications.transcript posts detailed finding bullets (rule, pattern, description, action) on post-turn remediation", async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-transcript-detail-"));
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
    notifications: { enabled: true, transcript: true },
    updateNotice: { enabled: false },
  }));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));

  const synthetics = [];
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

  const notices = synthetics.filter(s => /\[Guardian\]/.test(s.text));
  assert.equal(notices.length, 1, "expected 1 detailed transcript notice");
  const notice = notices[0];
  assert.equal(notice.resume, false);
  assert.equal(isTrustedGuardianMetadata("s-detail", notice.metadata, "visible"), true);
  assert.match(notice.text, /↻ REMEDIATION/, "must clearly show intervention type badge");
  assert.match(notice.text, /- discipline\/no-evasion\b/, "must include bullet for triggered rule");
  assert.match(notice.text, /- integrity\/no-silent-failure\b/, "must include bullet for silent failure rule");
  assert.match(notice.text, /empty JavaScript\/TypeScript catch/i, "must include finding pattern/detail");
  assert.match(notice.text, /Action:/, "must clearly state the action taken");
});

test("notifications.transcript redacts any secret-like tokens in finding descriptions and never leaks raw secrets", async () => {
  const { formatGuardianTranscriptNotice } = await import("../dist/toast.js");
  const secret = "sk-proj-abcdef1234567890abcdef1234567890";
  const text = formatGuardianTranscriptNotice({
    kind: "remediation",
    ruleIds: ["security/no-secrets"],
    details: [{
      ruleId: "security/no-secrets",
      pattern: "OpenAI API key",
      description: `Hardcoded credential detected near ${secret}`,
      filePath: "src/client.ts",
    }],
  });
  assert.match(text, /\[Guardian\] ↻ REMEDIATION/);
  assert.match(text, /security\/no-secrets/);
  assert.match(text, /OpenAI API key/);
  assert.match(text, /src\/client\.ts/);
  assert.equal(text.includes(secret), false, "raw secret must never appear in chat transcript notice");
});
