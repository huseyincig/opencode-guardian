import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, { isTrustedGuardianMetadata, normalizeV2Messages, loadConfig } from "../dist/index.js";

const loop = "我想想".repeat(70);

async function harness(t, notifications) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-transcript-"));
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
    ...(notifications ? { notifications } : {}),
    secrets: { enabled: false }, updateNotice: { enabled: false },
  }));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
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
