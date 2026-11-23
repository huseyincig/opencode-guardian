import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, { readGuardianActivity, readGuardianStatus } from "../dist/index.js";

const loop = "我想想".repeat(70);

async function harness(t) {
  process.env.OPENCODE_GUARDIAN_STREAM_VERIFY_MS = "150";
  t.after(() => { delete process.env.OPENCODE_GUARDIAN_STREAM_VERIFY_MS; });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-stream-verify-"));
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
    secrets: { enabled: false }, updateNotice: { enabled: false },
  }));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let calls = 0, wake;
  const queue = [];
  const cleanup = await Guardian.setup({
    location: { directory },
    session: {
      async context() { return []; },
      async synthetic() {},
      async get() { return { location: { directory } }; },
      async interrupt() { calls++; },
    },
    event: { subscribe({ signal }) { return (async function* () {
      const stop = () => wake?.();
      signal.addEventListener("abort", stop, { once: true });
      try { while (!signal.aborted) {
        if (!queue.length) await new Promise(resolve => { wake = resolve; });
        const entry = queue.shift();
        if (entry) { yield entry.event; entry.resolve(); }
      } } finally { signal.removeEventListener("abort", stop); }
    })(); } },
  });
  t.after(cleanup);
  const send = async event => {
    await new Promise(resolve => { queue.push({ event, resolve }); wake?.(); });
    await new Promise(resolve => setImmediate(resolve));
  };
  const delta = value => send({
    type: "session.text.delta",
    data: { sessionID: "s", assistantMessageID: "a", ordinal: 0, delta: value },
  });
  const kinds = () => readGuardianActivity(directory, 50).map(e => e.kind);
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  return { directory, send, delta, kinds, sleep, get calls() { return calls; } };
}

test("stream stop is verified once the host reports the execution interrupted", async t => {
  const h = await harness(t);
  await h.delta(loop);
  assert.equal(h.calls, 1);
  await h.send({ type: "session.execution.interrupted", data: { sessionID: "s" } });
  assert.ok(h.kinds().includes("stream-interrupt-verified"));
  const status = readGuardianStatus(h.directory);
  assert.equal(status.streamStops, 1);
  assert.equal(status.streamVerified, 1);
  assert.equal(status.streamIneffective, 0);
  await h.sleep(250);
  assert.ok(!h.kinds().includes("stream-interrupt-ineffective"));
});

test("stream stop is ineffective when deltas keep flowing, and the loop may be interrupted again", async t => {
  const h = await harness(t);
  await h.delta(loop);
  assert.equal(h.calls, 1);
  await h.delta("我想想".repeat(12));
  await h.sleep(300);
  assert.ok(h.kinds().includes("stream-interrupt-ineffective"));
  assert.ok(!h.kinds().includes("stream-interrupt-verified"));
  const status = readGuardianStatus(h.directory);
  assert.equal(status.streamStops, 1);
  assert.equal(status.streamIneffective, 1);
  await h.delta(loop);
  assert.equal(h.calls, 2, "an ineffective stop must allow another interrupt attempt");
});

test("stream stop stays unverified when the host sends neither a terminal event nor more deltas", async t => {
  const h = await harness(t);
  await h.delta(loop);
  await h.sleep(300);
  const kinds = h.kinds();
  assert.ok(kinds.includes("stream-interrupt-requested"));
  assert.ok(!kinds.includes("stream-interrupt-verified"));
  assert.ok(!kinds.includes("stream-interrupt-ineffective"));
  assert.equal(readGuardianStatus(h.directory).streamStops, 1);
});
