import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, { detectDegenerativeLoop, normalizeV2Messages, circuitBreakerRule,
  readGuardianActivity, readGuardianStatus } from "../dist/index.js";

const loop = "我想想".repeat(70);
function fixture(t, rules = "error") {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-stream-fixes-"));
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
    rules: { "runtime/circuit-breaker": rules }, secrets: { enabled: false }, updateNotice: { enabled: false },
  }));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

async function v2(t, setting = "error", interrupt = async () => {}, sessionDirectory) {
  const directory = fixture(t, setting);
  let calls = 0, wake;
  const queue = [];
  const cleanup = await Guardian.setup({ location: { directory },
    session: {
      async context() { return []; }, async synthetic() {},
      async get() { return { location: { directory: sessionDirectory ?? directory } }; },
      async interrupt(input) { calls++; return interrupt(input); },
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
  const delta = (value, type = "text", ordinal = 0, assistantMessageID = "a") => send({
    type: `session.${type}.delta`, data: { sessionID: "s", assistantMessageID, ordinal, delta: value },
  });
  return { directory, cleanup, send, delta, get calls() { return calls; } };
}

test("native V2 text and reasoning deltas interrupt without waiting for idle", async t => {
  for (const kind of ["text", "reasoning"]) {
    const h = await v2(t);
    for (let n = 0; n < 8; n++) await h.delta("我想想".repeat(12), kind, 0);
    assert.equal(h.calls, 1, kind);
    assert.equal(readGuardianStatus(h.directory).blocked, 0, "a stop request is not a preflight prevention");
    assert.ok(readGuardianActivity(h.directory, 30).some(e => e.kind === "stream-interrupt-requested"));
  }
});

test("V2 honors string and object warn/off settings", async t => {
  for (const setting of ["off", { severity: "off" }, "warn", { severity: "warn" }]) {
    const b = await v2(t, setting); await b.delta(loop);
    assert.equal(b.calls, 0, JSON.stringify(setting));
    if (setting === "warn" || setting.severity === "warn") {
      assert.equal(readGuardianStatus(b.directory).warnings, 1);
    }
  }
});

test("V2 retries a rejected interrupt but deduplicates successful admission", async t => {
  let attempts = 0;
  const h = await v2(t, "error", async () => { if (++attempts === 1) throw new Error("fixture transport failure"); });
  await h.delta(loop); await h.delta(loop); await h.delta(loop);
  assert.equal(h.calls, 2);
  assert.equal(readGuardianStatus(h.directory).errors, 1);
});

test("V2 uses the active project's rule setting for native deltas", async t => {
  const other = fixture(t, "off");
  const h = await v2(t, "error", async () => {}, other);
  await h.delta(loop);
  assert.equal(h.calls, 0);
});

test("V2 reasoning survives normalization and reaches the post-turn rule", () => {
  const messages = normalizeV2Messages([{ id: "a", type: "assistant", content: [{ type: "reasoning", text: loop }] }], "s");
  assert.equal(messages[0].parts[0]?.type, "reasoning");
  assert.equal(circuitBreakerRule.inspect({ sessionID: "s", directory: "/tmp", messages,
    currentTurn: messages, ruleConfig: {} }).decision, "block");
});

test("quoted numeric/hex fixtures pass even at their streaming prefixes", () => {
  for (const char of ["0", "a"]) for (const quote of ['"', "'"]) {
    for (const suffix of ["", quote, quote + ";\n"]) {
      assert.equal(detectDegenerativeLoop(`const fixture = ${quote}${char.repeat(64)}${suffix}`).detected, false);
    }
  }
});

test("long periodic sentences and astral Unicode cycles are detected", () => {
  for (const unit of [
    "I need to check the implementation before deciding what to change. ",
    "この実装を変更する前に、処理の流れとテストの結果をもう一度確認する必要があります。",
    "𠀀𠀁𠀂",
  ]) assert.equal(detectDegenerativeLoop(unit.repeat(100)).detected, true, unit);
});

test("V2 lifecycle events invalidate a detection while its project lookup is pending", async t => {
  const directory = fixture(t);
  let release, lookupStarted;
  const started = new Promise(resolve => { lookupStarted = resolve; });
  const lookup = new Promise(resolve => { release = resolve; });
  let interruptCalls = 0, wake;
  const queue = [];
  const cleanup = await Guardian.setup({ location: { directory }, session: {
    async get() { lookupStarted(); await lookup; return { location: { directory } }; },
    async context() { return []; }, async synthetic() {}, async interrupt() { interruptCalls++; },
  }, event: { subscribe({ signal }) { return (async function* () {
    signal.addEventListener("abort", () => wake?.(), { once: true });
    while (!signal.aborted) {
      if (!queue.length) await new Promise(resolve => { wake = resolve; });
      const item = queue.shift(); if (item) yield item;
    }
  })(); } } });
  t.after(cleanup);
  queue.push({ type: "session.text.delta", data: { sessionID: "s", assistantMessageID: "old", ordinal: 0, delta: loop } }); wake?.();
  await started;
  queue.push({ type: "session.execution.succeeded", data: { sessionID: "s" } },
    { type: "session.text.delta", data: { sessionID: "s", assistantMessageID: "new", ordinal: 0, delta: "New response without repetition." } }); wake?.();
  await new Promise(resolve => setImmediate(resolve));
  release(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(interruptCalls, 0, "the stop belongs to the completed old response");
});

test("V2 stop requests explicitly disable host resumption", async t => {
  let input;
  const h = await v2(t, "error", async value => { input = value; });
  await h.delta(loop);
  assert.deepEqual(input, { sessionID: "s", resume: false });
});

test("V2 ignores completed parts and session deletion resets watcher ownership", async t => {
  const h = await v2(t);
  await h.send({ type: "session.reasoning.ended", data: { sessionID: "s", assistantMessageID: "a", ordinal: 0 } });
  await h.delta(loop, "reasoning");
  assert.equal(h.calls, 0);
  await h.delta(loop); assert.equal(h.calls, 1);
  await h.send({ type: "session.deleted", data: { sessionID: "s" } });
  await h.delta(loop); assert.equal(h.calls, 2);
});
