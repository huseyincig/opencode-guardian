import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, { createV1TurnWatcher } from "../dist/index.js";

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function eventually(predicate, timeoutMs = 1800) {
  const until = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= until) assert.fail("V1 completion was not observed in time");
    await wait(5);
  }
}
const messages = (complete = false) => [
  { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Run all tests" }] },
  { info: { id: "a1", role: "assistant",
    time: complete ? { completed: 123456 } : { created: 123400 } },
    parts: [{ type: "text", text: "Tests passed." }] },
];

test("V1 watcher only inspects completed assistant turns after two stable idle checks", async () => {
  let state = "busy";
  let complete = false;
  let inspected = 0;
  const watcher = createV1TurnWatcher({
    intervalMs: 8, maxPolls: 30,
    async status() { return state; },
    async messages() { return messages(complete); },
    async onIdle() { inspected++; },
    onError(_id, error) { assert.fail(String(error)); },
  });
  try {
    watcher.watch("s1");
    await wait(30);
    assert.equal(inspected, 0, "busy sessions must never be inspected");
    state = "idle";
    await wait(30);
    assert.equal(inspected, 0, "an unfinished response is not turn completion");
    complete = true;
    await eventually(() => inspected === 1);
    await wait(25);
    assert.equal(inspected, 1, "a single turn is inspected only once");
  } finally { watcher.stopAll(); }
});

test("V1 missing active-status entry means idle only after a completed response", async () => {
  let inspected = 0;
  const watcher = createV1TurnWatcher({
    intervalMs: 5, maxPolls: 25,
    async status() { return undefined; },
    async messages() { return messages(true); },
    async onIdle() { inspected++; },
    onError(_id, error) { assert.fail(String(error)); },
  });
  try {
    watcher.watch("s2");
    await eventually(() => inspected === 1);
  } finally { watcher.stopAll(); }
});

test("V1 watcher cancellation prevents stale native-event and teardown inspections", async () => {
  let inspected = 0;
  const watcher = createV1TurnWatcher({
    intervalMs: 10, maxPolls: 50,
    async status() { return "idle"; },
    async messages() { return messages(true); },
    async onIdle() { inspected++; },
    onError(_id, error) { assert.fail(String(error)); },
  });
  watcher.watch("deleted");
  watcher.stop("deleted");
  watcher.watch("shutdown");
  watcher.stopAll();
  await wait(40);
  assert.equal(inspected, 0);
});

test("V1 repeated SDK failures report a visible error without an infinite loop", async () => {
  let calls = 0;
  let errors = 0;
  const watcher = createV1TurnWatcher({
    intervalMs: 4, maxPolls: 100,
    async status() { calls++; throw new Error("status unavailable"); },
    async messages() { assert.fail("not reachable"); },
    async onIdle() { assert.fail("not reachable"); },
    onError(_id, error) { errors++; assert.match(String(error), /status unavailable/); },
  });
  try {
    watcher.watch("bad");
    await eventually(() => errors === 1);
    await wait(25);
    assert.equal(calls, 3);
  } finally { watcher.stopAll(); }
});

test("V1 server fallback inspects a completed turn when host drops session.idle", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v1-host-fallback-"));
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"),
    JSON.stringify({ enabled: true, rules: {
      "discipline/no-apology": "off", "quality/no-shortcuts": "off",
    } }));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let statusCalls = 0;
  let messagesCalls = 0;
  let remediation = 0;
  const client = { session: {
    async status() { statusCalls++; return { data: {} }; },
    async messages() {
      messagesCalls++;
      return { data: [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Implement fully and run tests." }] },
        { info: { id: "a1", role: "assistant", time: { completed: 123456 } },
          parts: [{ type: "text", text: "The test failure is unrelated to this change." }] },
      ] };
    },
    async promptAsync() { remediation++; },
  } };
  const hooks = await Guardian.server({ directory, client });
  try {
    await hooks["chat.message"]({ sessionID: "lost-idle", messageID: "u1" }, {
      parts: [{ type: "text", text: "Implement fully and run tests." }],
    });
    await eventually(() => remediation === 1, 2700);
    assert.ok(statusCalls >= 2);
    assert.ok(messagesCalls >= 2);
    assert.equal(remediation, 1, "the fallback must send exactly one remediation");
  } finally { await hooks.dispose?.(); }
});

test("V1 native session.idle cancels its fallback and avoids duplicate remediation", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v1-native-idle-"));
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"), '{"enabled":true}');
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let statusCalls = 0;
  let remediation = 0;
  const client = { session: {
    async status() { statusCalls++; return { data: {} }; },
    async messages() { return { data: [
      { info: { id: "u1", role: "user" },
        parts: [{ type: "text", text: "Complete the requested task." }] },
      { info: { id: "a1", role: "assistant", time: { completed: 123456 } },
        parts: [{ type: "text", text: "The test failure is unrelated to this change." }] },
    ] }; },
    async promptAsync() { remediation++; },
  } };
  const hooks = await Guardian.server({ directory, client });
  try {
    await hooks["chat.message"]({ sessionID: "native-idle", messageID: "u1" }, {
      parts: [{ type: "text", text: "Complete the requested task." }],
    });
    await hooks.event({ event: {
      type: "session.idle", properties: { sessionID: "native-idle" },
    } });
    await wait(1600);
    assert.equal(remediation, 1);
    assert.equal(statusCalls, 0, "native idle must cancel the pending probe");
  } finally { await hooks.dispose?.(); }
});

test("V1 long-running busy and retry turns do not consume the idle completion budget", async () => {
  let state = "busy";
  let activePolls = 0;
  let inspected = 0;
  const errors = [];
  const watcher = createV1TurnWatcher({
    intervalMs: 5, maxPolls: 2, maxBusyPolls: 25,
    async status() {
      if (state === "busy" || state === "retry") activePolls++;
      return state;
    },
    async messages() { return messages(true); },
    async onIdle() { inspected++; },
    onError(_id, error) { errors.push(error); },
  });
  try {
    watcher.watch("long-running");
    await eventually(() => activePolls >= 5);
    state = "retry";
    await eventually(() => activePolls >= 8);
    state = "idle";
    await eventually(() => inspected === 1);
    assert.equal(errors.length, 0);
    assert.equal(inspected, 1);
  } finally { watcher.stopAll(); }
});

test("V1 orphaned busy probes end quietly at their independent safety limit", async () => {
  let polls = 0;
  let errors = 0;
  const watcher = createV1TurnWatcher({
    intervalMs: 4, maxPolls: 2, maxBusyPolls: 4,
    async status() { polls++; return "busy"; },
    async messages() { assert.fail("busy turns must not fetch messages"); },
    async onIdle() { assert.fail("busy turns must not be inspected"); },
    onError() { errors++; },
  });
  try {
    watcher.watch("orphan");
    await eventually(() => polls === 4);
    await wait(35);
    assert.equal(polls, 4);
    assert.equal(errors, 0, "normal orphan cleanup must not report a completion error");
  } finally { watcher.stopAll(); }
});

test("V1 idle sessions without a completed response have a bounded error callback", async () => {
  let statuses = 0;
  let messagesRead = 0;
  const errors = [];
  const watcher = createV1TurnWatcher({
    intervalMs: 4, maxPolls: 3, maxBusyPolls: 20,
    async status() { statuses++; return "idle"; },
    async messages() { messagesRead++; return messages(false); },
    async onIdle() { assert.fail("incomplete messages must never be inspected"); },
    onError(_id, error) { errors.push(String(error)); },
  });
  try {
    watcher.watch("incomplete");
    await eventually(() => errors.length === 1);
    await wait(25);
    assert.equal(statuses, 4);
    assert.equal(messagesRead, 3);
    assert.match(errors[0], /idle polling limit/);
  } finally { watcher.stopAll(); }
});

test("V1 watcher reports an inspection callback failure exactly once", async () => {
  const errors = [];
  let called = 0;
  const watcher = createV1TurnWatcher({
    intervalMs: 4, maxPolls: 5,
    async status() { return "idle"; },
    async messages() { return messages(true); },
    async onIdle() { called++; throw new Error("inspection callback rejected"); },
    onError(_id, error) { errors.push(String(error)); },
  });
  try {
    watcher.watch("callback-rejected");
    await eventually(() => errors.length === 1);
    await wait(25);
    assert.equal(called, 1);
    assert.match(errors[0], /inspection callback rejected/);
  } finally { watcher.stopAll(); }
});

test("V1 SDK polling failures are recorded without writing a stack over the TUI", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v1-quiet-errors-"));
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"), '{"enabled":true}');
  let statusCalls = 0;
  let consoleCalls = 0;
  const originalError = console.error;
  const client = { session: {
    async status() { statusCalls++; return { error: { message: "SDK status unavailable" } }; },
  } };
  const hooks = await Guardian.server({ directory, client });
  t.after(async () => {
    await hooks.dispose?.();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  try {
    console.error = () => { consoleCalls++; };
    await hooks["chat.message"]({ sessionID: "sdk-error", messageID: "u1" }, {
      parts: [{ type: "text", text: "Complete the current task." }],
    });
    await eventually(() => statusCalls === 3, 3600);
    await eventually(() => fs.readFileSync(
      path.join(directory, ".opencode", "guardian-events.jsonl"), "utf8"
    ).includes('"rules":["v1-completion-probe"]'), 500);
    assert.equal(consoleCalls, 0, "Guardian must not corrupt the host prompt");
    assert.equal(statusCalls, 3);
  } finally {
    console.error = originalError;
  }
});
