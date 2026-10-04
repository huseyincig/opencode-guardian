import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, { readGuardianStatus } from "../dist/index.js";

async function eventually(check, limit = 1500) {
  const until = Date.now() + limit;
  while (!check()) {
    if (Date.now() > until) assert.fail("V2 event stream did not reach the expected state");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function fixture(t, subscribe) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v2-event-"));
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({ enabled: true }));
  const original = process.env.OPENCODE_GUARDIAN_STATE_DIR;
  process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
  t.after(() => {
    if (original === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    else process.env.OPENCODE_GUARDIAN_STATE_DIR = original;
    fs.rmSync(directory, { recursive: true, force: true });
  });
  return {
    location: { directory },
    event: { subscribe },
    session: {
      async context() { return []; },
      async synthetic() {},
    },
  };
}

test("V2 idle inspection resubscribes after a transient stream failure", async (t) => {
  let subscriptions = 0;
  let inspected = 0;
  const host = fixture(t, ({ signal }) => {
    subscriptions++;
    if (subscriptions === 1) return (async function* () { throw new Error("transient stream"); })();
    return (async function* () {
      yield { type: "session.idle", data: { sessionID: "recovered-session" } };
      await new Promise((resolve) => {
        if (signal.aborted) resolve();
        else signal.addEventListener("abort", resolve, { once: true });
      });
    })();
  });
  host.session.context = async () => { inspected++; return []; };
  const original = console.error;
  const errors = [];
  console.error = (message) => errors.push(String(message));
  let cleanup;
  try {
    cleanup = await Guardian.setup(host);
    await eventually(() => inspected === 1);
    assert.equal(subscriptions, 2);
    assert.equal(readGuardianStatus().errors, 1);
    assert.deepEqual(errors, [], "stream exceptions must not corrupt the interactive TUI");
  } finally {
    await cleanup?.();
    console.error = original;
  }
});

test("V2 finite event streams report and bound failed resubscriptions", async (t) => {
  let subscriptions = 0;
  const host = fixture(t, () => {
    subscriptions++;
    return (async function* () {})();
  });
  const original = console.error;
  const errors = [];
  console.error = (message) => errors.push(String(message));
  let cleanup;
  try {
    cleanup = await Guardian.setup(host);
    await eventually(() => readGuardianStatus().errors === 3, 1700);
    assert.deepEqual(errors, [], "stream errors must be recorded without terminal output");
    assert.equal(subscriptions, 3);
    assert.equal(readGuardianStatus().errors, 3);
  } finally {
    await cleanup?.();
    console.error = original;
  }
});

test("V2 cleanup cancels pending event-stream reconnect", async (t) => {
  let subscriptions = 0;
  const host = fixture(t, () => {
    subscriptions++;
    return (async function* () {})();
  });
  const original = console.error;
  console.error = () => {};
  let cleanup;
  try {
    cleanup = await Guardian.setup(host);
    await eventually(() => readGuardianStatus().errors === 1);
    await cleanup();
    await new Promise((resolve) => setTimeout(resolve, 260));
    assert.equal(subscriptions, 1);
  } finally {
    await cleanup?.();
    console.error = original;
  }
});
