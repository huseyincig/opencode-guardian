import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian from "../dist/index.js";

function host(t, onHook) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v2-hook-lifecycle-"));
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"),
    JSON.stringify({
      enabled: true,
      preflight: { enabled: false },
      secrets: { enabled: false },
    }));
  const original = process.env.OPENCODE_GUARDIAN_STATE_DIR;
  process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
  t.after(() => {
    if (original === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    else process.env.OPENCODE_GUARDIAN_STATE_DIR = original;
    fs.rmSync(directory, { recursive: true, force: true });
  });
  return {
    location: { directory },
    event: { subscribe({ signal }) { return (async function* () {
      await new Promise((resolve) => {
        if (signal.aborted) resolve();
        else signal.addEventListener("abort", resolve, { once: true });
      });
    })(); } },
    session: {
      async context() { return []; },
      async synthetic() {},
      hook: onHook,
    },
  };
}

test("V2 task hooks dispose an earlier registration when a later hook fails", async (t) => {
  let disposed = 0;
  const ctx = host(t, async (kind) => {
    if (kind === "prompt") return { dispose() { disposed++; } };
    throw new Error("context hook not supported");
  });
  const prior = console.error;
  console.error = (...args) => { void args; };
  let cleanup;
  try { cleanup = await Guardian.setup(ctx); } finally { console.error = prior; }
  assert.equal(disposed, 1, "orphan prompt hook must be disposed immediately");
  assert.equal(typeof cleanup, "function", "idle inspection remains available");
  await cleanup();
  assert.equal(disposed, 1, "no double-disposal");
});

test("V2 task hook without a disposer never poisons plugin shutdown", async (t) => {
  const ctx = host(t, async () => undefined);
  const prior = console.error;
  console.error = (...args) => { void args; };
  let cleanup;
  try { cleanup = await Guardian.setup(ctx); } finally { console.error = prior; }
  assert.equal(typeof cleanup, "function");
  await assert.doesNotReject(cleanup());
});
