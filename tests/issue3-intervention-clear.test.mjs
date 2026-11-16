import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, {
  clearToastListeners,
  GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD,
  GUARDIAN_INTERVENTION_RPC_DEFINITION,
  GUARDIAN_INTERVENTION_RPC_METHOD,
  registerToastClearListener,
  registerToastListener,
} from "../dist/index.js";

function createAsyncEventStream() {
  const queue = [];
  let waiting = null;
  let closed = false;
  return {
    push(event) {
      if (closed) return;
      if (waiting) {
        const resolve = waiting;
        waiting = null;
        resolve({ value: event, done: false });
      } else {
        queue.push(event);
      }
    },
    close() {
      closed = true;
      if (waiting) {
        const resolve = waiting;
        waiting = null;
        resolve({ value: undefined, done: true });
      }
    },
    iterable: {
      [Symbol.asyncIterator]() {
        return {
          next() {
            if (queue.length > 0) {
              return Promise.resolve({ value: queue.shift(), done: false });
            }
            if (closed) {
              return Promise.resolve({ value: undefined, done: true });
            }
            return new Promise((resolve) => {
              waiting = resolve;
            });
          },
        };
      },
    },
  };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test("Issue #3 (V2): stream-interrupt-requested banner clears after subsequent clean turn", async (t) => {
  clearToastListeners();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-issue3-v2-"));
  t.after(() => {
    clearToastListeners();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const stream = createAsyncEventStream();
  let rpcHandlers = null;
  let promptHook = null;
  let sessionMessages = [];

  const receivedToasts = [];
  const clearedScopes = [];
  registerToastListener((payload, scope) => {
    receivedToasts.push({ payload, scope });
  }, { directory: dir });
  registerToastClearListener((scope) => {
    clearedScopes.push(scope);
  }, { directory: dir });

  const dispose = await Guardian.setup({
    location: { directory: dir },
    options: { enabled: true },
    event: {
      subscribe: () => stream.iterable,
    },
    rpc: {
      register: async (def, handlers) => {
        if (def.id === GUARDIAN_INTERVENTION_RPC_DEFINITION.id) {
          rpcHandlers = handlers;
        }
        return { dispose() {} };
      },
    },
    session: {
      get: async ({ sessionID }) => ({ id: sessionID, location: { directory: dir } }),
      context: async () => sessionMessages,
      synthetic: async () => {},
      interrupt: async () => true,
      hook: async (name, cb) => {
        if (name === "prompt") promptHook = cb;
        return { dispose() {} };
      },
    },
    tool: {
      hook: async () => ({ dispose() {} }),
    },
  });
  t.after(async () => {
    stream.close();
    await dispose?.();
  });

  const sessionID = "ses-issue3-v2";
  // Turn 1: prompt + repetitive stream delta
  await promptHook({ sessionID, messageID: "u1", prompt: { text: "Write a helper" }, metadata: {} });
  stream.push({
    type: "session.text.delta",
    data: {
      sessionID,
      assistantMessageID: "a1",
      ordinal: 0,
      delta: "repeating phrase ".repeat(12),
    },
  });
  await sleep(60);

  assert.equal(receivedToasts.length, 1);
  assert.equal(receivedToasts[0].payload.variant, "warning");
  const afterInterrupt = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID });
  assert.equal(afterInterrupt.active, true);

  // Turn 1 goes idle cleanly (short interrupted output) -> banner must remain visible on Turn 1
  sessionMessages = [
    { id: "u1", type: "user", text: "Write a helper" },
    { id: "a1", type: "assistant", content: [{ type: "text", text: "Done." }] },
  ];
  stream.push({ type: "session.idle", data: { sessionID } });
  await sleep(60);

  const afterTurn1Idle = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID });
  assert.equal(afterTurn1Idle.active, true, "banner should remain visible right after interrupted turn idle");
  assert.equal(clearedScopes.length, 0);

  // Turn 2: new human prompt + clean assistant response -> banner must clear
  await promptHook({ sessionID, messageID: "u2", prompt: { text: "Continue cleanly" }, metadata: {} });
  sessionMessages = [
    ...sessionMessages,
    { id: "u2", type: "user", text: "Continue cleanly" },
    { id: "a2", type: "assistant", content: [{ type: "text", text: "Here is the clean answer." }] },
  ];
  stream.push({ type: "session.idle", data: { sessionID } });
  await sleep(60);

  const afterTurn2Idle = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID });
  assert.equal(afterTurn2Idle.active, false, "banner must clear after subsequent clean turn");
  assert.equal(clearedScopes.length, 1);
  assert.equal(clearedScopes[0].sessionID, sessionID);
});

test("Issue #3 (V2): RPC clear method clears both session-scoped and directory-wide interventions", async (t) => {
  clearToastListeners();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-issue3-rpc-"));
  t.after(() => {
    clearToastListeners();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const stream = createAsyncEventStream();
  let rpcHandlers = null;
  let toolBeforeHook = null;

  const clearedScopes = [];
  registerToastClearListener((scope) => {
    clearedScopes.push(scope);
  }, { directory: dir });

  const dispose = await Guardian.setup({
    location: { directory: dir },
    options: { enabled: true, preflight: { enabled: true } },
    event: { subscribe: () => stream.iterable },
    rpc: {
      register: async (_def, handlers) => {
        rpcHandlers = handlers;
        return { dispose() {} };
      },
    },
    session: {
      get: async ({ sessionID }) => ({ id: sessionID, location: { directory: dir } }),
      context: async () => [],
      synthetic: async () => {},
      hook: async () => ({ dispose() {} }),
    },
    tool: {
      hook: async (name, cb) => {
        if (name === "execute.before") toolBeforeHook = cb;
        return { dispose() {} };
      },
    },
  });
  t.after(async () => {
    stream.close();
    await dispose?.();
  });

  const sessionID = "ses-rpc-clear";
  await assert.rejects(
    () => toolBeforeHook({ id: "c1", sessionID, tool: "bash", input: { command: "rm -rf /" } }),
    /Tool execution rejected/
  );

  const activeSnap = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID });
  assert.equal(activeSnap.active, true);

  const res = await rpcHandlers[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD]({ sessionID });
  assert.deepEqual(res, { cleared: true });

  const clearedSnap = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID });
  assert.equal(clearedSnap.active, false);
  assert.equal(clearedScopes.some((s) => s.sessionID === sessionID), true);

  // Trigger again, then test directory-wide clear (no sessionID, e.g. /guardian-reset from home)
  await assert.rejects(
    () => toolBeforeHook({ id: "c2", sessionID, tool: "bash", input: { command: "rm -rf /" } }),
    /Tool execution rejected/
  );
  assert.equal((await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID })).active, true);

  const globalRes = await rpcHandlers[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD]({});
  assert.deepEqual(globalRes, { cleared: true });
  assert.equal((await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID })).active, false);
});

test("Issue #3 (V2): session.moved dispatches toast clear for same-process listeners", async (t) => {
  clearToastListeners();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-issue3-move-"));
  t.after(() => {
    clearToastListeners();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const stream = createAsyncEventStream();
  let toolBeforeHook = null;
  const clearedScopes = [];
  registerToastClearListener((scope) => {
    clearedScopes.push(scope);
  });

  const dispose = await Guardian.setup({
    location: { directory: dir },
    options: { enabled: true, preflight: { enabled: true } },
    event: { subscribe: () => stream.iterable },
    session: {
      get: async ({ sessionID }) => ({ id: sessionID, location: { directory: dir } }),
      context: async () => [],
      synthetic: async () => {},
      hook: async () => ({ dispose() {} }),
    },
    tool: {
      hook: async (name, cb) => {
        if (name === "execute.before") toolBeforeHook = cb;
        return { dispose() {} };
      },
    },
  });
  t.after(async () => {
    stream.close();
    await dispose?.();
  });

  const sessionID = "ses-move";
  await assert.rejects(
    () => toolBeforeHook({ id: "c1", sessionID, tool: "bash", input: { command: "rm -rf /" } }),
    /Tool execution rejected/
  );
  stream.push({ type: "session.moved", data: { sessionID, location: { directory: dir } } });
  await sleep(50);

  assert.equal(clearedScopes.some((s) => s.sessionID === sessionID), true);
});
