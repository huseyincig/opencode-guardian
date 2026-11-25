import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import Guardian from "../dist/index.js";
import {
  forgetMeshSession,
  getBlockingSessionLease,
  getLatestMeshIntervention,
} from "../dist/bridge.js";

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
            if (queue.length > 0) return Promise.resolve({ value: queue.shift(), done: false });
            if (closed) return Promise.resolve({ value: undefined, done: true });
            return new Promise((resolve) => {
              waiting = resolve;
            });
          },
        };
      },
    },
  };
}

describe("V2 pre-idle experimental.idle interception (zero-race subagent remediation)", () => {
  test("1. experimental.idle inspects and injects remediation BEFORE returning (without waiting for session.execution.succeeded)", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-preidle-1-"));
    const sessionID = "ses_preidle_worker_1";
    const stream = createAsyncEventStream();
    t.after(() => {
      stream.close();
      forgetMeshSession(sessionID);
      fs.rmSync(dir, { recursive: true, force: true });
    });

    const timeline = [];
    const synthetics = [];
    let expIdleCb = null;
    const messages = [
      { id: "u1", type: "user", text: "Fix the failing unit test." },
      {
        id: "a1",
        type: "assistant",
        agent: "coder",
        content: [
          { type: "text", text: "The test failure is unrelated to my changes and pre-existing." },
        ],
      },
    ];

    const dispose = await Guardian.setup({
      location: { directory: dir },
      options: {
        enabled: true,
        secrets: { enabled: false },
        rules: { "discipline/no-evasion": "error" },
      },
      event: { subscribe: () => stream.iterable },
      session: {
        get: async ({ sessionID: sid }) => ({
          id: sid,
          parentID: "ses_manager_parent",
          agent: "coder",
          location: { directory: dir },
        }),
        context: async () => messages,
        synthetic: async (req) => {
          timeline.push("synthetic-injected");
          synthetics.push(req);
          return { id: `syn-${synthetics.length}` };
        },
        hook: async (name, cb) => {
          if (name === "experimental.idle") expIdleCb = cb;
          return { dispose() {} };
        },
      },
      agent: {
        list: async () => [
          {
            id: "coder",
            name: "coder",
            permissions: [
              { resource: "*", action: "edit", effect: "allow" },
              { resource: "*", action: "shell", effect: "allow" },
            ],
          },
        ],
      },
      tool: { hook: async () => ({ dispose() {} }) },
      shell: { hook: async () => ({ dispose() {} }) },
      rpc: { register: async () => ({ dispose() {} }) },
    });
    t.after(async () => {
      if (typeof dispose === "function") await dispose();
    });

    assert.equal(typeof expIdleCb, "function", "experimental.idle hook must be registered");

    // Host invokes experimental.idle BEFORE transitioning the child to idle or delivering <background-result>.
    // Notice NO session.execution.succeeded or session.idle event is pushed!
    await expIdleCb({ sessionID, background: [] });
    timeline.push("experimental-idle-resolved");

    assert.equal(
      synthetics.length,
      1,
      "Guardian must inject remediation synthetic INSIDE experimental.idle before the session goes idle"
    );
    assert.deepEqual(
      timeline,
      ["synthetic-injected", "experimental-idle-resolved"],
      "synthetic remediation must be admitted before experimental.idle resolves so OpenCode continues in the same execution"
    );
    assert.equal(synthetics[0].resume, true);
    assert.equal(getLatestMeshIntervention(sessionID)?.kind, "post-remediation");
  });

  test("2. same-execution remediation passes on second experimental.idle, clears lease/mesh, and deduplicates subsequent session.execution.succeeded", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-preidle-2-"));
    const sessionID = "ses_preidle_worker_2";
    const stream = createAsyncEventStream();
    t.after(() => {
      stream.close();
      forgetMeshSession(sessionID);
      fs.rmSync(dir, { recursive: true, force: true });
    });

    let contextFetches = 0;
    const synthetics = [];
    let expIdleCb = null;
    let currentMessages = [
      { id: "u1", type: "user", text: "Implement compute()." },
      {
        id: "a1",
        type: "assistant",
        agent: "coder",
        content: [
          {
            type: "tool",
            id: "c1",
            name: "write",
            state: {
              status: "completed",
              input: { filePath: path.join(dir, "src", "calc.ts"), content: "export function compute() {}\n" },
              output: "ok",
            },
          },
          { type: "text", text: "Added compute." },
        ],
      },
    ];

    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "calc.ts"), "export function compute() {}\n");

    const dispose = await Guardian.setup({
      location: { directory: dir },
      options: {
        enabled: true,
        secrets: { enabled: false },
        rules: {
          "integrity/no-stubs": "error",
          "integrity/no-unverified-claims": "off",
          "task/completion-gate": "off",
        },
      },
      event: { subscribe: () => stream.iterable },
      session: {
        get: async ({ sessionID: sid }) => ({
          id: sid,
          parentID: "ses_manager_parent",
          agent: "coder",
          location: { directory: dir },
        }),
        context: async () => {
          contextFetches += 1;
          return currentMessages;
        },
        synthetic: async (req) => {
          synthetics.push(req);
          return { id: `syn-${synthetics.length}` };
        },
        hook: async (name, cb) => {
          if (name === "experimental.idle") expIdleCb = cb;
          return { dispose() {} };
        },
      },
      agent: {
        list: async () => [
          {
            id: "coder",
            name: "coder",
            permissions: [
              { resource: "*", action: "edit", effect: "allow" },
              { resource: "*", action: "shell", effect: "allow" },
            ],
          },
        ],
      },
      tool: { hook: async () => ({ dispose() {} }) },
      shell: { hook: async () => ({ dispose() {} }) },
      rpc: { register: async () => ({ dispose() {} }) },
    });
    t.after(async () => {
      if (typeof dispose === "function") await dispose();
    });

    // Round 1: stub detected inside experimental.idle -> remediation injected before idle!
    await expIdleCb({ sessionID, background: [] });
    assert.equal(synthetics.length, 1);

    // Round 2 (same execution): worker fixes src/calc.ts cleanly
    fs.writeFileSync(path.join(dir, "src", "calc.ts"), "export function compute(x: number) { return x * 2; }\n");
    currentMessages = [
      ...currentMessages,
      { id: "syn1", type: "synthetic", text: synthetics[0].text, metadata: synthetics[0].metadata },
      {
        id: "a2",
        type: "assistant",
        agent: "coder",
        content: [
          {
            type: "tool",
            id: "c2",
            name: "write",
            state: {
              status: "completed",
              input: {
                filePath: path.join(dir, "src", "calc.ts"),
                content: "export function compute(x: number) { return x * 2; }\n",
              },
              output: "ok",
            },
          },
          { type: "text", text: "Implemented compute(x) properly." },
        ],
      },
    ];

    await expIdleCb({ sessionID, background: [] });
    assert.equal(synthetics.length, 1, "clean remediated turn must not send another remediation");
    assert.equal(getLatestMeshIntervention(sessionID), undefined, "mesh intervention must clear after verified remediation");
    assert.equal(
      getBlockingSessionLease(sessionID, "active_remediation"),
      undefined,
      "active_remediation lease must release after clean pre-idle verification"
    );

    // Host now finishes execution and emits session.execution.succeeded -> must NOT re-inspect or re-remediate
    const fetchesBeforeEvent = contextFetches;
    stream.push({
      type: "session.execution.succeeded",
      location: { directory: dir },
      data: { sessionID },
    });
    await new Promise((r) => setTimeout(r, 80));
    assert.equal(synthetics.length, 1, "post-idle event must not duplicate remediation");
    assert.ok(contextFetches <= fetchesBeforeEvent + 1, "post-idle event must short-circuit via inspected message dedup");
  });

  test("3. experimental.idle with active own background job defers without fetching context or remediating", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-preidle-3-"));
    const sessionID = "ses_preidle_bg_3";
    const stream = createAsyncEventStream();
    t.after(() => {
      stream.close();
      forgetMeshSession(sessionID);
      fs.rmSync(dir, { recursive: true, force: true });
    });

    let contextFetches = 0;
    const synthetics = [];
    let expIdleCb = null;

    const dispose = await Guardian.setup({
      location: { directory: dir },
      options: {
        enabled: true,
        secrets: { enabled: false },
        rules: { "discipline/no-apology": "error" },
      },
      event: { subscribe: () => stream.iterable },
      session: {
        get: async ({ sessionID: sid }) => ({ id: sid, location: { directory: dir } }),
        context: async () => {
          contextFetches += 1;
          return [
            { id: "u1", type: "user", text: "Fix it." },
            { id: "a1", type: "assistant", content: [{ type: "text", text: "I deeply apologize." }] },
          ];
        },
        synthetic: async (req) => {
          synthetics.push(req);
          return { id: "syn-1" };
        },
        hook: async (name, cb) => {
          if (name === "experimental.idle") expIdleCb = cb;
          return { dispose() {} };
        },
      },
      tool: { hook: async () => ({ dispose() {} }) },
      shell: { hook: async () => ({ dispose() {} }) },
      rpc: { register: async () => ({ dispose() {} }) },
    });
    t.after(async () => {
      if (typeof dispose === "function") await dispose();
    });

    await expIdleCb({
      sessionID,
      background: [{ kind: "shell", sessionID, shellID: "sh_1", command: "npm test" }],
    });
    assert.equal(contextFetches, 0, "must not inspect when own background job is running");
    assert.equal(synthetics.length, 0);
  });

  test("4. read-only subagent records post-warning mesh intervention inside experimental.idle without injecting self-remediation", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-preidle-4-"));
    const sessionID = "ses_preidle_readonly_4";
    const stream = createAsyncEventStream();
    t.after(() => {
      stream.close();
      forgetMeshSession(sessionID);
      fs.rmSync(dir, { recursive: true, force: true });
    });

    const synthetics = [];
    let expIdleCb = null;

    const dispose = await Guardian.setup({
      location: { directory: dir },
      options: {
        enabled: true,
        secrets: { enabled: false },
        rules: { "discipline/no-evasion": "error" },
      },
      event: { subscribe: () => stream.iterable },
      session: {
        get: async ({ sessionID: sid }) => ({
          id: sid,
          parentID: "ses_manager_parent",
          agent: "explorer",
          location: { directory: dir },
        }),
        context: async () => [
          { id: "u1", type: "user", text: "Inspect failures." },
          {
            id: "a1",
            type: "assistant",
            agent: "explorer",
            content: [{ type: "text", text: "The test failure is unrelated to this change and pre-existing." }],
          },
        ],
        synthetic: async (req) => {
          synthetics.push(req);
          return { id: "syn-1" };
        },
        hook: async (name, cb) => {
          if (name === "experimental.idle") expIdleCb = cb;
          return { dispose() {} };
        },
      },
      agent: {
        list: async () => [
          {
            id: "explorer",
            name: "explorer",
            permissions: [
              { resource: "*", action: "edit", effect: "deny" },
              { resource: "*", action: "shell", effect: "deny" },
            ],
          },
        ],
      },
      tool: { hook: async () => ({ dispose() {} }) },
      shell: { hook: async () => ({ dispose() {} }) },
      rpc: { register: async () => ({ dispose() {} }) },
    });
    t.after(async () => {
      if (typeof dispose === "function") await dispose();
    });

    await expIdleCb({ sessionID, background: [] });

    assert.equal(synthetics.length, 0, "read-only subagent must never receive self-remediation synthetic");
    const meshIntervention = getLatestMeshIntervention(sessionID);
    assert.ok(meshIntervention && meshIntervention.active, "read-only blocking finding must publish to mesh before idle resolves");
    assert.equal(meshIntervention.kind, "post-warning");
    assert.ok(meshIntervention.ruleIds.includes("discipline/no-evasion"));
    assert.equal(getBlockingSessionLease(sessionID, "active_remediation"), undefined, "pre-inspection lease must release");
  });
});
