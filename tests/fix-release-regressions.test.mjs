import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, { readGuardianStatus, recordGuardianEvent } from "../dist/index.js";
import cleanupMergedBranches from "../scripts/cleanup-merged-branches.cjs";

const name = "huseyincig/opencode-guardian";
const sha = (letter) => letter.repeat(40);
const pr = (ref, tip, options = {}) => ({
  merged_at: options.merged === false ? null : "2026-10-04T00:00:00Z",
  head: { ref, sha: tip, repo: { full_name: options.fork ? "foreign/fork" : name } },
});

function mockGitHub({ closed = [], open = [], refs = {}, deleteError } = {}) {
  const lookedUp = [];
  const deleted = [];
  const github = {
    paginate: async (_method, args) => args.state === "open" ? open : closed,
    rest: {
      pulls: { list() {} },
      git: {
        async getRef({ ref }) {
          lookedUp.push(ref);
          if (!(ref in refs)) throw Object.assign(new Error("missing"), { status: 404 });
          if (refs[ref] instanceof Error) throw refs[ref];
          return { data: { object: { sha: refs[ref] } } };
        },
        async deleteRef({ ref }) {
          deleted.push(ref);
          if (deleteError) throw deleteError;
        },
      },
    },
  };
  return { github, lookedUp, deleted, core: { info() {} },
    context: { repo: { owner: "huseyincig", repo: "opencode-guardian" },
      payload: { repository: { default_branch: "main" } } } };
}

test("merged branch cleanup deletes only unchanged SHA and never reused, open, default or fork refs", async () => {
  const args = mockGitHub({
    closed: [
      pr("fix/merged", sha("a")),
      pr("fix/reused", sha("b")),
      pr("fix/open", sha("c")),
      pr("main", sha("d")),
      pr("fork/work", sha("e"), { fork: true }),
      pr("fix/not-merged", sha("f"), { merged: false }),
    ],
    open: [pr("fix/open", sha("c"), { merged: false })],
    refs: {
      "heads/fix/merged": sha("a"),
      "heads/fix/reused": sha("f"),
      "heads/fix/open": sha("c"),
    },
  });
  await cleanupMergedBranches(args);
  assert.deepEqual(args.deleted, ["heads/fix/merged"]);
  assert.deepEqual(args.lookedUp, ["heads/fix/merged", "heads/fix/reused"]);
});

test("merged branch cleanup does not delete if current ref cannot be verified", async () => {
  const args = mockGitHub({
    closed: [pr("fix/unknown", sha("a"))],
    refs: { "heads/fix/unknown": Object.assign(new Error("forbidden"), { status: 403 }) },
  });
  await assert.rejects(() => cleanupMergedBranches(args), /forbidden/);
  assert.deepEqual(args.deleted, []);
});

test("merged branch cleanup handles missing and protected refs without touching other branches", async () => {
  const args = mockGitHub({
    closed: [pr("fix/missing", sha("a")), pr("fix/protected", sha("b"))],
    refs: { "heads/fix/protected": sha("b") },
    deleteError: Object.assign(new Error("protected"), { status: 422 }),
  });
  await cleanupMergedBranches(args);
  assert.deepEqual(args.deleted, ["heads/fix/protected"]);
});

test("merged branch cleanup never proceeds if open PR discovery fails", async () => {
  const args = mockGitHub({ closed: [pr("fix/merged", sha("a"))], refs: { "heads/fix/merged": sha("a") } });
  args.github.paginate = async (_method, options) => {
    if (options.state === "open") throw new Error("open pull discovery unavailable");
    return [];
  };
  await assert.rejects(() => cleanupMergedBranches(args), /discovery unavailable/);
  assert.deepEqual(args.deleted, []);
});

function tempProject(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-delivery-regression-"));
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"),
    JSON.stringify({ enabled: true, updateNotice: { enabled: false } }));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function failedAssistant(completed = false) {
  return [
    { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the broken tests." }] },
    { info: { id: "a1", role: "assistant", ...(completed ? { time: { completed: 123456 } } : {}) },
      parts: [{ type: "text", text: "The test failures are unrelated to my changes." }] },
  ];
}

test("V1 rejected promptAsync response rolls back remediation and a later idle retries", async (t) => {
  const directory = tempProject(t);
  let syntheticAttempts = 0;
  let visibleCalls = 0;
  const hooks = await Guardian.server({ directory, client: { session: {
    async get({ path: requestPath }) {
      return { data: { id: requestPath.id, parentID: undefined } };
    },
    async messages() { return { data: failedAssistant() }; },
    async promptAsync(input) {
      const part = input.body?.parts?.[0];
      if (part?.synthetic === true) {
        syntheticAttempts++;
        return syntheticAttempts === 1
          ? { data: undefined, error: { message: "simulated host rejection" } }
          : { data: {}, error: undefined };
      }
      visibleCalls++;
      return { data: {}, error: undefined };
    },
  } } });
  t.after(async () => hooks.dispose?.());
  await hooks.event({ event: { type: "session.idle", properties: { sessionID: "retry" } } });
  assert.equal(syntheticAttempts, 1);
  assert.equal(visibleCalls, 0);
  assert.equal(readGuardianStatus(directory).remediations, 0);
  assert.equal(readGuardianStatus(directory).errors, 1);
  await hooks.event({ event: { type: "session.idle", properties: { sessionID: "retry" } } });
  assert.equal(syntheticAttempts, 2);
  assert.equal(visibleCalls, 1);
  assert.equal(readGuardianStatus(directory).remediations, 1);
});

test("V1 completion watcher also rejects an API error instead of recording a delivered remediation", async (t) => {
  const directory = tempProject(t);
  let attempts = 0;
  const hooks = await Guardian.server({ directory, client: { session: {
    async get({ path: requestPath }) {
      return { data: { id: requestPath.id, parentID: undefined } };
    },
    async status() { return { data: {} }; },
    async messages() { return { data: failedAssistant(true) }; },
    async promptAsync() {
      attempts++;
      return { data: undefined, error: { message: "simulated host rejection" } };
    },
  } } });
  t.after(async () => hooks.dispose?.());
  await hooks["chat.message"]({ sessionID: "watcher", messageID: "u1" },
    { parts: [{ type: "text", text: "Fix the broken tests." }] });
  const deadline = Date.now() + 3600;
  while (attempts === 0 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.equal(attempts, 1);
  assert.equal(readGuardianStatus(directory).remediations, 0);
  assert.equal(readGuardianStatus(directory).errors, 1);
});

test("V1 session fetch failures are reported without exposing raw exception in console", async (t) => {
  const directory = tempProject(t);
  const marker = "SYNTHETIC_PRIVATE_ERROR_MARKER";
  const hooks = await Guardian.server({ directory, client: { session: {
    async messages() { throw new Error(marker); },
  } } });
  t.after(async () => hooks.dispose?.());
  const old = console.error;
  const captured = [];
  console.error = (...args) => captured.push(args);
  try {
    await hooks.event({ event: { type: "session.idle", properties: { sessionID: "failed-fetch" } } });
  } finally {
    console.error = old;
  }
  const contents = fs.readFileSync(path.join(directory, ".opencode", "guardian-events.jsonl"), "utf8");
  assert.equal(captured.length, 0);
  assert.equal(contents.includes(marker), false);
  assert.equal(readGuardianStatus(directory).errors, 1);
});

test("status reports the newest event instead of mistaking past blocked counters for current state", (t) => {
  const directory = tempProject(t);
  recordGuardianEvent({ kind: "runtime-started", runtime: "v1", preflight: "active" }, directory);
  recordGuardianEvent({ kind: "preflight-blocked", rules: ["destructive-command"] }, directory);
  recordGuardianEvent({ kind: "post-remediation", rules: ["discipline/no-evasion"] }, directory);
  recordGuardianEvent({ kind: "preflight-allowed", tool: "bash" }, directory);
  const status = readGuardianStatus(directory);
  assert.equal(status.blocked, 1);
  assert.equal(status.remediations, 1);
  assert.equal(status.lastKind, "preflight-allowed");
});

test("CI cleanup is restricted to main and runs the independently tested safety policy", () => {
  const workflow = fs.readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
  assert.match(workflow, /github\.event_name == 'push' && github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /require\('\.\/scripts\/cleanup-merged-branches\.cjs'\)/);
  assert.match(workflow.split("cleanup-merged-branches:")[1], /uses: actions\/checkout@v5/);
});
