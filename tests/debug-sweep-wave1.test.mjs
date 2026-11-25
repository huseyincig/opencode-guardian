import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import Guardian, { GuardEngine, extractTaskContract, resolveEffectiveConfig } from "../dist/index.js";
import { collectTurnEvidence, isDestructiveCommand, VerificationSnapshotStore } from "../dist/evidence.js";
import { evaluatePreflight } from "../dist/preflight.js";
import { deniedVerification } from "../dist/locale-intents.js";
import { latestHumanInstruction } from "../dist/task-constraints.js";
import { extractLikelyShellMutation } from "../dist/tool-input.js";
import { maskCodeLiterals } from "../dist/code-context.js";
import {
  forgetMeshSession,
  getBlockingSessionLease,
  getLatestMeshIntervention,
  registerMeshStateRpc,
  resetMeshStateForTests,
  stampMeshMetadata,
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

describe("Debug Sweep Wave 1 — Runtime, Pre-Idle, Mesh, Evidence, Shell, Contract & Engine", () => {
  test("A1: same-instance experimental.idle and eventLoop never run handleSessionIdle concurrently", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-a1-"));
    const sessionID = "ses_a1_race";
    const stream = createAsyncEventStream();
    t.after(() => {
      stream.close();
      forgetMeshSession(sessionID);
      fs.rmSync(dir, { recursive: true, force: true });
    });

    let expIdleCb = null;
    let releaseContextFetch = null;
    let fetchCount = 0;
    const synthetics = [];

    const dispose = await Guardian.setup({
      location: { directory: dir },
      options: {
        enabled: true,
        remediationBudget: 1,
        secrets: { enabled: false },
        rules: { "discipline/no-apology": "error" },
      },
      event: { subscribe: () => stream.iterable },
      session: {
        get: async ({ sessionID: sid }) => ({ id: sid, location: { directory: dir } }),
        context: async () => {
          fetchCount += 1;
          if (fetchCount === 1) {
            await new Promise((r) => {
              releaseContextFetch = r;
            });
          }
          return [
            { id: "u1", type: "user", text: "Fix it." },
            { id: "a1", type: "assistant", content: [{ type: "text", text: "I deeply apologize." }] },
          ];
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
      tool: { hook: async () => ({ dispose() {} }) },
      shell: { hook: async () => ({ dispose() {} }) },
      rpc: { register: async () => ({ dispose() {} }) },
    });
    t.after(async () => {
      if (typeof dispose === "function") await dispose();
    });

    // Start experimental.idle (pauses inside session.context)
    const p1 = expIdleCb({ sessionID, background: [] });
    await new Promise((r) => setTimeout(r, 15));
    // While experimental.idle is in flight, eventLoop receives session.execution.succeeded
    stream.push({ type: "session.execution.succeeded", location: { directory: dir }, data: { sessionID } });
    await new Promise((r) => setTimeout(r, 35));
    releaseContextFetch?.();
    await p1;
    await new Promise((r) => setTimeout(r, 35));

    assert.equal(synthetics.length, 1, "must remediate exactly once");
    assert.equal(
      getLatestMeshIntervention(sessionID)?.kind,
      "post-remediation",
      "concurrent eventLoop must NOT wipe live post-remediation mesh intervention"
    );
    assert.ok(
      getBlockingSessionLease(sessionID, "orchestration_dispatch"),
      "concurrent eventLoop must NOT destroy live active_remediation lease"
    );
  });

  test("A2: session.hook('prompt') aborts in-flight experimental.idle inspection", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-a2-"));
    const sessionID = "ses_a2_prompt_abort";
    const stream = createAsyncEventStream();
    t.after(() => {
      stream.close();
      forgetMeshSession(sessionID);
      fs.rmSync(dir, { recursive: true, force: true });
    });

    let expIdleCb = null;
    let promptCb = null;
    let releaseContext = null;
    const synthetics = [];

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
          await new Promise((r) => {
            releaseContext = r;
          });
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
          if (name === "prompt") promptCb = cb;
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

    const p1 = expIdleCb({ sessionID, background: [] });
    await new Promise((r) => setTimeout(r, 15));
    // Human submits a new prompt while experimental.idle is awaiting context
    await promptCb({ sessionID, prompt: { text: "New task" } });
    releaseContext?.();
    await p1;

    assert.equal(synthetics.length, 0, "stale experimental.idle must abort and never inject remediation into new user turn");
    assert.equal(getBlockingSessionLease(sessionID, "orchestration_dispatch"), undefined);
  });

  test("A4: invalid project config in eventLoop pre-lease never crashes or kills eventLoop for healthy projects", async (t) => {
    const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-a4-root-"));
    const badProj = path.join(rootDir, "bad-proj");
    const goodProj = path.join(rootDir, "good-proj");
    fs.mkdirSync(badProj, { recursive: true });
    fs.mkdirSync(goodProj, { recursive: true });
    fs.writeFileSync(path.join(badProj, "opencode-guardian.json"), "{ invalid json !!!");
    const stream = createAsyncEventStream();
    t.after(() => {
      stream.close();
      forgetMeshSession("ses_good_a4");
      fs.rmSync(rootDir, { recursive: true, force: true });
    });

    const synthetics = [];
    const dispose = await Guardian.setup({
      location: { directory: rootDir },
      options: { enabled: true, secrets: { enabled: false }, rules: { "discipline/no-apology": "error" } },
      event: { subscribe: () => stream.iterable },
      session: {
        get: async ({ sessionID: sid }) => ({
          id: sid,
          location: { directory: sid === "ses_good_a4" ? goodProj : badProj },
        }),
        context: async () => [
          { id: "u1", type: "user", text: "Fix." },
          { id: "a1", type: "assistant", content: [{ type: "text", text: "I deeply apologize." }] },
        ],
        synthetic: async (req) => {
          synthetics.push(req);
          return { id: "syn-1" };
        },
        hook: async () => ({ dispose() {} }),
      },
      tool: { hook: async () => ({ dispose() {} }) },
      shell: { hook: async () => ({ dispose() {} }) },
      rpc: { register: async () => ({ dispose() {} }) },
    });
    t.after(async () => {
      if (typeof dispose === "function") await dispose();
    });

    // Fire 4 events for badProj -> must NOT kill eventLoop
    for (let i = 0; i < 4; i++) {
      stream.push({ type: "session.idle", location: { directory: badProj }, data: { sessionID: `ses_bad_${i}` } });
    }
    await new Promise((r) => setTimeout(r, 40));
    stream.push({ type: "session.idle", location: { directory: goodProj }, data: { sessionID: "ses_good_a4" } });
    for (let i = 0; i < 40 && synthetics.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 15));
    }
    assert.equal(synthetics.length, 1, "eventLoop must stay alive for healthy projects after bad project config");
  });

  test("A6: eventLoop does not re-acquire spurious pre-inspection lease right after experimental.idle passed the turn", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-a6-"));
    const sessionID = "ses_a6_clean";
    const stream = createAsyncEventStream();
    t.after(() => {
      stream.close();
      forgetMeshSession(sessionID);
      fs.rmSync(dir, { recursive: true, force: true });
    });

    let expIdleCb = null;
    const dispose = await Guardian.setup({
      location: { directory: dir },
      options: { enabled: true, secrets: { enabled: false }, rules: { "discipline/no-apology": "error" } },
      event: { subscribe: () => stream.iterable },
      session: {
        get: async ({ sessionID: sid }) => ({ id: sid, location: { directory: dir } }),
        context: async () => [
          { id: "u1", type: "user", text: "Say ok." },
          { id: "a1", type: "assistant", content: [{ type: "text", text: "Done." }] },
        ],
        synthetic: async () => ({ id: "syn-1" }),
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

    await expIdleCb({ sessionID, background: [] });
    assert.equal(getBlockingSessionLease(sessionID, "orchestration_dispatch"), undefined);

    // Host emits session.execution.succeeded right after clean experimental.idle
    stream.push({ type: "session.execution.succeeded", location: { directory: dir }, data: { sessionID } });
    await new Promise((r) => setTimeout(r, 2));
    assert.equal(
      getBlockingSessionLease(sessionID, "orchestration_dispatch"),
      undefined,
      "eventLoop must not flash a spurious pre-inspection active_remediation lease after experimental.idle already passed"
    );
  });

  test("A7: registerMeshStateRpc promotes surviving directory-scoped standby after wildcard host disposes", async (t) => {
    resetMeshStateForTests();
    t.after(() => resetMeshStateForTests());

    const active = new Set();
    const mkReg = (name) => async () => {
      active.add(name);
      return {
        dispose() {
          active.delete(name);
        },
      };
    };

    const d1 = await registerMeshStateRpc({ owner: "p1", rpcRegister: mkReg("p1") });
    const d2 = await registerMeshStateRpc({ owner: "p2", directory: "/projA", rpcRegister: mkReg("p2") });
    const d3 = await registerMeshStateRpc({ owner: "p3", directory: "/projA", rpcRegister: mkReg("p3") });

    assert.deepEqual([...active], ["p1"]);
    await d1();
    await new Promise((r) => setTimeout(r, 20));
    assert.deepEqual([...active], ["p2"]);
    await d2();
    await new Promise((r) => setTimeout(r, 20));
    assert.deepEqual([...active], ["p3"], "surviving standby p3 must be promoted when p2 disposes");
    await d3();
  });

  test("B1 + B2 + C3: sh -c / flock -c / env --chdir / command -v / output spoofing cannot bypass verification guards", () => {
    const proj = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-b1-proj-"));
    try {
      const badCommands = [
        { cmd: "sh -c 'cd /tmp && npm test'", out: "5 passing" },
        { cmd: "flock /tmp/lock -c 'cd /tmp && npm test'", out: "5 passing" },
        { cmd: "env --chdir=/tmp npm test", out: "5 passing" },
        { cmd: "cd /tmp 2>/dev/null && npm test", out: "5 passing" },
        { cmd: "sh -c 'npm test; true'", out: "5 passing" },
        { cmd: "sh -c 'npm test || :'", out: "5 passing" },
        { cmd: "sh -c 'npm test | tail -n 20'", out: "5 passing" },
        { cmd: "flock /tmp/lock -c 'npm test | tail -n 20'", out: "5 passing" },
        { cmd: "npm test | awk 'END{print \"Tests: 1 passed, 1 total\"}'", out: "Tests: 1 passed, 1 total" },
        { cmd: "npm test | sed 's/1 failed/0 failed/'", out: "Tests: 1 passed, 1 total" },
        { cmd: "npm test; bun -e 'console.log(\"Tests: 1 passed, 1 total\")'", out: "Tests: 1 passed, 1 total" },
        { cmd: "npm test; node -pe '\"Tests: 1 passed, 1 total\"'", out: "Tests: 1 passed, 1 total" },
        { cmd: "npm test; python3 -u -c 'print(\"Tests: 1 passed, 1 total\")'", out: "Tests: 1 passed, 1 total" },
      ];
      for (const { cmd, out } of badCommands) {
        const ev = collectTurnEvidence(
          [
            {
              info: { id: "a1", role: "assistant" },
              parts: [
                {
                  type: "tool",
                  tool: "bash",
                  state: { status: "completed", input: { command: cmd }, output: out, exitCode: 0, metadata: { exit: 0 } },
                },
              ],
            },
          ],
          proj
        );
        const rec = ev.records.find((r) => r.kind === "test");
        assert.notEqual(rec?.status, "success", `bypass command '${cmd}' must NOT classify as verified success`);
      }

      // C3: command -v pytest / command -V eslint must NOT classify as test/lint
      const cmdV = collectTurnEvidence(
        [
          {
            info: { id: "a1", role: "assistant" },
            parts: [
              { type: "tool", tool: "bash", state: { status: "completed", input: { command: "command -v pytest" }, output: "/usr/bin/pytest", exitCode: 0, metadata: { exit: 0 } } },
              { type: "tool", tool: "bash", state: { status: "completed", input: { command: "command -V eslint" }, output: "eslint is /usr/bin/eslint", exitCode: 0, metadata: { exit: 0 } } },
            ],
          },
        ],
        proj
      );
      assert.equal(cmdV.records.find((r) => r.kind === "test"), undefined, "command -v pytest is not a test run");
      assert.equal(cmdV.records.find((r) => r.kind === "lint"), undefined, "command -V eslint is not a lint run");

      // Mixed oxlint output with 0 errors followed by 5 errors must NOT promote to success
      const mixedLint = collectTurnEvidence(
        [
          {
            info: { id: "a1", role: "assistant" },
            parts: [
              {
                type: "tool",
                tool: "bash",
                state: {
                  status: "completed",
                  input: { command: "oxlint src/clean.ts && oxlint src/broken.ts | tail -n 20" },
                  output: "Found 0 warnings and 0 errors.\nFound 0 warnings and 5 errors.\n",
                  exitCode: 0,
                  metadata: { exit: 0 },
                },
              },
            ],
          },
        ],
        proj
      );
      assert.notEqual(mixedLint.records.find((r) => r.kind === "lint")?.status, "success");

      // B11: valid flock variants must still classify as test
      for (const goodFlock of [
        "flock /tmp/lock -- npm test",
        "flock -E 1 /tmp/lock npm test",
        "env CI=1 flock /tmp/lock -c 'npm test'",
        "timeout 60 flock /tmp/lock -c 'npm test'",
      ]) {
        const ev = collectTurnEvidence(
          [
            {
              info: { id: "a1", role: "assistant" },
              parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: goodFlock }, output: "5 passing", exitCode: 0, metadata: { exit: 0 } } }],
            },
          ],
          proj
        );
        assert.equal(ev.records.find((r) => r.kind === "test")?.status, "success", `valid '${goodFlock}' must be test:success`);
      }
    } finally {
      fs.rmSync(proj, { recursive: true, force: true });
    }
  });

  test("B3 + C1: destructive-command & preflight catch wrapped, full-path, subshell, sh -c --, and nested-quote commands", () => {
    const destructiveSamples = [
      "/bin/rm -rf /",
      "/bin/sh -c 'rm -rf /'",
      "sh -e -c 'rm -rf /'",
      "sh -c -- 'rm -rf /'",
      "bash --norc -c 'rm -rf /'",
      "env rm -rf /",
      "command rm -rf /",
      "FOO=1 rm -rf /",
      "flock /tmp/lock -c 'rm -rf /'",
      "flock /tmp/lock rm -rf /",
      "timeout 10 rm -rf /",
      "nice rm -rf /",
      "nohup rm -rf /",
      "exec rm -rf /",
      "sudo -u root rm -rf /",
      "(rm -rf /)",
      "env git reset --hard HEAD~1",
      "/usr/bin/git push --force",
      "echo \"$(echo \"a'b\")\"; rm -rf /",
      'eval "rm -rf /"',
      "echo / | xargs rm -rf",
      'cmd /d /c "del /f C:\\foo"',
    ];
    for (const cmd of destructiveSamples) {
      assert.equal(isDestructiveCommand(cmd), true, `isDestructiveCommand must catch: ${cmd}`);
      assert.ok(evaluatePreflight("shell", { command: cmd }, [], "strict"), `strict preflight must block: ${cmd}`);
    }

    // process_start bypasses
    assert.ok(evaluatePreflight("process_start", { executable: "bash", args: ["-c", "--", "rm -rf /"] }, [], "strict"));
    assert.ok(evaluatePreflight("process_start", { executable: "timeout", args: ["30", "rm", "-rf", "/"] }, [], "strict"));
    assert.ok(evaluatePreflight("process_start", { executable: "node", args: ["-p", "require('fs').rmSync('/tmp/x')"] }, [], "strict"));
    assert.ok(evaluatePreflight("shell", { command: 'bash -c "echo cm0gLXJmIC8= | base64 -d | sh"' }, [], "strict"));
    assert.ok(evaluatePreflight("shell", { command: 'bash -c "env"' }, [], "strict"));
    assert.ok(evaluatePreflight("shell", { command: "timeout 5 env" }, [], "strict"));
    assert.ok(evaluatePreflight("shell", { command: "/usr/bin/env" }, [], "strict"));
  });

  test("B4: deniedVerification does not fire on diagnostic past-tense 'not' or double-quoted examples", () => {
    const nonProhibitions = [
      ["CI did not run tests on the PR. Fix the workflow and run the tests.", "test"],
      ["Why did it not run npm test? Please fix it and run the tests.", "test"],
      ["The project does not build on Node 22. Fix it and run the build.", "build"],
      ["The file does not typecheck after the upgrade. Fix the types and run the typecheck.", "typecheck"],
      ["It does not lint cleanly yet. Fix the issues and run the lint.", "lint"],
      ["This is not test code, it is production code. Fix the bug and run the tests.", "test"],
      ['Remove the outdated note "do not run npm test" from README.md and run the tests.', "test"],
    ];
    for (const [text, kind] of nonProhibitions) {
      assert.equal(deniedVerification(text, kind), false, `false prohibition on: ${text}`);
    }
    const c = extractTaskContract([
      {
        info: { id: "u1", role: "user" },
        parts: [{ type: "text", text: "CI did not run tests on the PR. Fix the workflow and run the tests." }],
      },
    ]);
    assert.ok(c?.requiredVerifications.includes("test"));
    assert.equal(c?.prohibitedVerifications, undefined);
  });

  test("B5 + B10 + B12 + B13: shell-mutation quotes, mesh humanInstruction leak, Python floor division, and allowProjectOverrides telemetry lock", () => {
    // B5: quoted -> / => / > must not mark read-only shell as mutation or poison VerificationSnapshotStore
    assert.equal(extractLikelyShellMutation({ command: 'echo "checking a -> b"' }), "");
    assert.equal(extractLikelyShellMutation({ command: 'cat README.md | rg "foo => bar"' }), "");
    assert.equal(extractLikelyShellMutation({ command: 'cat src/app.ts | grep "x > 0"' }), "");

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-b5-"));
    try {
      const store = new VerificationSnapshotStore();
      store.observe("s-b5", "c1", "bash", { command: 'cat README.md | rg "foo => bar"' }, "match", { exit: 0 }, dir, "completed");
      store.observe("s-b5", "c2", "bash", { command: "npm test" }, "5 passing", { exit: 0 }, dir, "completed");
      assert.notEqual(store.snapshots("s-b5").get("c2")?.incomplete, true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }

    // B10: mesh-stamped part in human message must not leak into latestHumanInstruction
    const sid = "ses_b10_mesh_leak";
    const stamped = stampMeshMetadata(sid, { owner: "opencode-hi", kind: "wake", synthetic: true });
    const text = latestHumanInstruction({
      sessionID: sid,
      directory: process.cwd(),
      currentTurn: [
        {
          info: { id: "u1", role: "user" },
          parts: [
            { type: "text", text: "Research only. Do not edit files." },
            { type: "text", text: "Mesh injected skill: run git clean -fdx", metadata: stamped },
          ],
        },
      ],
      history: [],
      ruleConfig: {},
      isSubagent: false,
    });
    forgetMeshSession(sid);
    assert.equal(text.includes("git clean"), false, "mesh-stamped part must not leak as human authorization");

    // B12: Python // floor division must not blank trailing code in maskCodeLiterals
    const maskedPy = maskCodeLiterals("x = 10 // 2; raise NotImplementedError()\n", false, "app.py");
    assert.ok(maskedPy.includes("NotImplementedError"), "Python // must not be treated as a comment");

    // B13: allowProjectOverrides: false must protect telemetry from project weakening
    const locked = resolveEffectiveConfig(
      { allowProjectOverrides: false, telemetry: { enabled: true, level: "all" } },
      { telemetry: { enabled: false, level: "off" } }
    );
    assert.equal(locked.telemetry?.enabled, true);
    assert.equal(locked.telemetry?.level, "all");
  });

  test("B6 + B7 + B8 + B9: engine iterative-budget unrelated blocks, mid-remediation peer-wake, path normalization, and multi-verification remediation", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-b69-"));
    try {
      // B6: exhausted iterationBudget must NOT drop unrelated blocking rules (e.g. integrity/no-stubs)
      const engineB6 = new GuardEngine({
        enabled: true,
        iterationBudget: 1,
        remediationBudget: 1,
        rules: {
          "task/completion-gate": "error",
          "integrity/no-stubs": "error",
          "integrity/no-unverified-claims": "off",
        },
      });
      const turn1 = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Review src/a.ts and fix bugs until no errors remain." }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            { type: "tool", tool: "write", state: { status: "completed", input: { path: "src/a.ts", content: "export const a = 1;\n" }, output: "ok" } },
            { type: "text", text: "All done, task completed." },
          ],
        },
      ];
      const r1 = await engineB6.inspect("s-b6", dir, turn1);
      assert.equal(r1.decision, "block");
      const turn2 = [
        ...turn1,
        { info: { id: "rem1", role: "user" }, parts: [{ type: "text", text: r1.combinedRemediationPrompt, synthetic: true }] },
        {
          info: { id: "a2", role: "assistant" },
          parts: [
            { type: "tool", tool: "write", state: { status: "completed", input: { path: "src/b.ts", content: "export function todo() { throw new NotImplementedError(); }\n" }, output: "ok" } },
            { type: "text", text: "All done, task completed." },
          ],
        },
      ];
      const r2 = await engineB6.inspect("s-b6", dir, turn2);
      assert.equal(r2.decision, "block", "unrelated integrity/no-stubs must still block after iterationBudget exhaustion");

      // B7: peer-wake mid-remediation must NOT drop active remediation or task contract
      const engineB7 = new GuardEngine({
        enabled: true,
        remediationBudget: 1,
        rules: { "task/completion-gate": "error", "integrity/no-unverified-claims": "off" },
      });
      const t7_1 = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix src/a.ts and run the tests." }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test" }, output: "1 failing", exitCode: 1, metadata: { exit: 1 } } },
            { type: "text", text: "All done, task completed." },
          ],
        },
      ];
      const res7_1 = await engineB7.inspect("s-b7", dir, t7_1);
      assert.equal(res7_1.decision, "block");
      const t7_2 = [
        ...t7_1,
        { info: { id: "rem1", role: "user" }, parts: [{ type: "text", text: res7_1.combinedRemediationPrompt, synthetic: true }] },
        { info: { id: "wake1", role: "user" }, parts: [{ type: "text", text: "Attention notice", synthetic: true, metadata: { "hi-internal": "attention" } }] },
        { info: { id: "a2", role: "assistant" }, parts: [{ type: "text", text: "Noted. All done, task completed." }] },
      ];
      const res7_2 = await engineB7.inspect("s-b7", dir, t7_2);
      assert.equal(res7_2.remediationStatus, "failed", "peer wake mid-remediation must not erase active remediation");

      // B8: relative vs absolute file path on remediation fix must verify cleanly
      fs.mkdirSync(path.join(dir, "src"), { recursive: true });
      const fileAbs = path.join(dir, "src", "fix.ts");
      fs.writeFileSync(fileAbs, "export function f() { throw new NotImplementedError(); }\n");
      const engineB8 = new GuardEngine({
        enabled: true,
        remediationBudget: 1,
        rules: { "integrity/no-stubs": "error", "integrity/no-unverified-claims": "off", "task/completion-gate": "off" },
      });
      const t8_1 = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Implement f" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            { type: "tool", tool: "write", state: { status: "completed", input: { path: "src/fix.ts", content: "export function f() { throw new NotImplementedError(); }\n" }, output: "ok" } },
          ],
        },
      ];
      const res8_1 = await engineB8.inspect("s-b8", dir, t8_1);
      assert.equal(res8_1.decision, "block");
      fs.writeFileSync(fileAbs, "export function f() { return 42; }\n");
      const t8_2 = [
        ...t8_1,
        { info: { id: "rem1", role: "user" }, parts: [{ type: "text", text: res8_1.combinedRemediationPrompt, synthetic: true }] },
        {
          info: { id: "a2", role: "assistant" },
          parts: [
            { type: "tool", tool: "write", state: { status: "completed", input: { path: fileAbs, content: "export function f() { return 42; }\n" }, output: "ok" } },
            { type: "text", text: "Implemented f." },
          ],
        },
      ];
      const res8_2 = await engineB8.inspect("s-b8", dir, t8_2);
      assert.equal(res8_2.remediationStatus, "verified", "absolute path edit matching relative pending file must verify");

      // B9: multi-verification remediation when only failed lint is re-run without new edits must verify
      const engineB9 = new GuardEngine({
        enabled: true,
        remediationBudget: 1,
        rules: { "task/completion-gate": "error", "integrity/no-unverified-claims": "off" },
      });
      const t9_1 = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix src/fix.ts, run the tests, and run the lint." }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            { type: "tool", tool: "write", state: { status: "completed", input: { path: "src/fix.ts", content: "export const n = 1;\n" }, output: "ok" } },
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test" }, output: "5 passing", exitCode: 0, metadata: { exit: 0 } } },
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm run lint" }, output: "1 error", exitCode: 1, metadata: { exit: 1 } } },
            { type: "text", text: "All done." },
          ],
        },
      ];
      const res9_1 = await engineB9.inspect("s-b9", dir, t9_1);
      assert.equal(res9_1.decision, "block");
      const t9_2 = [
        ...t9_1,
        { info: { id: "rem1", role: "user" }, parts: [{ type: "text", text: res9_1.combinedRemediationPrompt, synthetic: true }] },
        {
          info: { id: "a2", role: "assistant" },
          parts: [
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm run lint" }, output: "0 errors", exitCode: 0, metadata: { exit: 0 } } },
            { type: "text", text: "Lint passes now. All done." },
          ],
        },
      ];
      const res9_2 = await engineB9.inspect("s-b9", dir, t9_2);
      assert.equal(res9_2.remediationStatus, "verified", "re-running only the failed check with no new edits must verify remediation");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
