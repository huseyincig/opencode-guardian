import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import Guardian, {
  GuardEngine,
  resolveEffectiveConfig,
} from "../dist/index.js";
import {
  calculateProductFingerprint,
  collectTurnEvidence,
  isDestructiveCommand,
  isOpaqueShellExecution,
} from "../dist/evidence.js";
import { evaluatePreflight, isHallucinatedOrMalformedPackageInstall } from "../dist/preflight.js";
import { assessCommandPreflight } from "../dist/secrets/preflight.js";
import { sanitizeMessages, sanitizeObject, sanitizeString } from "../dist/secrets/sanitizer.js";
import { findAllSecretsInCode } from "../dist/rules/no-secrets.js";
import { destructiveOperationsRule } from "../dist/rules/destructive-operations.js";
import { noGhostDepsRule } from "../dist/rules/no-ghost-deps.js";
import { taskCompletionRule } from "../dist/rules/task-completion.js";
import { circuitBreakerRule } from "../dist/rules/circuit-breaker.js";
import { noStubsRule } from "../dist/rules/no-stubs.js";
import { noSilentFailureRule } from "../dist/rules/no-silent-failure.js";
import { noShortcutsRule } from "../dist/rules/no-shortcuts.js";
import { instructionFidelityRule } from "../dist/rules/instruction-fidelity.js";
import { deniedVerification } from "../dist/locale-intents.js";
import { extractLikelyShellMutation } from "../dist/tool-input.js";
import {
  forgetMeshSession,
  getBlockingSessionLease,
  registerMeshStateRpc,
  resetMeshStateForTests,
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

describe("Debug Sweep Pass-2 — Runtime, Mesh, Shell, Evidence, Preflight, Engine, Secrets & Rules", () => {
  test("A-P2-1 & A-P2-2: pre-inspection lease refcounting survives concurrent callers and releases cleanly on idleQueue drop/eviction", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-p2-a12-"));
    const sessionID = "ses_p2_refcount";
    const stream = createAsyncEventStream();
    t.after(() => {
      stream.close();
      forgetMeshSession(sessionID);
      fs.rmSync(dir, { recursive: true, force: true });
    });

    let expIdleCb = null;
    let releaseFirstContext = null;
    let calls = 0;

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
          calls += 1;
          if (calls === 1) {
            await new Promise((r) => {
              releaseFirstContext = r;
            });
          }
          return [
            { id: "u1", type: "user", text: "Hello" },
            { id: "a1", type: "assistant", content: [{ type: "text", text: "Done cleanly." }] },
          ];
        },
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

    // EventLoop starts idleQueue job1 and pauses inside context()
    stream.push({ type: "session.execution.succeeded", location: { directory: dir }, data: { sessionID } });
    await new Promise((r) => setTimeout(r, 30));
    assert.ok(getBlockingSessionLease(sessionID, "orchestration_dispatch"), "job1 holds pre-inspection lease");

    // Concurrent experimental.idle hits busy processIdleSlot and returns early: must NOT drop job1's lease!
    await expIdleCb({ sessionID, background: [] });
    assert.ok(
      getBlockingSessionLease(sessionID, "orchestration_dispatch"),
      "early-exiting experimental.idle must NOT strip job1's active pre-inspection lease"
    );

    releaseFirstContext?.();
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(getBlockingSessionLease(sessionID, "orchestration_dispatch"), undefined);

    // Capacity eviction (>128 sessions) must immediately release evicted pre-inspection leases
    for (let i = 0; i < 131; i++) {
      stream.push({ type: "session.execution.succeeded", location: { directory: dir }, data: { sessionID: `ses_evict_${i}` } });
    }
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(
      getBlockingSessionLease("ses_evict_0", "orchestration_dispatch"),
      undefined,
      "evicted idleQueue session must release its pre-inspection lease immediately"
    );
    for (let i = 0; i < 131; i++) forgetMeshSession(`ses_evict_${i}`);
  });

  test("A-P2-3, A-P2-5 & A-P2-6: skipped experimental.idle and new turn activity allow pre-lease; prompt hook survives bad config & cancels mid-await idle", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-p2-a356-"));
    const badDir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-p2-bad-"));
    fs.writeFileSync(path.join(badDir, "opencode-guardian.json"), "{ invalid json");
    const stream = createAsyncEventStream();
    t.after(() => {
      stream.close();
      forgetMeshSession("ses_p2_skip");
      forgetMeshSession("ses_p2_prompt_race");
      forgetMeshSession("ses_p2_bad_prompt");
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(badDir, { recursive: true, force: true });
    });

    let expIdleCb = null;
    let promptCb = null;
    let bgRunning = true;
    let releaseGet = null;
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
        get: async ({ sessionID: sid }) => {
          if (sid === "ses_p2_bad_prompt") return { id: sid, location: { directory: badDir } };
          if (sid === "ses_p2_prompt_race" && releaseGet === null) {
            await new Promise((r) => {
              releaseGet = r;
            });
          }
          return { id: sid, location: { directory: dir } };
        },
        context: async ({ sessionID: sid }) => {
          if (sid === "ses_p2_skip" && bgRunning) {
            return [
              { id: "u1", type: "user", text: "Run bg" },
              {
                id: "a1",
                type: "assistant",
                content: [
                  {
                    type: "tool",
                    name: "bash",
                    state: {
                      status: "running",
                      input: { command: "npm test" },
                      metadata: { jobID: "j1", status: "running" },
                    },
                  },
                ],
              },
            ];
          }
          return [
            { id: "u1", type: "user", text: "Fix" },
            { id: "a1", type: "assistant", content: [{ type: "text", text: "I deeply apologize." }] },
          ];
        },
        synthetic: async (req) => {
          synthetics.push(req);
          return { id: `syn-${synthetics.length}` };
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

    // A-P2-3: skipped experimental.idle (bg tool running) must NOT suppress later eventLoop pre-lease
    await expIdleCb({ sessionID: "ses_p2_skip", background: [] });
    bgRunning = false;
    stream.push({ type: "session.idle", location: { directory: dir }, data: { sessionID: "ses_p2_skip" } });
    await new Promise((r) => setTimeout(r, 2));
    assert.ok(
      getBlockingSessionLease("ses_p2_skip", "orchestration_dispatch"),
      "eventLoop must acquire pre-inspection lease after a skipped experimental.idle"
    );
    await new Promise((r) => setTimeout(r, 35));

    // A-P2-5: prompt hook must NOT throw on invalid project config
    await assert.doesNotReject(
      promptCb({ sessionID: "ses_p2_bad_prompt", messageID: "u-bad", prompt: { text: "Hello" } })
    );

    // A-P2-6: prompt hook must cancel idle queued DURING its session.get await
    const beforeSyn = synthetics.length;
    const pPrompt = promptCb({ sessionID: "ses_p2_prompt_race", messageID: "u-race", prompt: { text: "New prompt" } });
    await new Promise((r) => setTimeout(r, 10));
    stream.push({ type: "session.idle", location: { directory: dir }, data: { sessionID: "ses_p2_prompt_race" } });
    await new Promise((r) => setTimeout(r, 2));
    releaseGet?.();
    await pPrompt;
    await new Promise((r) => setTimeout(r, 35));
    assert.equal(synthetics.length, beforeSyn, "late idle queued during prompt await must be cancelled");
  });

  test("A-P2-4: registerMeshStateRpc keeps host slot occupied during async dispose so concurrent register queues as standby", async (t) => {
    resetMeshStateForTests();
    t.after(() => resetMeshStateForTests());

    let activeOwner = null;
    let releaseDisposeA = null;
    const makeRpcRegister = (name) => async () => {
      if (activeOwner !== null) throw new Error(`duplicate RPC while ${activeOwner} active`);
      activeOwner = name;
      return {
        dispose: async () => {
          if (name === "A") {
            await new Promise((r) => {
              releaseDisposeA = r;
            });
          }
          if (activeOwner === name) activeOwner = null;
        },
      };
    };

    const dA = await registerMeshStateRpc({ owner: "A", directory: "/projX", rpcRegister: makeRpcRegister("A") });
    const dB = await registerMeshStateRpc({ owner: "B", directory: "/projX", rpcRegister: makeRpcRegister("B") });
    const pDisposeA = dA();
    await new Promise((r) => setTimeout(r, 10));
    const dC = await registerMeshStateRpc({ owner: "C", directory: "/projX", rpcRegister: makeRpcRegister("C") });
    releaseDisposeA?.();
    await pDisposeA;

    assert.equal(activeOwner, "B", "B must be promoted cleanly after A finishes async dispose");
    await dB();
    assert.equal(activeOwner, "C", "C must be promoted after B disposes");
    await dC();
    assert.equal(activeOwner, null);
  });

  test("B-P2-1..B-P2-4: ANSI-C $'...', |&, process_start flags/launchers, shell wrappers, eval, and git global opts", () => {
    // B-P2-1: ANSI-C quoting
    assert.equal(evaluatePreflight("bash", { command: "echo $'hello\\''; rm -rf /" }, [], "strict"), "destructive-command");
    const ansiEv = collectTurnEvidence([
      { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test && echo $'\\'' || true" }, output: "ok", exitCode: 0, metadata: { exit: 0 } } }] },
    ], process.cwd());
    assert.equal(ansiEv.records.find((r) => r.kind === "test")?.status, "unknown");

    // B-P2-2: |& pipe
    assert.equal(isOpaqueShellExecution("echo cm0gLXJmIC8= | base64 -d |& bash"), true);
    assert.equal(evaluatePreflight("bash", { command: "echo cm0gLXJmIC8= | base64 -d |& bash" }, [], "strict"), "opaque-shell-execution");

    // B-P2-3: process_start bypasses
    const blockedProcs = [
      { executable: "pwsh", args: ["-ExecutionPolicy", "Bypass", "-Command", "Remove-Item -Recurse -Force C:\\"] },
      { executable: "powershell", args: ["-ExecutionPolicy", "Bypass", "-EncodedCommand", "ZQBjAGgAbwAgADAA"] },
      { executable: "bash", args: ["--rcfile", "-c", "-c", "rm -rf /"] },
      { executable: "stdbuf", args: ["-oL", "node", "-e", "process.exit(0)"] },
      { executable: "ionice", args: ["-c3", "python3", "-c", "print(1)"] },
      { executable: "python3", args: ["-uc", "import shutil; shutil.rmtree(\"/\")"] },
      { executable: "sudo", args: ["--user", "root", "node", "-e", "process.exit(0)"] },
      { executable: "flock", args: ["/tmp/lock", "--command", "rm -rf /"] },
      { executable: "env", args: ["-S", "rm -rf /"] },
    ];
    for (const proc of blockedProcs) {
      assert.notEqual(evaluatePreflight("process_start", proc, [], "strict"), undefined, `must block process_start: ${JSON.stringify(proc)}`);
    }

    // B-P2-4: shell-risk bypasses
    const blockedCmds = [
      "! rm -rf /",
      "! git reset --hard",
      "! find . -delete",
      "! base64 -d | sh",
      "! bash -c 'rm -rf /'",
      "eval rm -rf /",
      'eval "rm" "-rf" "/"',
      "bash -o errexit -c 'rm -rf /'",
      "bash +e -c 'rm -rf /'",
      "bash -c $'rm -rf /'",
      "flock /tmp/lock --command 'rm -rf /'",
      "env - rm -rf /",
      'env -S "rm -rf /"',
      "sudo --user root rm -rf /",
      "timeout -s9 5 rm -rf /",
      "nice -n10 rm -rf /",
      "stdbuf -o L rm -rf /",
      "setsid --wait rm -rf /",
      "2>/dev/null rm -rf /",
      "'rm' -rf /",
      "env $CMD -rf /",
      "FOO=1 $CMD -rf /",
      "git --no-pager reset --hard",
      "git -P push --force",
      "git --no-pager clean -fd",
      "git --git-dir=/tmp/repo clean -fd",
      "git -C. reset --hard",
    ];
    for (const command of blockedCmds) {
      assert.notEqual(evaluatePreflight("bash", { command }, [], "strict"), undefined, `must block: ${command}`);
    }
    assert.equal(isDestructiveCommand("git --no-pager reset --hard"), true);
  });

  test("B-P2-5..B-P2-11: evidence spoofing/pipefail/cwd, telemetry lock, deniedVerification, tool-input, preflight commit/pkg", () => {
    // B-P2-5: output spoofing bypasses
    for (const [cmd, out] of [
      ['npm test | grep -e "Tests:" fake-pass.txt', "Tests: 5 passed, 5 total"],
      ['npm test | grep --regexp="Tests:" fake-pass.txt', "Tests: 5 passed, 5 total"],
      ["npm test | tee /dev/null < fake-pass.txt", "Tests: 5 passed, 5 total"],
      ["jest --coverage || pwd", "Tests: 5 passed, 5 total"],
      ['oxlint src/ | grep -e "Found" fake-oxlint.txt', "Found 0 warnings and 0 errors."],
      ['oxlint clean.ts ; oxlint broken.ts | grep -v "Found"', "Found 0 warnings and 0 errors."],
    ]) {
      const ev = collectTurnEvidence([
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: cmd }, output: out, exitCode: 0, metadata: { exit: 0 } } }] },
      ], process.cwd());
      assert.notEqual(ev.records.find((r) => r.kind === "test" || r.kind === "lint")?.status, "success", `spoofing must NOT pass: ${cmd}`);
    }

    // B-P2-6: pipefail bypasses
    for (const cmd of [
      "set -o pipefail; (set +o pipefail; npm test | cat)",
      "if false; then\nset -o pipefail\nfi\nnpm test | cat",
    ]) {
      const ev = collectTurnEvidence([
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: cmd }, output: "ok", exitCode: 0, metadata: { exit: 0 } } }] },
      ], process.cwd());
      assert.equal(ev.records.find((r) => r.kind === "test")?.status, "unknown", `pipefail bypass must stay unknown: ${cmd}`);
    }

    // B-P2-7: env -C case sensitivity & wrappers + pushd / builtin cd
    for (const okCmd of [
      "env CI=1 eslint -c ../shared/eslint.config.js src/",
      "env CI=1 pytest -c ../pytest.ini",
    ]) {
      const ev = collectTurnEvidence([
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: okCmd }, output: "ok", exitCode: 0, metadata: { exit: 0 } } }] },
      ], process.cwd());
      assert.equal(ev.records.find((r) => r.kind === "lint" || r.kind === "test")?.status, "success", `lowercase -c must NOT trigger foreign cwd: ${okCmd}`);
    }
    for (const foreignCmd of [
      "timeout 30 env -C /tmp npm test",
      "pushd /tmp && npm test",
      "builtin cd /tmp && npm test",
    ]) {
      const ev = collectTurnEvidence([
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: foreignCmd }, output: "ok", exitCode: 0, metadata: { exit: 0 } } }] },
      ], process.cwd());
      assert.equal(ev.records.find((r) => r.kind === "test")?.status, "unknown", `foreign cwd bypass must be unknown: ${foreignCmd}`);
    }

    // B-P2-8: allowProjectOverrides telemetry lock
    const lockedDefault = resolveEffectiveConfig({ allowProjectOverrides: false }, { telemetry: { enabled: false, level: "off" } });
    assert.equal(lockedDefault.telemetry?.enabled, true);
    assert.equal(lockedDefault.telemetry?.level, "violations");
    const lockedLevelOnly = resolveEffectiveConfig({ allowProjectOverrides: false, telemetry: { level: "all" } }, { telemetry: { enabled: false } });
    assert.equal(lockedLevelOnly.telemetry?.enabled, true);
    assert.equal(lockedLevelOnly.telemetry?.level, "all");
    const lockedNoUpgrade = resolveEffectiveConfig({ allowProjectOverrides: false, telemetry: { enabled: true } }, {});
    assert.equal(lockedNoUpgrade.telemetry?.level, "violations");

    // B-P2-9: deniedVerification negations
    assert.equal(deniedVerification("Fix the auth bug and do not skip tests; run the tests to verify.", "test"), false);
    assert.equal(deniedVerification("Fix the parser and run the tests; never finish without running tests.", "test"), false);
    assert.equal(deniedVerification("Do not merge without running the build. Fix the code and run the build.", "build"), false);
    assert.equal(deniedVerification("Fix the script. It is currently not running tests in CI. Run the tests locally.", "test"), false);

    // B-P2-10: extractLikelyShellMutation does not flag node --test / pytest args
    assert.equal(extractLikelyShellMutation({ command: "node --test tests/writeFileSync.test.mjs" }), "");
    assert.equal(extractLikelyShellMutation({ command: 'node --test --test-name-pattern="writeFileSync"' }), "");
    assert.equal(extractLikelyShellMutation({ command: "python3 -m pytest -k test_write_text" }), "");

    // B-P2-11: empty commit message, -unormal/-cmain, GitHub shorthand
    assert.equal(evaluatePreflight("bash", { command: 'git commit -m ""' }, [], "strict"), "lazy-commit-message");
    assert.equal(evaluatePreflight("bash", { command: 'git commit -m "" --no-verify' }, [], "strict"), "lazy-commit-message");
    assert.equal(evaluatePreflight("bash", { command: 'git commit -unormal -m "feat: add comprehensive user authentication"' }, [], "strict"), undefined);
    assert.equal(evaluatePreflight("bash", { command: "git commit -cmain" }, [], "strict"), undefined);
    assert.equal(isHallucinatedOrMalformedPackageInstall("npm install MyOrg/my-repo"), false);
    assert.equal(isHallucinatedOrMalformedPackageInstall("npm install gitlab:MyOrg/my-repo"), false);
  });

  test("B-P2-12: GuardEngine B6/B7/B8/B9 edge cases & symlink canonicalization", async () => {
    // B8 symlink canonicalization
    const baseTmp = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-p2-sym-"));
    try {
      const realDir = path.join(baseTmp, "real-proj");
      const linkDir = path.join(baseTmp, "link-proj");
      fs.mkdirSync(path.join(realDir, "src"), { recursive: true });
      fs.writeFileSync(path.join(realDir, "src", "a.ts"), "export const ok = 1;\n");
      fs.symlinkSync(realDir, linkDir);
      const fp = calculateProductFingerprint(linkDir, [path.join(realDir, "src", "a.ts")]);
      assert.notEqual(fp, "unverified-state", "canonical realpath inside symlinked project root must fingerprint cleanly");

      // B7: peer wake AFTER completed remediation in same human turn acts as fresh peer-wake turn
      const engine = new GuardEngine({
        enabled: true,
        remediationBudget: 1,
        rules: { "discipline/no-apology": "error", "task/completion-gate": "off", "integrity/no-unverified-claims": "off" },
      });
      const t1 = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Help me." }] },
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "text", text: "I deeply apologize." }] },
      ];
      const r1 = await engine.inspect("s-p2-b7", realDir, t1);
      assert.equal(r1.decision, "block");
      const t2 = [
        ...t1,
        { info: { id: "rem1", role: "user" }, parts: [{ type: "text", text: r1.combinedRemediationPrompt, synthetic: true }] },
        { info: { id: "a2", role: "assistant" }, parts: [{ type: "text", text: "Resolved directly." }] },
      ];
      await engine.inspect("s-p2-b7", realDir, t2);
      const t3 = [
        ...t2,
        { info: { id: "w1", role: "user" }, parts: [{ type: "text", text: "Wake", synthetic: true, metadata: { "hi-internal": "attention" } }] },
        { info: { id: "a3", role: "assistant" }, parts: [{ type: "text", text: "Acknowledged." }] },
      ];
      const r3 = await engine.inspect("s-p2-b7", realDir, t3);
      assert.equal(r3.remediationStatus, undefined, "peer wake after completed remediation must not stay stuck in remediationResponse mode");

      // B9: iterative contract with requiresSourceReview + requiredVerifications verifies when Round 2 does source review after Round 1 passing test
      const engineB9 = new GuardEngine({
        enabled: true,
        iterationBudget: 2,
        remediationBudget: 1,
        rules: { "task/completion-gate": "error", "integrity/no-unverified-claims": "off" },
      });
      const b9_1 = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix src/a.ts, run tests, and do a full source review again until no errors remain." }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            { type: "tool", tool: "write", state: { status: "completed", input: { path: "src/a.ts", content: "export const ok = 2;\n" }, output: "ok" } },
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test" }, output: "1 passing", exitCode: 0, metadata: { exit: 0 } } },
            { type: "text", text: "All done, task completed." },
          ],
        },
      ];
      const rb9_1 = await engineB9.inspect("s-p2-b9", realDir, b9_1);
      assert.equal(rb9_1.decision, "block");
      const b9_2 = [
        ...b9_1,
        { info: { id: "rem1", role: "user" }, parts: [{ type: "text", text: rb9_1.combinedRemediationPrompt, synthetic: true }] },
        {
          info: { id: "a2", role: "assistant" },
          parts: [
            { type: "tool", tool: "read_file", state: { status: "completed", input: { path: "src/a.ts" }, output: "export const ok = 2;\n" } },
            { type: "text", text: "Reviewed src/a.ts cleanly. All done, task completed." },
          ],
        },
      ];
      const rb9_2 = await engineB9.inspect("s-p2-b9", realDir, b9_2);
      assert.equal(rb9_2.remediationStatus, "verified");
    } finally {
      fs.rmSync(baseTmp, { recursive: true, force: true });
    }
  });

  test("C-P2-1..C-P2-7: secrets preflight, Step 3b regex cursor/code/prose/pin_code, >2MiB YAML & single-line chunking, sanitizeMessages counter, findAllSecretsInCode", () => {
    // C-P2-1
    for (const cmd of [
      "env -0",
      "env --null",
      "env > /tmp/out.txt",
      "printenv > /tmp/out.txt",
      "docker exec mybox /usr/bin/env",
      "docker container inspect mybox",
    ]) {
      assert.equal(assessCommandPreflight(cmd).isHighRiskEnvDump, true, `must flag env dump: ${cmd}`);
    }

    // C-P2-2: hasRegexCustomKeys after word: prefix
    assert.equal(sanitizeString("log: x_vault_key=secret123456", { customSensitiveKeys: [/^x_vault_/i] }).sanitized.includes("secret123456"), false);
    assert.equal(sanitizeString('debug: x_vault_id: "super_secret_999"', { customSensitiveKeys: [/^x_vault_/i] }).sanitized.includes("super_secret_999"), false);

    // C-P2-3: code & prose preservation
    for (const safe of [
      "const cfg = { token: getToken(), secret: cfg.getSecret() };",
      "interface AuthConfig {\n  token: string;\n  password: string;\n}",
      "const cfg = {\n  token: user.token,\n  secret: env.SECRET,\n};",
      "Please provide your password immediately.",
      "The password Manager crashed.",
      "Invalid token (expired)",
    ]) {
      assert.equal(sanitizeString(safe).sanitized, safe, `must preserve safe text: ${safe}`);
    }

    // C-P2-4: findAllSecretsInCode customSensitiveKeys code refs
    const customOpts = { customSensitiveKeys: ["my_vault_key"] };
    for (const safeCode of [
      "const cfg = { my_vault_key: getSecret() };",
      "const cfg = { my_vault_key: vault.getKey() };",
      "const cfg = { my_vault_key: opts?.vaultKey };",
      "interface Cfg { my_vault_key: string[]; }",
    ]) {
      assert.equal(findAllSecretsInCode(safeCode, "src/cfg.ts", undefined, customOpts).length, 0, `must not flag code ref: ${safeCode}`);
    }

    // C-P2-5: pin_code inline & duplicate JSON
    assert.equal(sanitizeString("log: pin_code=987654").sanitized.includes("987654"), false);
    assert.equal(sanitizeString('{"pin_code": "987654", "pin_code": ""}').sanitized.includes("987654"), false);

    // C-P2-6: >2MiB Buffer YAML block scalar & single-line secret straddling 1MiB
    const yamlBuf = Buffer.from(
      "a".repeat(1024 * 1024 - 20) +
        "\nprivate_key: |\n  secret_line_1\n  secret_line_2_leaked\n" +
        "b".repeat(1024 * 1024)
    );
    const sanYaml = sanitizeObject({ buf: yamlBuf }).sanitized.buf.toString("utf8");
    assert.equal(sanYaml.includes("secret_line_2_leaked"), false);

    const singleLineBuf = Buffer.from(
      "x".repeat(1024 * 1024 - 11) +
        " sk-proj-1234567890abcdefghij1234567890 " +
        "y".repeat(1024 * 1024)
    );
    const sanLine = sanitizeObject({ buf: singleLineBuf }).sanitized.buf.toString("utf8");
    assert.equal(sanLine.includes("sk-proj-1234567890"), false);

    // C-P2-7: sanitizeMessages preserves numeric counter keys
    const sanMsgs = sanitizeMessages([{ info: { role: "assistant" }, token_count: 1500, parts: [{ type: "text", text: "ok" }] }]);
    assert.equal(sanMsgs[0].token_count, 1500);
  });

  test("C-P2-8..C-P2-15: destructive-operations, ghost-deps, task-completion, circuit-breaker, no-stubs, no-silent-failure, no-shortcuts, instruction-fidelity", () => {
    // C-P2-8: guardBypass -nm"msg", -c key="val space", and -am "-n" FP
    for (const bypassCmd of [
      'git commit -nm"fix: skip hooks"',
      'git commit -anm"fix: skip hooks"',
      'git -c user.name="John Doe" commit --no-verify -m "feat: bypass"',
      'git -c core.hooksPath="/tmp/my hooks" commit -m "feat: bypass"',
    ]) {
      const turn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Commit the changes." }] },
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: bypassCmd }, output: "ok" } }] },
      ];
      assert.equal(destructiveOperationsRule.inspect({ sessionID: "s-c8", directory: process.cwd(), currentTurn: turn, history: turn, evidence: collectTurnEvidence(turn, process.cwd()), ruleConfig: {}, isSubagent: false }).decision, "block", bypassCmd);
    }
    const safeCommitTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Commit the changes." }] },
      { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: 'git commit -am "-n"' }, output: "ok" } }] },
    ];
    assert.equal(destructiveOperationsRule.inspect({ sessionID: "s-c8-ok", directory: process.cwd(), currentTurn: safeCommitTurn, history: safeCommitTurn, evidence: collectTurnEvidence(safeCommitTurn, process.cwd()), ruleConfig: {}, isSubagent: false }).decision, "pass");

    // C-P2-9: no-ghost-deps arr[0]/2, multi-interpolation template, nested template `}`
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-p2-ghost-"));
    try {
      fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app", dependencies: {} }));
      for (const code of [
        'const x = arr[0] / 2; const y = require("totally-fake-ghost-pkg");',
        'const s = `${require("totally-fake-ghost-pkg")} ${ok}`;',
        'const s = `${`}`}`;\nimport x from "totally-fake-ghost-pkg";',
      ]) {
        const turn = [
          { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Edit" }] },
          { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "write", state: { status: "completed", input: { path: "src/a.ts", content: code }, output: "ok" } }] },
        ];
        assert.equal(noGhostDepsRule.inspect({ sessionID: "s-c9", directory: dir, currentTurn: turn, history: turn, ruleConfig: {}, isSubagent: false }).decision, "block", code);
      }

      // C-P2-10: compound probe failure must block; npm run test -> npm test & npx vitest run resolve
      const compFailTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Migrate" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "test -f package.json && node scripts/migrate.mjs" }, output: "Migration aborted: schema mismatch", exitCode: 1, metadata: { exit: 1 } } },
            { type: "text", text: "Done." },
          ],
        },
      ];
      assert.equal(taskCompletionRule.inspect({ sessionID: "s-c10a", directory: dir, currentTurn: compFailTurn, history: compFailTurn, evidence: collectTurnEvidence(compFailTurn, dir), ruleConfig: {}, isSubagent: false }).decision, "block");

      const npmRunToTestTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix auth" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm run test -- tests/auth.test.mjs" }, output: "1 failing", exitCode: 1, metadata: { exit: 1 } } },
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test" }, output: "5 passing", exitCode: 0, metadata: { exit: 0 } } },
            { type: "text", text: "Task completed." },
          ],
        },
      ];
      assert.equal(taskCompletionRule.inspect({ sessionID: "s-c10b", directory: dir, currentTurn: npmRunToTestTurn, history: npmRunToTestTurn, evidence: collectTurnEvidence(npmRunToTestTurn, dir), ruleConfig: {}, isSubagent: false }).decision, "pass");

      // C-P2-11: circuit-breaker catches compound grep && fail and find -exec fail
      const cbTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Run" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [1, 2, 3].map((n) => ({
            type: "tool",
            tool: "bash",
            state: { status: "completed", input: { command: `grep -q foo package.json && node scripts/migrate.mjs --step ${n}` }, output: "Migration failed: missing table users", exitCode: 1, metadata: { exit: 1 } },
          })),
        },
      ];
      assert.equal(circuitBreakerRule.inspect({ sessionID: "s-c11", directory: dir, currentTurn: cbTurn, history: cbTurn, evidence: collectTurnEvidence(cbTurn, dir), ruleConfig: {}, isSubagent: false }).decision, "block");

      // C-P2-12: no-stubs multi-stage shell redirection & absolute test/ helper path
      const stubShellTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Write" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: 'echo "" > types.d.ts && cat << EOF > src/app.ts\nexport function broken() { throw new NotImplementedError(); }\nEOF' }, output: "ok" } }],
        },
      ];
      assert.equal(noStubsRule.inspect({ sessionID: "s-c12a", directory: dir, currentTurn: stubShellTurn, history: stubShellTurn, ruleConfig: {}, isSubagent: false }).decision, "block");

      const absTestHelperTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Add helper" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [{ type: "tool", tool: "write", state: { status: "completed", input: { path: path.join(dir, "test", "helper.ts"), content: "export function mockCb() {}\n" }, output: "ok" } }],
        },
      ];
      assert.equal(noStubsRule.inspect({ sessionID: "s-c12b", directory: dir, currentTurn: absTestHelperTurn, history: absTestHelperTurn, ruleConfig: {}, isSubagent: false }).decision, "pass");

      // C-P2-13: no-silent-failure catches ; true, ; :, sh -c 'npm test; true', cmd /c, pwsh -Command
      for (const maskCmd of [
        "npm test; true",
        "npm test; :",
        "sh -c 'npm test; true'",
        'cmd /c "npm test || true"',
        'pwsh -Command "npm test || true"',
      ]) {
        const turn = [
          { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Run tests" }] },
          { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: maskCmd }, output: "ok" } }] },
        ];
        assert.equal(noSilentFailureRule.inspect({ sessionID: "s-c13", directory: dir, currentTurn: turn, history: turn, evidence: collectTurnEvidence(turn, dir), ruleConfig: {}, isSubagent: false }).decision, "block", maskCmd);
      }

      // C-P2-14: no-shortcuts JS regex literal, Python //, Rust #[...]
      const jsRegexBypass = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Write" }] },
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "write", state: { status: "completed", input: { path: "src/a.ts", content: "const q = /'/;\n// TODO: finish later\n" }, output: "ok" } }] },
      ];
      assert.equal(noShortcutsRule.inspect({ sessionID: "s-c14a", directory: dir, currentTurn: jsRegexBypass, history: jsRegexBypass, ruleConfig: {}, isSubagent: false }).decision, "block");
      for (const [p, c] of [
        ["src/a.ts", 'const re = /https?:\\/\\//; const msg = "for now";\n'],
        ["src/a.py", 'x = total // 2; label = "for now"\n'],
        ["src/lib.rs", '#[deprecated(note = "for now")]\npub fn old() {}\n'],
      ]) {
        const turn = [
          { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Write" }] },
          { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "write", state: { status: "completed", input: { path: p, content: c }, output: "ok" } }] },
        ];
        assert.equal(noShortcutsRule.inspect({ sessionID: "s-c14b", directory: dir, currentTurn: turn, history: turn, ruleConfig: {}, isSubagent: false }).decision, "pass", p);
      }

      // C-P2-15: descriptive "No changes have been made yet; please fix src/a.ts." is not research-only
      const descTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "No changes have been made yet; please fix src/a.ts." }] },
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "write", state: { status: "completed", input: { path: "src/a.ts", content: "export const ok = 1;\n" }, output: "ok" } }] },
      ];
      assert.equal(instructionFidelityRule.inspect({ sessionID: "s-c15", directory: dir, currentTurn: descTurn, history: descTurn, evidence: collectTurnEvidence(descTurn, dir), ruleConfig: {}, isSubagent: false }).decision, "pass");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
