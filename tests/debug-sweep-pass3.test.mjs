import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import Guardian from "../dist/index.js";
import { collectTurnEvidence } from "../dist/evidence.js";
import { evaluatePreflight } from "../dist/preflight.js";
import { assessCommandPreflight } from "../dist/secrets/preflight.js";
import { sanitizeObject, sanitizeString } from "../dist/secrets/sanitizer.js";
import { findAllSecretsInCode } from "../dist/rules/no-secrets.js";
import { noStubsRule } from "../dist/rules/no-stubs.js";
import { destructiveOperationsRule } from "../dist/rules/destructive-operations.js";
import { taskCompletionRule } from "../dist/rules/task-completion.js";
import { circuitBreakerRule } from "../dist/rules/circuit-breaker.js";
import { noSilentFailureRule } from "../dist/rules/no-silent-failure.js";
import { noGhostDepsRule } from "../dist/rules/no-ghost-deps.js";
import { noShortcutsRule } from "../dist/rules/no-shortcuts.js";
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

describe("Debug Sweep Pass-3 — P0/P1/P2 Closure", () => {
  test("R-P3-1: registerMeshStateRpc awaits in-flight standby promotion before resolving standby dispose", async (t) => {
    resetMeshStateForTests();
    t.after(() => resetMeshStateForTests());

    let releaseRegB = null;
    let regBDisposed = false;
    const dA = await registerMeshStateRpc({
      owner: "A",
      directory: "/p3-rpc",
      rpcRegister: async () => ({ dispose: async () => {} }),
    });
    const dB = await registerMeshStateRpc({
      owner: "B",
      directory: "/p3-rpc",
      rpcRegister: async () => {
        await new Promise((r) => {
          releaseRegB = r;
        });
        return {
          dispose: async () => {
            regBDisposed = true;
          },
        };
      },
    });

    const pA = dA();
    await new Promise((r) => setTimeout(r, 10));
    let dBResolved = false;
    const pB = dB().then(() => {
      dBResolved = true;
    });
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(dBResolved, false, "dB() must await in-flight promotion before resolving");
    releaseRegB?.();
    await Promise.all([pA, pB]);
    assert.equal(dBResolved, true);
    assert.equal(regBDisposed, true, "disposed standby must cleanly dispose its newly promoted registration");
  });

  test("R-P3-2 & R-P3-3: no zombie preInspectionLeases and prompt aborts concurrent experimental.idle started during session.get", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-p3-rt-"));
    const stream = createAsyncEventStream();
    t.after(() => {
      stream.close();
      forgetMeshSession("ses_p3_zombie");
      forgetMeshSession("ses_p3_exp_race");
      fs.rmSync(dir, { recursive: true, force: true });
    });

    let expIdleCb = null;
    let promptCb = null;
    let releaseGetPrompt = null;
    let releaseExpCtx = null;
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
          if (sid === "ses_p3_exp_race" && releaseGetPrompt === null) {
            await new Promise((r) => {
              releaseGetPrompt = r;
            });
          }
          return { id: sid, location: { directory: dir } };
        },
        context: async ({ sessionID: sid }) => {
          if (sid === "ses_p3_exp_race" && releaseExpCtx === null) {
            await new Promise((r) => {
              releaseExpCtx = r;
            });
          }
          return [
            { id: "u1", type: "user", text: "Hello" },
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

    // R-P3-3: experimental.idle starts DURING prompt's session.get await -> must be aborted, 0 stale synthetics
    const pPrompt = promptCb({ sessionID: "ses_p3_exp_race", messageID: "u2", prompt: { text: "New task" } });
    await new Promise((r) => setTimeout(r, 10));
    const pExp = expIdleCb({ sessionID: "ses_p3_exp_race", background: [] });
    await new Promise((r) => setTimeout(r, 10));
    releaseGetPrompt?.();
    await pPrompt;
    releaseExpCtx?.();
    await pExp;
    assert.equal(synthetics.length, 0, "experimental.idle started during prompt await must not inject stale remediation");
    assert.equal(getBlockingSessionLease("ses_p3_exp_race", "orchestration_dispatch"), undefined);
  });

  test("R-P3-4..R-P3-6: shell-risk, process_start, and evidence pipefail/summary/cwd closure", () => {
    // R-P3-4: preflight bypasses
    const blockedBash = [
      "echo $'\\'' $(rm -rf /)",
      "echo $'\\'' `rm -rf /`",
      'bash -co errexit "rm -rf /"',
      "bash -c 'rm'' -rf /'",
      "env -C/tmp rm -rf /",
      'env -S"rm -rf /"',
      '! pwsh -Command "Remove-Item -Recurse -Force C:\\"',
    ];
    for (const command of blockedBash) {
      assert.notEqual(evaluatePreflight("bash", { command }, [], "strict"), undefined, `must block: ${command}`);
    }
    const blockedProc = [
      { executable: "bash", args: ["-co", "errexit", "rm -rf /"] },
      { executable: "env", args: ["-Srm -rf /"] },
      { executable: "env", args: ["-vS", "rm -rf /"] },
      { executable: "timeout", args: ["--", "5", "node", "-e", "1"] },
      { executable: "flock", args: ["--", "/tmp/l", "node", "-e", "1"] },
    ];
    for (const proc of blockedProc) {
      assert.notEqual(evaluatePreflight("process_start", proc, [], "strict"), undefined, `must block proc: ${JSON.stringify(proc)}`);
    }

    // R-P3-5: process_start script/module args after positional or -m must NOT false-block
    for (const okProc of [
      { executable: "python3", args: ["-m", "pytest", "-c", "pytest.ini"] },
      { executable: "node", args: ["server.js", "-p", "3000"] },
      { executable: "node", args: ["cli.js", "-e", "prod"] },
    ]) {
      assert.equal(evaluatePreflight("process_start", okProc, [], "strict"), undefined, `must allow proc: ${JSON.stringify(okProc)}`);
    }

    // R-P3-6: evidence subshell pipefail, grep/head -n 0 spoofing, wrapped env -C / sudo --chdir
    for (const [cmd, out] of [
      ["(set -o pipefail); npm test | cat", "ok"],
      ["npm test | grep -ieTests: fake-pass.txt", "Tests: 5 passed, 5 total"],
      ["npm test | grep -fpat.txt fake-pass.txt", "Tests: 5 passed, 5 total"],
      ["oxlint broken.ts | head -n 0 ; oxlint clean.ts", "Found 0 warnings and 0 errors."],
      ["oxlint broken.ts | tail -1 ; oxlint clean.ts", "Found 0 warnings and 0 errors."],
      ["npm test | head -n 0 ; npm test tests/pass.test.mjs", "Tests: 5 passed, 5 total"],
      ["npm test tests/fail.test.mjs | tail -1 ; npm test tests/pass.test.mjs", "Tests: 5 passed, 5 total"],
      ["FOO=1 env -C /tmp npm test", "5 passing"],
      ["sudo --chdir /tmp npm test", "5 passing"],
    ]) {
      const ev = collectTurnEvidence([
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: cmd }, output: out, exitCode: 0, metadata: { exit: 0 } } }] },
      ], process.cwd());
      assert.notEqual(ev.records.find((r) => r.kind === "test" || r.kind === "lint")?.status, "success", `must stay unknown: ${cmd}`);
    }
  });

  test("S-P3-1, S-P3-5, S-P3-6, S-P3-9: P0 dotted/paren secret redaction, env-dump preflight, >2MiB YAML/single-line chunking, parenthetical prose", () => {
    // S-P3-1 [P0]: dotted secrets & parenthesized passwords MUST be redacted
    for (const [input, leaked] of [
      ["api_key: SG.AbCdEfGhIjKlMnOpQrStUv.WxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz", "SG.AbCdEf"],
      ["token: v4.local.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "v4.local."],
      ["log: api_key=SG.AbCdEfGhIjKlMnOpQrStUv.WxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz", "SG.AbCdEf"],
      ["log: token=MTIzNDU2Nzg5.GhIjKl.MnOpQrStUvWxYz1234567890", "MTIzNDU2Nzg5"],
      ["Set-Cookie: session.abc123def456", "abc123def456"],
      ["password: my.secret.passphrase", "passphrase"],
      ["password: MyPass(2024)", "MyPass(2024)"],
    ]) {
      const res = sanitizeString(input);
      assert.equal(res.sanitized.includes(leaked), false, `must redact secret in: ${input} -> ${res.sanitized}`);
    }
    assert.ok(findAllSecretsInCode("my_vault_key=SG.AbCdEfGhIjKlMnOp.WxYz0123456789", ".env", undefined, { customSensitiveKeys: ["my_vault_key"] }).length > 0);
    assert.ok(findAllSecretsInCode("my_vault_key=MyPass(2024)", ".env", undefined, { customSensitiveKeys: ["my_vault_key"] }).length > 0);

    // S-P3-9: parenthetical prose preserved
    for (const safe of [
      "The password (or passkey) is required.",
      "Please rotate your API token (see docs/auth.md).",
    ]) {
      assert.equal(sanitizeString(safe).sanitized, safe);
    }

    // S-P3-5: env-dump preflight
    for (const cmd of [
      "env FOO=1",
      "env FOO=1 > /tmp/out.txt",
      "env -u PATH",
      "env --unset=PATH",
      "docker container exec mybox env",
    ]) {
      assert.equal(assessCommandPreflight(cmd).isHighRiskEnvDump, true, `must flag env dump: ${cmd}`);
    }

    // S-P3-6: >2MiB >4KiB YAML block scalar & >512B single-line token straddling 1MiB
    const y =
      "a".repeat(1024 * 1024 - 5000) +
      "\nprivate_key: |\n" +
      "  line_of_secret_data_1234567890\n".repeat(160) +
      "  FINAL_LEAKED_YAML_SECRET_999\n" +
      "b".repeat(1024 * 1024);
    assert.equal(sanitizeObject({ buf: Buffer.from(y) }).sanitized.buf.toString("utf8").includes("FINAL_LEAKED_YAML_SECRET_999"), false);

    const s =
      "x".repeat(1024 * 1024 - 600) +
      ' token="' +
      "A".repeat(700) +
      'TAIL_SECRET_LEAKED_999"' +
      "y".repeat(1024 * 1024);
    assert.equal(sanitizeObject({ buf: Buffer.from(s) }).sanitized.buf.toString("utf8").includes("TAIL_SECRET_LEAKED_999"), false);
  });

  test("S-P3-2, S-P3-3, S-P3-4, S-P3-7, S-P3-8, S-P3-10: stubs heredoc, destructive-operations, task-completion, circuit-breaker, no-silent-failure, ghost-deps, shortcuts", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-p3-rules-"));
    try {
      fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app", dependencies: {} }));

      // S-P3-2: multi-line heredocs in no-stubs (bypasses blocked, test/fixture heredocs allowed)
      for (const badHeredoc of [
        "cat << 'EOF' > src/app.py\ndef broken():\n    pass\nEOF",
        "cat << 'EOF' > src/app.ts\nexport function broken() {\n}\nEOF",
      ]) {
        const turn = [
          { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Write" }] },
          { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: badHeredoc }, output: "ok" } }] },
        ];
        assert.equal(noStubsRule.inspect({ sessionID: "s-h1", directory: dir, currentTurn: turn, history: turn, ruleConfig: {}, isSubagent: false }).decision, "block", badHeredoc);
      }
      for (const okHeredoc of [
        "cat << 'EOF' > tests/helper.ts\nexport function mockCb() {}\nEOF",
        "cat << 'EOF' > __fixtures__/stub.ts\nthrow new NotImplementedError();\nEOF",
      ]) {
        const turn = [
          { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Write" }] },
          { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: okHeredoc }, output: "ok" } }] },
        ];
        assert.equal(noStubsRule.inspect({ sessionID: "s-h2", directory: dir, currentTurn: turn, history: turn, ruleConfig: {}, isSubagent: false }).decision, "pass", okHeredoc);
      }

      // S-P3-3: destructive-operations -unormal/-uno/-cnext FP & ! / $'...' / Windows bypasses
      for (const okCmd of [
        'git commit -unormal -m "feat: add auth"',
        'git commit -uno -m "feat: add auth"',
        'git commit -cnext -m "feat: reuse"',
      ]) {
        const turn = [
          { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Commit" }] },
          { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: okCmd }, output: "ok" } }] },
        ];
        assert.equal(destructiveOperationsRule.inspect({ sessionID: "s-d1", directory: dir, currentTurn: turn, history: turn, evidence: collectTurnEvidence(turn, dir), ruleConfig: {}, isSubagent: false }).decision, "pass", okCmd);
      }
      for (const badCmd of [
        '! git commit --no-verify -m "feat: skip hooks"',
        "git commit -m $'don\\'t' --no-verify",
        'cmd /c "git commit --no-verify -m fix"',
        'pwsh -Command "git commit --no-verify -m fix"',
      ]) {
        const turn = [
          { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Commit" }] },
          { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: badCmd }, output: "ok" } }] },
        ];
        assert.equal(destructiveOperationsRule.inspect({ sessionID: "s-d2", directory: dir, currentTurn: turn, history: turn, evidence: collectTurnEvidence(turn, dir), ruleConfig: {}, isSubagent: false }).decision, "block", badCmd);
      }

      // S-P3-4 & S-P3-7: task-completion `:strict` / `:e2e` boundary, `vitest` -> `vitest run`, piped diff/grep
      const strictFailTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Check types" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm run typecheck:strict" }, output: "TS error", exitCode: 1, metadata: { exit: 1 } } },
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm run typecheck" }, output: "ok", exitCode: 0, metadata: { exit: 0 } } },
            { type: "text", text: "Done." },
          ],
        },
      ];
      assert.equal(taskCompletionRule.inspect({ sessionID: "s-tc1", directory: dir, currentTurn: strictFailTurn, history: strictFailTurn, evidence: collectTurnEvidence(strictFailTurn, dir), ruleConfig: {}, isSubagent: false }).decision, "block");

      const vitestResolveTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix auth" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npx vitest tests/auth.test.ts" }, output: "1 failing", exitCode: 1, metadata: { exit: 1 } } },
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npx vitest run" }, output: "5 passing", exitCode: 0, metadata: { exit: 0 } } },
            { type: "text", text: "Task completed." },
          ],
        },
      ];
      assert.equal(taskCompletionRule.inspect({ sessionID: "s-tc2", directory: dir, currentTurn: vitestResolveTurn, history: vitestResolveTurn, evidence: collectTurnEvidence(vitestResolveTurn, dir), ruleConfig: {}, isSubagent: false }).decision, "pass");

      const pipedDiffTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Patch" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "diff a.txt b.txt | patch -p1" }, output: "Hunk #1 FAILED at 10.", exitCode: 1, metadata: { exit: 1 } } },
            { type: "text", text: "Done." },
          ],
        },
      ];
      assert.equal(taskCompletionRule.inspect({ sessionID: "s-tc3", directory: dir, currentTurn: pipedDiffTurn, history: pipedDiffTurn, evidence: collectTurnEvidence(pipedDiffTurn, dir), ruleConfig: {}, isSubagent: false }).decision, "block");

      const pipedCbTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Migrate" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [1, 2, 3].map((n) => ({
            type: "tool",
            tool: "bash",
            state: { status: "completed", input: { command: `grep foo package.json | node scripts/migrate.mjs --step ${n}` }, output: "Migration aborted: missing users table", exitCode: 1, metadata: { exit: 1 } },
          })),
        },
      ];
      assert.equal(circuitBreakerRule.inspect({ sessionID: "s-cb3", directory: dir, currentTurn: pipedCbTurn, history: pipedCbTurn, evidence: collectTurnEvidence(pipedCbTurn, dir), ruleConfig: {}, isSubagent: false }).decision, "block");

      // S-P3-8: ANSI-C $'...' in no-silent-failure
      const ansiMaskTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Run" }] },
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: "echo $'hello\\''; npm test || true" }, output: "ok" } }] },
      ];
      assert.equal(noSilentFailureRule.inspect({ sessionID: "s-sf", directory: dir, currentTurn: ansiMaskTurn, history: ansiMaskTurn, evidence: collectTurnEvidence(ansiMaskTurn, dir), ruleConfig: {}, isSubagent: false }).decision, "block");

      // S-P3-10: regex inside template interpolation (ghost-deps) & template `${/`/}` + `--i` (no-shortcuts)
      const ghostTplTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Edit" }] },
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "write", state: { status: "completed", input: { path: "src/a.ts", content: "const sql = `SELECT * FROM t WHERE name = '${name.replace(/'/g, \"''\")}'`;\nimport ghost from \"totally-fake-ghost-pkg\";\n" }, output: "ok" } }] },
      ];
      assert.equal(noGhostDepsRule.inspect({ sessionID: "s-gd", directory: dir, currentTurn: ghostTplTurn, history: ghostTplTurn, ruleConfig: {}, isSubagent: false }).decision, "block");

      const shortcutTplTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Edit" }] },
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "write", state: { status: "completed", input: { path: "src/a.ts", content: "const s = `backtick: ${x.replace(/`/g, \"\")}`;\n// TODO: finish later\n" }, output: "ok" } }] },
      ];
      assert.equal(noShortcutsRule.inspect({ sessionID: "s-sc1", directory: dir, currentTurn: shortcutTplTurn, history: shortcutTplTurn, ruleConfig: {}, isSubagent: false }).decision, "block");

      const decLoopTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Edit" }] },
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "write", state: { status: "completed", input: { path: "src/a.ts", content: 'for (let i = n; i > 0; --i) log("good enough");\n' }, output: "ok" } }] },
      ];
      assert.equal(noShortcutsRule.inspect({ sessionID: "s-sc2", directory: dir, currentTurn: decLoopTurn, history: decLoopTurn, ruleConfig: {}, isSubagent: false }).decision, "pass");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
