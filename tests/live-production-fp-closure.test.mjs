import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { collectTurnEvidence } from "../dist/evidence.js";
import { noUnverifiedClaimsRule } from "../dist/rules/no-unverified-claims.js";
import { noShortcutsRule } from "../dist/rules/no-shortcuts.js";
import { noCheatRule } from "../dist/rules/no-cheat.js";
import { taskCompletionRule } from "../dist/rules/task-completion.js";
import { deniedVerification } from "../dist/locale-intents.js";

function makeTurn(userText, parts, directory = process.cwd()) {
  const messages = [
    { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: userText }] },
    { info: { id: "a1", role: "assistant" }, parts },
  ];
  const evidence = collectTurnEvidence(messages, directory);
  return {
    sessionID: "ses_live_fp",
    directory,
    messages,
    currentTurn: messages,
    evidence,
    ruleConfig: { severity: "error" },
  };
}

describe("Live Production False-Positive Closure (opencode.db v0.18.4 replay)", () => {
  test("evidence confirms per-segment exit-status echoes (`echo TC=$?`, `echo BUILD=$?`, `echo EXIT ${PIPESTATUS[0]}`) and benign `echo TEST_DONE` while rejecting spoofing", () => {
    // 1. Real worker command: typecheck + echo TC=$? + build + echo BUILD=$? + node --test | grep + echo TEST_DONE
    const fullCmd =
      'npm run typecheck; echo TC=$?; npm run build; echo BUILD=$?; node --test tests/unit/a.test.mjs 2>&1 | grep -E "^ℹ (tests|pass|fail)|✖"; echo TEST_DONE';
    const fullOut = [
      "TC=0",
      "wrote dist/schema.json",
      "BUILD=0",
      "ℹ tests 674",
      "ℹ pass 674",
      "ℹ fail 0",
      "TEST_DONE",
    ].join("\n");
    const ev1 = collectTurnEvidence(
      [{ info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: fullCmd }, output: fullOut, metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(ev1.records.find((r) => r.kind === "typecheck")?.status, "success");
    assert.equal(ev1.records.find((r) => r.kind === "build")?.status, "success");
    assert.equal(ev1.records.find((r) => r.kind === "test")?.status, "success");

    // 2. Real worker command with non-zero exit echo (`EXIT=1`) MUST be classified as failure, NOT masked!
    const failEv = collectTurnEvidence(
      [{ info: { id: "a2", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: "node --test tests/a.test.mjs; echo EXIT=$?" }, output: "✖ failing\nEXIT=1", metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(failEv.records.find((r) => r.kind === "test")?.status, "failure");

    // 3. Hardcoded literal `echo TC=0` (not `$?`) must NEVER confirm success!
    const spoofEv = collectTurnEvidence(
      [{ info: { id: "a3", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: "npm run typecheck; echo TC=0" }, output: "TC=0", metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(spoofEv.records.find((r) => r.kind === "typecheck")?.status, "unknown");

    // 4. Clean `tail -20` / `tail -8` on typecheck & build confirm success when error-free; `head` or errors stay unknown
    const tailEv = collectTurnEvidence(
      [{ info: { id: "a4", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: "cd . && npm run typecheck 2>&1 | tail -20; npm run build 2>&1 | tail -8" }, output: "wrote dist/app.js", metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(tailEv.records.find((r) => r.kind === "typecheck")?.status, "success");
    assert.equal(tailEv.records.find((r) => r.kind === "build")?.status, "success");

    const tsErrEv = collectTurnEvidence(
      [{ info: { id: "a5", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: "npm run typecheck 2>&1 | tail -20" }, output: "src/a.ts(1,1): error TS2322: Type string is not assignable", metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(tsErrEv.records.find((r) => r.kind === "typecheck")?.status, "unknown");

    // 5. Upstream AFT pipeline failure note invalidates piped verification
    const aftFailEv = collectTurnEvidence(
      [{ info: { id: "a6", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: "npm run build 2>&1 | tail -10" }, output: "ok\nnote: `npm` (segment 1 of 2) exited 1; the pipeline's exit code is `tail`'s.", metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(aftFailEv.records.find((r) => r.kind === "build")?.status, "unknown");

    // 6. PIPESTATUS[0] confirmation
    const psEv = collectTurnEvidence(
      [{ info: { id: "a7", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: "node --test tests/a.test.mjs 2>&1 | tail -n 60; echo EXIT ${PIPESTATUS[0]}" }, output: "ℹ tests 10\nℹ pass 10\nℹ fail 0\nEXIT 0", metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(psEv.records.find((r) => r.kind === "test")?.status, "success");
  });

  test("no-shortcuts does not false-flag observed/context-pruned placeholder reports while still catching authored placeholders", async () => {
    const pruned = makeTurn("Implement task A2", [
      {
        type: "text",
        text: "I couldn't do the task because I never received its instructions. The task text was pruned from my context. All I can see is a placeholder starting with `<!-- hi-task:123 -->`.",
      },
    ]);
    const res1 = await noShortcutsRule.inspect(pruned);
    assert.equal(res1.findings.length, 0);

    const authored = makeTurn("Implement task A2", [
      { type: "text", text: "I left a placeholder implementation for now and will finish it later." },
    ]);
    const res2 = await noShortcutsRule.inspect(authored);
    assert.equal(res2.decision, "block");
  });

  test("no-cheat does not false-flag balanced if/else assertions while still catching unbalanced conditional assertions", async () => {
    const balanced = makeTurn("Add role tests", [
      {
        type: "tool",
        tool: "write",
        state: {
          status: "completed",
          input: {
            path: "tests/unit/role-kinds.test.mjs",
            content:
              'test("roles", () => {\n  for (const [role, def] of roles) {\n    if (def.access === "primary") {\n      assert.equal(def.kinds.length, 0, role);\n    } else {\n      assert.ok(def.kinds.length > 0, role);\n    }\n  }\n});\n',
          },
          output: "ok",
        },
      },
      { type: "text", text: "Added role tests." },
    ]);
    const res1 = await noCheatRule.inspect(balanced);
    assert.equal(res1.findings.length, 0);

    const unbalanced = makeTurn("Add role tests", [
      {
        type: "tool",
        tool: "write",
        state: {
          status: "completed",
          input: {
            path: "tests/unit/role-kinds.test.mjs",
            content: 'test("roles", () => {\n  if (result) { expect(result).toBe(1); }\n});\n',
          },
          output: "ok",
        },
      },
      { type: "text", text: "Added role tests." },
    ]);
    const res2 = await noCheatRule.inspect(unbalanced);
    assert.ok(res2.findings.some((f) => f.pattern === "conditional assertion"));
  });

  test("task-completion accepts compound read-only existence probes (`ls -d`) and retried `todowrite` success", async () => {
    const turn = makeTurn("Verify patches removed and update todos", [
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "completed",
          input: {
            command: "cd . && grep -n -i 'patches' README.md || echo CLEAN; git status --porcelain; ls -d patches screenshot",
          },
          output: "CLEAN\nls: cannot access 'patches': No such file or directory",
          metadata: { exit: 2 },
        },
      },
      {
        type: "tool",
        tool: "todowrite",
        state: { status: "error", input: { todos: [1, 2, 3, 4, 5, 6, 7, 8, 9] }, error: "limit 8" },
      },
      {
        type: "tool",
        tool: "todowrite",
        state: { status: "completed", input: { todos: [1, 2, 3, 4, 5, 6, 7, 8] }, output: "ok" },
      },
      { type: "text", text: "Silme doğrulandı ve görev listesi güncellendi." },
    ]);
    const res = await taskCompletionRule.inspect(turn);
    assert.equal(res.decision, "pass");
    assert.equal(res.findings.length, 0);
  });

  test("no-unverified-claims respects manager verification delegation and honest unverified disclosure without allowing fake test-pass lies", async () => {
    assert.equal(deniedVerification("Implement change and leave verification to manager.", "test"), true);
    assert.equal(deniedVerification("Değişikliği yap, doğrulamayı yöneticiye bırak.", "test"), true);

    const honest = makeTurn("Implement change", [
      {
        type: "text",
        text: "The bug is fixed in `src/a.ts`. Doğrulama testlerini çalıştırmadım, yöneticiye devrediyorum.",
      },
    ]);
    const res1 = await noUnverifiedClaimsRule.inspect(honest);
    assert.equal(res1.findings.length, 0);

    // Explicit false claim that tests passed STILL triggers even if user delegated verification!
    const fakePass = makeTurn("Implement change and leave verification to manager.", [
      { type: "text", text: "All tests pass and build succeeded." },
    ]);
    const res2 = await noUnverifiedClaimsRule.inspect(fakePass);
    assert.ok(res2.findings.length > 0);
  });

  test("evidence handles heredoc file writes followed by typecheck/build/test and zero-match grep exit echo without spoofing regressions", () => {
    // 1. Heredoc append to .test.mjs followed by typecheck | tail -5, build | tail -3, node --test | tail -15
    const heredocCmd = [
      "cat >> tests/unit/test-scope.test.mjs <<'EOF'",
      'test("composer, ctest and cmake", () => {',
      '  for (const c of ["ctest"]) { assert.equal(c, "ctest"); }',
      "});",
      "EOF",
      "npm run typecheck 2>&1 | tail -5; npm run build 2>&1 | tail -3; node --test tests/unit/test-scope.test.mjs 2>&1 | tail -15",
    ].join("\n");
    const heredocOut = [
      "✔ composer, ctest and cmake (0.14ms)",
      "ℹ tests 76",
      "ℹ suites 0",
      "ℹ pass 76",
      "ℹ fail 0",
      "ℹ cancelled 0",
      "ℹ skipped 0",
      "ℹ todo 0",
    ].join("\n");
    const turn = makeTurn("Add PHP/C++ scope test", [
      {
        type: "tool",
        tool: "shell",
        state: { status: "completed", input: { command: heredocCmd }, output: heredocOut, metadata: { exit: 0 } },
      },
      { type: "text", text: "Typecheck and build passed; 76 of 76 tests passed." },
    ]);
    assert.equal(turn.evidence.records.find((r) => r.kind === "typecheck")?.status, "success");
    assert.equal(turn.evidence.records.find((r) => r.kind === "build")?.status, "success");
    assert.equal(turn.evidence.records.find((r) => r.kind === "test")?.status, "success");
    const res = noUnverifiedClaimsRule.inspect(turn);
    assert.equal(res.findings.length, 0);

    // 2. Mutation AFTER verification in the same command MUST STILL invalidate freshness!
    const postMutTurn = makeTurn("Verify", [
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "completed",
          input: { command: "npm run typecheck && echo x >> src/app.ts" },
          output: "",
          metadata: { exit: 0 },
        },
      },
      { type: "text", text: "Typecheck passed." },
    ]);
    const postMutRes = noUnverifiedClaimsRule.inspect(postMutTurn);
    assert.ok(postMutRes.findings.length > 0);

    // 3. `npx tsc --noEmit; echo tsc=$?; node --test ... | tail -12; grep ... file; echo grep=$?` with grep=1
    const grepCmd =
      "npx tsc --noEmit; echo tsc=$?; node --test tests/unit/a.test.mjs 2>&1 | tail -12; grep -nE 'legacy' tests/unit/a.test.mjs; echo grep=$?";
    const grepOut = "tsc=0\nℹ tests 16\nℹ pass 16\nℹ fail 0\ngrep=1";
    const grepEv = collectTurnEvidence(
      [{ info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: grepCmd }, output: grepOut, metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(grepEv.records.find((r) => r.kind === "typecheck")?.status, "success");
    assert.equal(grepEv.records.find((r) => r.kind === "test")?.status, "success");

    // 4. `tail -2` confirms clean typecheck; `tail -1` stays unknown
    const tail2Ev = collectTurnEvidence(
      [{ info: { id: "a2", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: "npm run typecheck 2>&1 | tail -2; echo tc=$?" }, output: "npm notice run tsc --noEmit\ntc=0", metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(tail2Ev.records.find((r) => r.kind === "typecheck")?.status, "success");

    const tail1Ev = collectTurnEvidence(
      [{ info: { id: "a3", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: "npm run typecheck 2>&1 | tail -1" }, output: "ok", metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(tail1Ev.records.find((r) => r.kind === "typecheck")?.status, "unknown");
  });

  test("no-unverified-claims handles clean compound git-status, scoped subset tests, partial X-of-Y reports, .test.mjs edits, and subagent verification relay", async () => {
    // 1. Compound `git status --short --branch && echo '---LOG---' && git log --oneline -5` + `[task bash-...]`
    const gitTurn = makeTurn("Check repo status", [
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "completed",
          input: { command: "git status --short --branch && echo '---LOG---' && git log --oneline -2" },
          output: "## main...origin/main\n---LOG---\n719819d1 fix mesh standby\ne1a574d2 tighten lock\n[task bash-1234abcd]",
          metadata: { exit: 0 },
        },
      },
      { type: "text", text: "Çalışma ağacı temiz." },
    ]);
    assert.equal((await noUnverifiedClaimsRule.inspect(gitTurn)).findings.length, 0);

    // Dirty `git status --short` STILL contradicts "working tree is clean"!
    const dirtyGitTurn = makeTurn("Check repo status", [
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "completed",
          input: { command: "git status --short --branch" },
          output: "## main...origin/main\n M src/index.ts\n[task bash-1234abcd]",
          metadata: { exit: 0 },
        },
      },
      { type: "text", text: "Working tree is clean." },
    ]);
    assert.equal((await noUnverifiedClaimsRule.inspect(dirtyGitTurn)).decision, "block");

    // 2. Scoped subset test pass (38/38 pass) + honest report of 3 out-of-scope failures in another file
    const scopedTurn = makeTurn("Implement capability policy", [
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "completed",
          input: { command: "npm run build 2>&1 | tail -10; node --test tests/unit/new.test.mjs 2>&1 | tail -15" },
          output: "wrote dist/app.js\nℹ tests 38\nℹ pass 38\nℹ fail 0",
          metadata: { exit: 0 },
        },
      },
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "completed",
          input: { command: "node --test tests/unit/config-registry.test.mjs 2>&1 | grep -E '^ℹ (tests|pass|fail)|✖'" },
          output: "ℹ tests 28\nℹ pass 25\nℹ fail 3",
          metadata: { exit: 0 },
        },
      },
      {
        type: "text",
        text: "Build passes, and the 38 new tests pass. 3 tests in config-registry.test.mjs fail because that file is outside my scope.",
      },
    ]);
    assert.equal((await noUnverifiedClaimsRule.inspect(scopedTurn)).findings.length, 0);

    // Universal claim "All tests pass" when later test failed MUST STILL fail!
    const universalLie = makeTurn("Implement capability policy", [
      ...scopedTurn.currentTurn[1].parts.slice(0, 2),
      { type: "text", text: "All tests pass." },
    ]);
    assert.ok((await noUnverifiedClaimsRule.inspect(universalLie)).findings.length > 0);

    // 3. Partial report "781 of 786 targeted tests pass" + `.test.mjs` perl edit after clean tsc
    const partialTurn = makeTurn("Rename skill", [
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "completed",
          input: { command: "npx tsc; echo tsc=$?" },
          output: "tsc=0",
          metadata: { exit: 0 },
        },
      },
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "completed",
          input: { command: "cd . && perl -pi -e 's/old/new/' tests/unit/skill.test.mjs" },
          output: "",
          metadata: { exit: 0 },
        },
      },
      { type: "text", text: "Typecheck passes. 781 of 786 targeted tests pass." },
    ]);
    assert.equal((await noUnverifiedClaimsRule.inspect(partialTurn)).findings.length, 0);

    // 4. Coordinator summarizing a worker's `<background-result>` verification without local edits
    const mgrMessages = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Implement gate via worker" }] },
      {
        info: { id: "s1", role: "user" },
        parts: [
          {
            type: "text",
            synthetic: true,
            metadata: { source: "subagent", childID: "ses_child", state: "completed" },
            text: "<background-result kind=\"subagent\">npm run typecheck exit 0; node --test role-capability-gate.test.mjs: 11 of 11 pass.</background-result>",
          },
        ],
      },
      {
        info: { id: "a1", role: "assistant" },
        parts: [{ type: "text", text: "Uygulama geldi ve denetledim: 11 yeni test PASS, typecheck temiz." }],
      },
    ];
    const mgrRes = await noUnverifiedClaimsRule.inspect({
      sessionID: "ses_mgr",
      directory: process.cwd(),
      messages: mgrMessages,
      currentTurn: mgrMessages,
      evidence: collectTurnEvidence(mgrMessages, process.cwd()),
      ruleConfig: { severity: "error" },
    });
    assert.equal(mgrRes.findings.length, 0);
  });

  test("no-cheat allows guard-clause continue loop assertions, no-shortcuts allows neutral placeholder fixture prose, and task-completion resolves tool retries and policy refusals", async () => {
    const guardLoop = makeTurn("Add role kinds tests", [
      {
        type: "tool",
        tool: "write",
        state: {
          status: "completed",
          input: {
            path: "tests/unit/role-kinds.test.mjs",
            content:
              'test("roles", () => {\n  for (const [role, def] of roles) {\n    if (def.access === "primary") {\n      assert.equal(def.kinds.length, 0, role);\n      continue;\n    }\n    assert.ok(def.kinds.length > 0, role);\n  }\n});\n',
          },
          output: "ok",
        },
      },
      { type: "text", text: "Added test." },
    ]);
    assert.equal((await noCheatRule.inspect(guardLoop)).findings.length, 0);

    const neutralPlaceholder = makeTurn("Sanitize fixtures", [
      { type: "text", text: "449 satır nötr placeholder’a çevrildi; üçüncü taraf marka adları temizlendi." },
    ]);
    assert.equal((await noShortcutsRule.inspect(neutralPlaceholder)).findings.length, 0);

    const policyAndRetryTurn = makeTurn("Delegate fix", [
      {
        type: "tool",
        tool: "edit",
        state: {
          status: "error",
          input: { filePath: "src/a.ts", oldString: "a", newString: "b" },
          error: "[policy] the primary manager session is a coordinator and cannot write src/a.ts directly; delegate this write to a worker.",
        },
      },
      {
        type: "tool",
        tool: "subagent",
        state: {
          status: "error",
          input: { prompt: "fix src/a.ts" },
          error: 'invalid arguments for tool "subagent": - agent: missing key',
        },
      },
      {
        type: "tool",
        tool: "subagent",
        state: {
          status: "completed",
          input: { agent: "coder", prompt: "fix src/a.ts" },
          output: "Delegated.",
        },
      },
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "error",
          input: { command: "grep -rn foo src/" },
          error: "do not search code by running grep/rg in shell — use the grep tool instead",
        },
      },
      {
        type: "tool",
        tool: "grep",
        state: {
          status: "completed",
          input: { pattern: "foo", path: "src" },
          output: "src/a.ts:1:foo",
        },
      },
      { type: "text", text: "Delegated to worker and verified search." },
    ]);
    const tcRes = await taskCompletionRule.inspect(policyAndRetryTurn);
    assert.equal(tcRes.decision, "pass");
    assert.equal(tcRes.findings.length, 0);

    // `npm run check` failing then succeeding via `cd <sameDir> && npm run check` resolves cleanly
    const cwdDir = process.cwd();
    const checkRetryTurn = makeTurn("Run full check", [
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "completed",
          input: { command: "npm run check", cwd: cwdDir },
          output: "1 failing test",
          metadata: { exit: 1 },
        },
      },
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "completed",
          input: { command: `cd ${cwdDir} && npm run check` },
          output: "all checks passed",
          metadata: { exit: 0 },
        },
      },
      { type: "text", text: "Full check now passes." },
    ], cwdDir);
    const checkRetryRes = await taskCompletionRule.inspect(checkRetryTurn);
    assert.equal(checkRetryRes.decision, "pass");
    assert.equal(checkRetryRes.findings.length, 0);
  });
});
