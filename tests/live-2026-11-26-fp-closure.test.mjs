import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { collectTurnEvidence } from "../dist/evidence.js";
import { noUnverifiedClaimsRule } from "../dist/rules/no-unverified-claims.js";
import { noShortcutsRule } from "../dist/rules/no-shortcuts.js";
import { noCheatRule } from "../dist/rules/no-cheat.js";
import { noSilentFailureRule } from "../dist/rules/no-silent-failure.js";
import { noEvasionRule } from "../dist/rules/no-evasion.js";
import { noSecretsRule } from "../dist/rules/no-secrets.js";
import { taskCompletionRule } from "../dist/rules/task-completion.js";

function makeTurn(userText, parts, directory = process.cwd()) {
  const messages = [
    { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: userText }] },
    { info: { id: "a1", role: "assistant" }, parts },
  ];
  const evidence = collectTurnEvidence(messages, directory);
  return {
    sessionID: "ses_live_20261126",
    directory,
    messages,
    currentTurn: messages,
    evidence,
    ruleConfig: { severity: "error" },
  };
}

describe("2026-11-26 Live Production False-Positive & Remediation Closure (v0.18.6)", () => {
  test("evidence confirms clean `lint | tail -N` (N>=2) and multi-word exit-status echoes (`echo \"lint exit=${PIPESTATUS[0]}\"`) while rejecting errors and hardcoded 0", () => {
    // 1. `npm run lint 2>&1 | tail -3` with clean output
    const lintTailCmd =
      'npm run build >/dev/null 2>&1; echo build=$?; npm run typecheck >/dev/null 2>&1; echo tc=$?; npm run lint 2>&1 | tail -3; node --test tests/unit/a.test.mjs 2>&1 | grep -E "^ℹ|✖"';
    const lintTailOut = [
      "build=0",
      "tc=0",
      "Found 0 warnings and 0 errors.",
      "Finished in 30ms on 515 files.",
      "ℹ tests 76",
      "ℹ pass 76",
      "ℹ fail 0",
    ].join("\n");
    const ev1 = collectTurnEvidence(
      [{ info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: lintTailCmd }, output: lintTailOut, metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(ev1.records.find((r) => r.kind === "build")?.status, "success");
    assert.equal(ev1.records.find((r) => r.kind === "typecheck")?.status, "success");
    assert.equal(ev1.records.find((r) => r.kind === "lint")?.status, "success");
    assert.equal(ev1.records.find((r) => r.kind === "test")?.status, "success");
    const claimTurn = makeTurn("Verify changes", [
      { type: "tool", tool: "shell", state: { status: "completed", input: { command: lintTailCmd }, output: lintTailOut, metadata: { exit: 0 } } },
      { type: "text", text: "Build, typecheck, lint pass; 76 tests pass." },
    ]);
    assert.equal(noUnverifiedClaimsRule.inspect(claimTurn).findings.length, 0);

    // 2. Multi-word quoted exit echo `echo "lint exit: ${PIPESTATUS[0]}"` + `node --test | grep`
    const multiWordCmd =
      'npm run lint 2>&1 | tail -6; echo "lint exit: ${PIPESTATUS[0]}"; node --import ./tests/support/isolate-env.mjs --test tests/unit/completion-evidence.test.mjs 2>&1 | grep -E "^ℹ (tests|pass|fail)|✖"';
    const multiWordOut = [
      "Found 0 warnings and 0 errors.",
      "lint exit: 0",
      "ℹ tests 62",
      "ℹ pass 62",
      "ℹ fail 0",
    ].join("\n");
    const ev2 = collectTurnEvidence(
      [{ info: { id: "a2", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: multiWordCmd }, output: multiWordOut, metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(ev2.records.find((r) => r.kind === "lint")?.status, "success");
    assert.equal(ev2.records.find((r) => r.kind === "test")?.status, "success");

    // 3. Multi-word `echo "lint exit=${PIPESTATUS[0]}"` + `typecheck exit=${PIPESTATUS[0]}` + `build exit=${PIPESTATUS[0]}`
    const multi3Cmd =
      'npm run lint 2>&1 | tail -3; echo "lint exit=${PIPESTATUS[0]}"; npm run typecheck 2>&1 | tail -3; echo "typecheck exit=${PIPESTATUS[0]}"; npm run build 2>&1 | tail -1; echo "build exit=${PIPESTATUS[0]}"';
    const multi3Out = "Found 0 warnings and 0 errors.\nlint exit=0\ntypecheck exit=0\nbuild exit=0";
    const ev3 = collectTurnEvidence(
      [{ info: { id: "a3", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: multi3Cmd }, output: multi3Out, metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(ev3.records.find((r) => r.kind === "lint")?.status, "success");
    assert.equal(ev3.records.find((r) => r.kind === "typecheck")?.status, "success");
    assert.equal(ev3.records.find((r) => r.kind === "build")?.status, "success");

    // 4. Negative: lint with actual warning/error count stays unknown, and hardcoded `echo "lint exit=0"` stays unknown
    const lintFailEv = collectTurnEvidence(
      [{ info: { id: "a4", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: "npm run lint 2>&1 | tail -3" }, output: "Found 2 warnings and 1 error.", metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(lintFailEv.records.find((r) => r.kind === "lint")?.status, "unknown");

    const spoofEv = collectTurnEvidence(
      [{ info: { id: "a5", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: 'npm run lint 2>&1 | tail -1; echo "lint exit=0"' }, output: "lint exit=0", metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(spoofEv.records.find((r) => r.kind === "lint")?.status, "unknown");

    // 5. Negative: non-zero `lint exit=1` promotes directly to failure!
    const lintNonZeroEv = collectTurnEvidence(
      [{ info: { id: "a6", role: "assistant" }, parts: [{ type: "tool", tool: "shell", state: { status: "completed", input: { command: 'npm run lint 2>&1 | tail -3; echo "lint exit=${PIPESTATUS[0]}"' }, output: "lint exit=1", metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(lintNonZeroEv.records.find((r) => r.kind === "lint")?.status, "failure");
  });

  test("no-shortcuts ignores negated, sentinel/technical placeholders, past-tense temporary stash, and golden test-fixture comments while blocking real shortcuts", async () => {
    const cleanReports = [
      "50 F satırı (17 uygulanmış/7 kısmi/26 yok), F41 Secret [REDACTED], wc -w 2912, placeholder yok.",
      "14/14 başlık, 50/50 F satırı doğrulandı; placeholder yoktur, placeholder/yabancı token yok.",
      "Doğrulama: yer-tutucu (TODO/placeholder) yok; placeholder taraması temiz; placeholder/TODO/TBD scan clean.",
      "§10’dan grup/ilk-kayıt çıkarıldı; `\\|` placeholder ile bölündü, markdown link temizlendi.",
      "The literal placeholder is now a private-use character instead of a printable token.",
      "A temporary git stash of the source file was used for the red-green check and restored.",
      "Derives skill IDs from dist instead of the hardcoded 13; replaced the hardcoded count.",
      "The unused parameter was in my first version of the test, and my later edit removed it.",
    ];
    for (const text of cleanReports) {
      const res = await noShortcutsRule.inspect(makeTurn("Generate report", [{ type: "text", text }]));
      assert.equal(res.findings.length, 0, `unexpected finding for: ${text}`);
    }

    // Comments in code/tests: sanitizer marker placeholder & test golden hard-coded fixture
    const codeTurn = makeTurn("Add sanitizer tests", [
      {
        type: "tool",
        tool: "edit",
        state: {
          status: "completed",
          input: {
            filePath: "tests/unit/v2-task-tool.test.mjs",
            newString: [
              "// Durable-state record must match an independently produced digest (node:crypto + a hard-coded golden).",
              "// Uses the registered literal rather than a hand-rolled regex or a pre-masked placeholder.",
              "// Otherwise fail closed to a placeholder that matches only the marker text.",
              'assert.equal(digest, "abc123");',
            ].join("\n"),
          },
          output: "ok",
        },
      },
      { type: "text", text: "Added sanitizer tests." },
    ]);
    assert.equal((await noShortcutsRule.inspect(codeTurn)).findings.length, 0);

    // Negative: real shortcut/deferred placeholder in production code or prose STILL blocks/flags
    const realShortcut = makeTurn("Implement feature", [
      { type: "text", text: "I left a placeholder implementation for now and will finish it later." },
    ]);
    assert.equal((await noShortcutsRule.inspect(realShortcut)).decision, "block");
  });

  test("task-completion ignores read invalid_range, scope/boundary/inspectable policy refusals, already-present edits, and lists concrete unresolved failures in remediationPrompt", async () => {
    const benignTurn = makeTurn("Triage G01 and add tests", [
      {
        type: "tool",
        tool: "read",
        state: {
          status: "error",
          input: { filePath: "src/a.ts", startLine: 326, endLine: 400 },
          error: "invalid_range: startLine 326 is past the end of the file (172 lines); no lines selected.",
        },
      },
      {
        type: "tool",
        tool: "grep",
        state: {
          status: "error",
          input: { pattern: "foo", path: "docs/decision-table.md" },
          error: "grep: search path does not exist: /repo/docs/decision-table.md",
        },
      },
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "error",
          input: { command: "cat > /tmp/opencode/exp.mjs <<'EOF'\nconsole.log(1)\nEOF" },
          error: "[opencode-hi] write target is outside the project boundary (target ../../../tmp/opencode/exp.mjs, tool shell)",
        },
      },
      {
        type: "tool",
        tool: "edit",
        state: {
          status: "error",
          input: { filePath: "tests/unit/other.test.mjs", newString: "x" },
          error: "[opencode-hi] write target tests/unit/other.test.mjs is outside task 0Vc5dYG3R5aj8FVaDI scope (tool edit)",
        },
      },
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "error",
          input: { command: "cat >> tests/unit/a.test.mjs <<'EOF'\n// x\nEOF" },
          error: "[opencode-hi] write target is not inspectable for task 0Vc5rh2vhtFmJf8eKU",
        },
      },
      {
        type: "tool",
        tool: "edit",
        state: {
          status: "error",
          input: { filePath: "tests/unit/a.test.mjs", edits: "invalid-json" },
          error: "edit: 'edits' must contain valid JSON representing an array",
        },
      },
      {
        type: "tool",
        tool: "edit",
        state: {
          status: "completed",
          input: { filePath: "tests/unit/a.test.mjs", edits: [{ oldString: "a", newString: "b" }] },
          output: "ok",
        },
      },
      {
        type: "tool",
        tool: "edit",
        state: {
          status: "error",
          input: { filePath: "tests/unit/a.test.mjs", oldString: "x", newString: "y" },
          error: "batch: edit[0] match not found\nnewString is already present at line 555",
        },
      },
      { type: "text", text: "Triage complete and all in-scope edits applied." },
    ]);
    const benignRes = await taskCompletionRule.inspect(benignTurn);
    assert.equal(benignRes.decision, "pass");
    assert.equal(benignRes.findings.length, 0);

    // Negative: real unresolved command failure MUST still block AND include the specific failure details in remediationPrompt!
    const realFailTurn = makeTurn("Fix build", [
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "completed",
          input: { command: "npm run build" },
          output: "src/app.ts(10,5): error TS2304: Cannot find name 'missingVar'.",
          metadata: { exit: 2 },
        },
      },
      { type: "text", text: "Done." },
    ]);
    const realFailRes = await taskCompletionRule.inspect(realFailTurn);
    assert.equal(realFailRes.decision, "block");
    assert.match(realFailRes.remediationPrompt ?? "", /unresolved build failure/i);
    assert.match(realFailRes.remediationPrompt ?? "", /TS2304|npm run build/i);
  });

  test("no-evasion accepts git stash baseline verification for pre-existing failure claims while still blocking unproven evasion", async () => {
    const provenTurn = makeTurn("Fix G05 coordination tests", [
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "completed",
          input: { command: "git stash push -m baseline-check && node --test tests/tui/attention-model.test.mjs; rc=$?; git stash pop; exit $rc" },
          output: "Saved working directory\n✖ attention-model\nDropped refs/stash@{0}",
          metadata: { exit: 1 },
        },
      },
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "completed",
          input: { command: "git stash list" },
          output: "",
          metadata: { exit: 0 },
        },
      },
      {
        type: "text",
        text: "Pre-existing failure in `tests/tui/attention-model.test.mjs` (1 vs 2), identical with my edits stashed.",
      },
    ]);
    assert.equal((await noEvasionRule.inspect(provenTurn)).decision, "pass");

    // Negative: claiming pre-existing failure with NO baseline command MUST still block!
    const unprovenTurn = makeTurn("Fix G05 coordination tests", [
      {
        type: "text",
        text: "Pre-existing failure in `tests/tui/attention-model.test.mjs`.",
      },
    ]);
    assert.equal((await noEvasionRule.inspect(unprovenTurn)).decision, "block");
  });

  test("no-silent-failure ignores commented rollback catch immediately followed by throw, while still flagging bare empty catch", async () => {
    const rollbackTurn = makeTurn("Harden sqlite transaction", [
      {
        type: "tool",
        tool: "edit",
        state: {
          status: "completed",
          input: {
            filePath: "src/storage/sqlite.ts",
            newString: [
              "try {",
              '  db.exec("BEGIN");',
              "  run();",
              '  db.exec("COMMIT");',
              "} catch (error) {",
              '  try { db.exec("ROLLBACK"); } catch { // rollback failure leaves the original error as the cause',
              "  }",
              "  throw error;",
              "}",
            ].join("\n"),
          },
          output: "ok",
        },
      },
      { type: "text", text: "Updated transaction rollback." },
    ]);
    assert.equal((await noSilentFailureRule.inspect(rollbackTurn)).findings.length, 0);

    // Markdown audit report quoting `.catch(()=>{})` is NOT executable JS code
    const mdDocTurn = makeTurn("Write audit report", [
      {
        type: "tool",
        tool: "write",
        state: {
          status: "completed",
          input: {
            filePath: "docs/audit-report.md",
            content: "- Hata yutma noktaları: `saveInflight().catch(()=>{})`, RPC `emit.catch(()=>{})`.",
          },
          output: "ok",
        },
      },
      { type: "text", text: "Report written." },
    ]);
    assert.equal((await noSilentFailureRule.inspect(mdDocTurn)).findings.length, 0);

    // Negative: bare empty catch swallowing error MUST still be flagged!
    const swallowedTurn = makeTurn("Update handler", [
      {
        type: "tool",
        tool: "edit",
        state: {
          status: "completed",
          input: {
            filePath: "src/app.ts",
            newString: "try { saveOrder(); } catch (err) { }",
          },
          output: "ok",
        },
      },
      { type: "text", text: "Updated handler." },
    ]);
    assert.ok((await noSilentFailureRule.inspect(swallowedTurn)).findings.length > 0);
  });

  test("no-cheat allows typeof type-narrowing guard alongside sibling unconditional assertions while still flagging lone conditional assertion", async () => {
    const descriptorScanTurn = makeTurn("Add sanitizer property descriptor tests", [
      {
        type: "tool",
        tool: "write",
        state: {
          status: "completed",
          input: {
            filePath: "tests/unit/sanitizer-coverage.test.mjs",
            content: [
              'test("no secret leaks in descriptors", () => {',
              "  for (const k of Object.keys(obj)) {",
              "    const d = Object.getOwnPropertyDescriptor(obj, k);",
              '    assert.equal(d.get, undefined, "no accessor survives");',
              '    if (typeof d.value === "string") assert.ok(!d.value.includes(FAKE), k);',
              "    assert.ok(!k.includes(FAKE));",
              "  }",
              "});",
            ].join("\n"),
          },
          output: "ok",
        },
      },
      { type: "text", text: "Added test." },
    ]);
    assert.equal((await noCheatRule.inspect(descriptorScanTurn)).findings.length, 0);

    // Negative: lone `if (result) { expect(result).toBe(1); }` with no sibling assertions still flags!
    const loneCondTurn = makeTurn("Add test", [
      {
        type: "tool",
        tool: "write",
        state: {
          status: "completed",
          input: {
            filePath: "tests/unit/foo.test.mjs",
            content: 'test("foo", () => {\n  if (result) { expect(result).toBe(1); }\n});',
          },
          output: "ok",
        },
      },
      { type: "text", text: "Added test." },
    ]);
    assert.ok((await noCheatRule.inspect(loneCondTurn)).findings.some((f) => f.pattern === "conditional assertion"));
  });

  test("no-secrets skips rejected/errored tool calls that never wrote to disk while still blocking executed secret writes", async () => {
    const blockedWriteTurn = makeTurn("Add PEM sanitizer test", [
      {
        type: "tool",
        tool: "shell",
        state: {
          status: "error",
          input: { command: "cat >> tests/unit/sanitizer-coverage.test.mjs <<'EOF'\nconst pem = '-----BEGIN PRIVATE KEY-----\\nfake\\n-----END PRIVATE KEY-----';\nEOF" },
          error: "[opencode-hi] write target is not inspectable for task 0Vc5rh2vhtFmJf8eKU",
        },
      },
      { type: "text", text: "Used edit tool instead." },
    ]);
    assert.equal((await noSecretsRule.inspect(blockedWriteTurn)).decision, "pass");

    // Negative: completed write containing a private key header MUST still block!
    const realSecretTurn = makeTurn("Add config", [
      {
        type: "tool",
        tool: "write",
        state: {
          status: "completed",
          input: {
            filePath: "src/keys.ts",
            content: "export const key = `-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw\n-----END PRIVATE KEY-----`;",
          },
          output: "ok",
        },
      },
      { type: "text", text: "Wrote key." },
    ]);
    assert.equal((await noSecretsRule.inspect(realSecretTurn)).decision, "block");
  });
});
