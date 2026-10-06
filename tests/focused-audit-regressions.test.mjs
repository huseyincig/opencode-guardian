import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  GuardEngine,
  collectTurnEvidence,
  evaluateTaskPolicy,
  isHallucinatedOrMalformedPackageInstall,
  isLazyCommitMessage,
  noCheatRule,
  noShortcutsRule,
} from "../dist/index.js";

test("same-call verification cannot certify a mutation that happens later in that call", () => {
  const evidence = collectTurnEvidence([{
    info: { id: "a1", role: "assistant" },
    parts: [{
      type: "tool",
      tool: "bash",
      state: {
        status: "completed",
        input: { command: "npm test && printf 'changed' > src/feature.ts" },
        metadata: { exit: 0 },
      },
    }],
  }]);

  const decision = evaluateTaskPolicy({
    turnKey: "u1",
    explicitAction: true,
    iterativeReview: false,
    requiresSourceReview: false,
    requiredVerifications: ["test"],
    requiresExplicitCompletion: true,
  }, evidence);

  assert.equal(decision.lastMutationSequence, 0);
  assert.equal(decision.verifications[0]?.status, "unknown");
});

test("empty test cheat detection covers classic callbacks and whole-file writes", () => {
  const inspect = (input) => noCheatRule.inspect({
    sessionID: "empty-test-regression",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [{
      info: { id: "a1", role: "assistant" },
      parts: [{ type: "tool", state: { input } }],
    }],
  });

  assert.equal(inspect({
    path: "/tmp/example.test.js",
    new_string: "it('does work', function() {});",
  }).decision, "block");

  assert.equal(inspect({
    path: "/tmp/new.test.js",
    content: "test('created empty', () => {});",
  }).decision, "block");
});

test("lazy commit discipline handles common short-option message forms", () => {
  for (const command of [
    'git commit -am "fix"',
    "git commit -mfix",
    'git -C /tmp/repo commit -m "fix"',
    'git -c color.ui=false commit -am "wip"',
  ]) {
    assert.equal(isLazyCommitMessage(command), true, command);
    const result = noShortcutsRule.inspect({
      sessionID: "commit-regression",
      directory: "/tmp",
      messages: [],
      ruleConfig: {},
      currentTurn: [{
        info: { id: command, role: "assistant" },
        parts: [{ type: "tool", state: { input: { command } } }],
      }],
    });
    assert.equal(result.decision, "block", command);
  }
});

test("package hallucination checks inspect real package names without rejecting local specs", () => {
  assert.equal(
    isHallucinatedOrMalformedPackageInstall("npm install express-security-patch@1.2.3"),
    true
  );
  assert.equal(
    isHallucinatedOrMalformedPackageInstall("npm install @BadScope/pkg"),
    true
  );
  assert.equal(
    isHallucinatedOrMalformedPackageInstall("npm install ./LocalPkg"),
    false
  );
  assert.equal(
    isHallucinatedOrMalformedPackageInstall("sudo npm install React"),
    true
  );
});

test("remediation disk recheck preserves configured rule behavior", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-rule-config-recheck-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.mkdirSync(path.join(directory, "src"), { recursive: true });
  const target = path.join(directory, "src", "feature.ts");
  fs.writeFileSync(target, "// shipitlater\nexport const value = 2;\n");

  const engine = new GuardEngine({
    remediationBudget: 2,
    rules: {
      "quality/no-shortcuts": {
        severity: "error",
        customPhrases: ["shipitlater"],
      },
    },
  });

  const firstTurn = [
    { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the file." }] },
    {
      info: { id: "a1", role: "assistant" },
      parts: [{
        type: "tool",
        state: {
          status: "completed",
          input: { path: target, content: "// shipitlater\nexport const value = 1;\n" },
        },
      }],
    },
  ];
  const first = await engine.inspect("s1", directory, firstTurn);
  assert.equal(first.decision, "block");
  assert.ok(first.combinedRemediationPrompt);

  const second = await engine.inspect("s1", directory, [
    ...firstTurn,
    {
      info: { id: "guardian-remediation", role: "user" },
      parts: [{
        type: "text",
        text: first.combinedRemediationPrompt,
        synthetic: true,
      }],
    },
    {
      info: { id: "a2", role: "assistant" },
      parts: [{
        type: "tool",
        state: {
          status: "completed",
          input: { path: target, new_string: "export const value = 2;" },
        },
      }],
    },
  ]);

  assert.notEqual(second.remediationStatus, "verified");
});

test("disabled update notices also disable sidebar update checks", () => {
  const source = fs.readFileSync(
    new URL("../src/tui.tsx", import.meta.url),
    "utf8"
  );
  assert.match(source, /checkUpdates\?:\s*boolean/);
  assert.match(source, /checkUpdates=\{config\.updateNotice\?\.enabled\s*!==\s*false\}/);
});
