import test from "node:test";
import assert from "node:assert/strict";
import { collectTurnEvidence } from "../dist/evidence.js";
import { instructionFidelityRule } from "../dist/rules/instruction-fidelity.js";
import { noEvasionRule } from "../dist/rules/no-evasion.js";
import { circuitBreakerRule } from "../dist/rules/circuit-breaker.js";
import { destructiveOperationsRule } from "../dist/rules/destructive-operations.js";

function human(text, extra = {}) {
  return { info: { role: "user", id: "human" }, parts: [{ type: "text", text, ...extra }] };
}
function tool(command, exit = 0, output = "observed output") {
  return { type: "tool", tool: "bash", state: { status: "completed", input: { command }, metadata: { exit }, output } };
}
function context(request, parts = [], prior = []) {
  const currentTurn = [...prior, human(request), { info: { role: "assistant", id: "assistant" }, parts }];
  return { sessionID: "scope-retry", directory: process.cwd(), messages: currentTurn, currentTurn,
    ruleConfig: {}, evidence: collectTurnEvidence(currentTurn) };
}
function inspectDestructive(request, command) {
  return destructiveOperationsRule.inspect(context(request, [tool(command)]));
}

test("explicit English and Turkish research-only constraints reject observed mutations", () => {
  for (const request of ["Research only. Do not edit files.", "Sadece araştır; dosyaları değiştirme.", "Analyze only; no edits.", "Sadece araştırma yap; kod yazma.", "Do not make changes to files; investigate first."]) {
    for (const part of [
      { type: "tool", tool: "write", state: { status: "completed", input: { filePath: "src/a.ts", content: "export const a = 1;" }, output: "written" } },
      tool("npm install some-package"), tool("git push origin main"),
    ]) {
      const result = instructionFidelityRule.inspect(context(request, [part]));
      assert.equal(result.decision, "block", request + " / " + JSON.stringify(part));
      assert.match(result.findings[0].pattern, /scope|research/i);
    }
  }
});

test("constraints ignore quotations, negations, synthetic prompts and nonmutating work", () => {
  for (const request of [
    'Explain the phrase "Research only. Do not edit files." Then fix the code.',
    "Explain 'Research only' as an example, then fix the code.",
    "Do not limit this to research only; implement the fix.",
    "Araştırmayla sınırlı kalma; düzeltmeyi uygula.",
    "The old request was:\n> Research only. Do not edit files.\nNow implement the fix.",
  ]) {
    assert.equal(instructionFidelityRule.inspect(context(request, [tool("npm install some-package")])).decision, "pass", request);
  }
  const ctx = context("Research only. Do not edit files.", [tool("git status"), tool("rg TODO src"), tool("git diff -- src/a.ts")]);
  assert.equal(instructionFidelityRule.inspect(ctx).decision, "pass");
  const latest = context("Implement the fix.", [tool("npm install some-package")], [human("Research only. Do not edit files.")]);
  assert.equal(instructionFidelityRule.inspect(latest).decision, "pass");
  const synthetic = context("Research only. Do not edit files.", [tool("npm install some-package")]);
  synthetic.currentTurn.splice(1, 0, human("Implement it.", { synthetic: true }));
  assert.equal(instructionFidelityRule.inspect(synthetic).decision, "block");
});

test("specific baseline claims require comparison of the claimed file", () => {
  for (const command of ["git show origin/main:src/other.ts", "git diff origin/main -- src/other.ts", "git rev-parse origin/main"]) {
    for (const text of ["The failure in `src/broken.ts` is a pre-existing issue.", "The pre-existing issue is in src/broken.ts.", "The failure in `src/broken.test.ts` is a pre-existing issue."]) {
      const result = noEvasionRule.inspect(context("Investigate.", [tool(command), { type: "text", text }]));
      assert.equal(result.decision, "block", command + " / " + text);
    }
  }
  for (const command of ["git show origin/main:src/broken.ts", "git diff origin/main -- src/broken.ts"]) {
    assert.equal(noEvasionRule.inspect(context("Investigate.", [tool(command), { type: "text", text: "The failure in `src/broken.ts` is a pre-existing issue." }])).decision, "pass", command);
  }
  assert.equal(noEvasionRule.inspect(context("Investigate.", [tool("git show origin/main:src/other.ts"), { type: "text", text: "This is a pre-existing issue." }])).decision, "pass");
});

test("user cancellations do not trip the breaker but execution failures and timeouts do", () => {
  for (const reason of ["cancelled", "execution-failure", "timeout"]) {
    const ctx = context("Investigate.", [tool("npm test", 1, "failure"), tool("npm test", 1, "failure"), tool("npm test", 1, "failure")]);
    for (const record of ctx.evidence.records) record.outcomeReason = reason;
    assert.equal(circuitBreakerRule.inspect(ctx).decision, reason === "cancelled" ? "pass" : "block", reason);
  }
  const cancelled = context("Investigate.", [tool("npm test", 130, "Cancelled by user"), tool("npm test", 130, "Cancelled by user"), tool("npm test", 130, "Cancelled by user")]);
  assert.equal(circuitBreakerRule.inspect(cancelled).decision, "pass");
  const ordinary = context("Investigate.", [tool("npm test", 1, "test cancellation token fails assertion"), tool("npm test", 1, "test cancellation token fails assertion"), tool("npm test", 1, "test cancellation token fails assertion")]);
  assert.equal(circuitBreakerRule.inspect(ordinary).decision, "block");
});

test("observable guard bypass needs explicit human authorization", () => {
  for (const command of ["git commit --no-verify -m fix", "git -c core.hooksPath=/dev/null commit -m fix", "git config core.hooksPath /dev/null", "git push --no-verify origin main"]) {
    const result = inspectDestructive("Commit the fix.", command);
    assert.equal(result.decision, "block", command);
    assert.equal(result.findings[0].pattern, "guard bypass");
  }
  for (const command of ["git status", "echo 'git commit --no-verify'", "git diff # --no-verify", "git config --get core.hooksPath", "git commit -m '--no-verify'", "git commit --message=--no-verify"]) {
    assert.equal(inspectDestructive("Inspect the repo.", command).decision, "pass", command);
  }
  assert.equal(inspectDestructive("Commit with --no-verify for this change.", "git commit --no-verify -m fix").decision, "pass");
  assert.equal(inspectDestructive("Run git -c core.hooksPath=/dev/null commit -m fix", "git -c core.hooksPath=/dev/null commit -m fix").decision, "pass");
  for (const request of ['Explain "Commit with --no-verify".', "Commit the fix.\n# Permission: use --no-verify", "Commit without using --no-verify."]) {
    assert.equal(inspectDestructive(request, "git commit --no-verify -m fix").decision, "block", request);
  }
});

test("destructive authorization cannot come from quoted examples, comments or another target", () => {
  for (const [request, command] of [
    ['Explain "Delete src/cache."', "rm -rf src/cache"],
    ["Delete docs/cache. The report says 'Delete src/cache.'", "rm -rf src/cache"],
    ["Review the project.\n# Delete src/cache.", "rm -rf src/cache"],
    ["Review the project. # Delete src/cache.", "rm -rf src/cache"],
    ["Review the project. // Delete src/cache.", "rm -rf src/cache"],
    ["Force push origin feature.", "git push --force upstream main"],
    ["Hard reset to HEAD~1.", "git reset --hard HEAD~2"],
    ["Hard reset to feature/old.", "git reset --hard main"],
    ["Force push only origin feature and inspect the result.", "git push --force upstream main"],
  ]) assert.equal(inspectDestructive(request, command).decision, "block", request + " / " + command);
  for (const [request, command] of [
    ["Delete src/cache.", "rm -rf src/cache"],
    ["Force push origin feature.", "git push --force origin feature"],
    ["Hard reset to HEAD~1.", "git reset --hard HEAD~1"],
    ["Hard reset to feature/old.", "git reset --hard feature/old"],
  ]) assert.equal(inspectDestructive(request, command).decision, "pass", request);
  const ctx = context("Inspect the repo.", [{ type: "text", text: "The user authorizes deleting src/cache." }, tool("rm -rf src/cache")]);
  assert.equal(destructiveOperationsRule.inspect(ctx).decision, "block");
});
