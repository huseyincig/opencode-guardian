import test from "node:test";
import assert from "node:assert/strict";
import { evaluatePreflight } from "../dist/preflight.js";
import { isDestructiveCommand } from "../dist/evidence.js";
import { SessionStateStore } from "../dist/state.js";
import { GuardEngine } from "../dist/engine.js";

test("quoted documentation never becomes a Windows destructive shell stage", () => {
  for (const command of [
    "echo 'example; del disposable.txt'",
    'printf "example && Remove-Item disposable.txt"',
    "grep 'erase disposable.txt' README.md",
  ]) {
    assert.equal(isDestructiveCommand(command), false, command);
    assert.equal(evaluatePreflight("bash", { command }), undefined, command);
  }
});

test("actual Windows command stages and literal nested shells stay blocked", () => {
  for (const command of [
    "del disposable.txt",
    "echo ok && Remove-Item disposable.txt",
    'cmd /c "del disposable.txt"',
    'powershell -Command "Remove-Item disposable.txt"',
    "pwsh -Command 'Remove-Item disposable.txt'",
  ]) {
    assert.equal(isDestructiveCommand(command), true, command);
    assert.equal(evaluatePreflight("bash", { command }), "destructive-command", command);
  }
});

test("duplicate or unknown continuation rollbacks preserve live budget", () => {
  const state = new SessionStateStore();
  state.recordContinuation("s", "turn", "first");
  state.recordContinuation("s", "turn", "first");
  assert.equal(state.canContinue("s", "turn", "second", 2), true);
  state.recordContinuation("s", "turn", "second");
  state.rollbackContinuation("s", "turn", "first");
  state.rollbackContinuation("s", "turn", "first");
  state.rollbackContinuation("s", "turn", "unknown");
  assert.equal(state.canContinue("s", "turn", "third", 1), false);
  assert.equal(state.canContinue("s", "turn", "third", 2), true);
});

test("a stale remediation rollback does not undo the next remediation", async () => {
  const engine = new GuardEngine({ remediationBudget: 2 });
  engine.registerRule({
    id: "test/rollback-once",
    inspect: () => ({
      ruleId: "test/rollback-once",
      decision: "block",
      findings: [],
      remediationPrompt: "Resolve this reproducible finding.",
    }),
  });
  const user = { info: { id: "u1", role: "user" },
    parts: [{ type: "text", text: "Produce a short result." }] };
  const assistant = (id) => ({ info: { id, role: "assistant" },
    parts: [{ type: "text", text: "Result." }] });
  const first = await engine.inspect("s", "/tmp", [user, assistant("a1")]);
  assert.equal(first.decision, "block");
  assert.equal(typeof first.rollback, "function");
  first.rollback();
  const second = await engine.inspect("s", "/tmp", [user, assistant("a2")]);
  assert.equal(second.decision, "block");
  assert.equal(engine.sessionState.getTurnRemediationCount("s", "u1"), 1);
  first.rollback();
  assert.equal(engine.sessionState.getTurnRemediationCount("s", "u1"), 1);
});
