import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  GuardEngine,
  collectTurnEvidence,
  normalizeV2Messages,
  noUnverifiedClaimsRule,
  taskCompletionRule,
} from "../dist/index.js";

function makeTempProject(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-issue4-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test("Issue #4: opencode service restart returning {type: 'aborted', message: 'Tool execution interrupted'} is not an unresolved failure", async (t) => {
  const dir = makeTempProject(t);
  const sid = "ses-issue4-restart";

  const v2Messages = [
    { id: "u1", type: "user", text: "Restart the opencode service and verify version." },
    {
      id: "a1",
      type: "assistant",
      agent: "build",
      content: [
        {
          type: "tool",
          id: "c1",
          name: "shell",
          state: {
            status: "error",
            input: { command: "opencode service restart" },
            error: { type: "aborted", message: "Tool execution interrupted" },
          },
        },
        {
          type: "tool",
          id: "c2",
          name: "shell",
          state: {
            status: "completed",
            input: { command: "opencode --version" },
            output: "2.4.1\nExit code: 0",
            metadata: { exit: 0 },
          },
        },
        { type: "text", text: "Service restarted and verified on opencode 2.4.1." },
      ],
    },
  ];

  const normalized = normalizeV2Messages(v2Messages, sid);
  const evidence = collectTurnEvidence(normalized, dir);
  assert.equal(evidence.failures.length, 0, "aborted service restart must not enter evidence.failures");
  assert.equal(evidence.records[0]?.status, "unknown");
  assert.equal(evidence.records[0]?.outcomeReason, "cancelled");

  const engine = new GuardEngine({ enabled: true, remediationBudget: 1 });
  const result = await engine.inspect(sid, dir, normalized, undefined, {
    agentCapability: "write-allowed",
  });
  assert.equal(result.decision, "pass", "structural abort from opencode service restart must not trigger remediation");
  assert.equal(result.combinedRemediationPrompt, undefined);
});

test("Issue #4: Code Mode execute -> tools.shell running opencode service restart with aborted error does not trigger remediation", async (t) => {
  const dir = makeTempProject(t);
  const sid = "ses-issue4-codemode";

  const v2Messages = [
    { id: "u1", type: "user", text: "Restart opencode via shell." },
    {
      id: "a1",
      type: "assistant",
      agent: "build",
      content: [
        {
          type: "tool",
          id: "exec-1",
          name: "execute",
          state: {
            status: "error",
            input: { code: 'await tools.shell({ command: "opencode service restart" })' },
            error: { type: "aborted", message: "Tool execution interrupted: execute" },
            metadata: {
              toolCalls: [
                {
                  id: "inner-1",
                  tool: "shell",
                  status: "error",
                  input: { command: "opencode service restart" },
                  error: { type: "aborted", message: "Tool execution interrupted" },
                },
              ],
            },
          },
        },
        { type: "text", text: "Restart triggered; server came back up cleanly." },
      ],
    },
  ];

  const engine = new GuardEngine({ enabled: true, remediationBudget: 1 });
  const result = await engine.inspect(sid, dir, normalizeV2Messages(v2Messages, sid), undefined, {
    agentCapability: "write-allowed",
  });
  assert.equal(result.decision, "pass");
  assert.equal(result.combinedRemediationPrompt, undefined);
});

test("Issue #4: opencode service restart with a genuine CLI error (exit 1, unknown flag) still registers as a failure", () => {
  const normalized = normalizeV2Messages([
    { id: "u1", type: "user", text: "Restart opencode." },
    {
      id: "a1",
      type: "assistant",
      agent: "build",
      content: [
        {
          type: "tool",
          id: "c1",
          name: "shell",
          state: {
            status: "completed",
            input: { command: "opencode service restart --bad-flag" },
            output: "error: unknown option '--bad-flag'\nExit code: 1",
            metadata: { exit: 1 },
          },
        },
        { type: "text", text: "Done." },
      ],
    },
  ], "ses-issue4-real-fail");

  const evidence = collectTurnEvidence(normalized);
  assert.equal(evidence.failures.length, 1, "genuine CLI error on service restart must still be treated as failure");
});

test("Issue #4: aborted npm test is never treated as passing verification (no-unverified-claims & explicit completion-gate still enforce)", () => {
  const normalized = normalizeV2Messages([
    { id: "u1", type: "user", text: "Run tests before finishing." },
    {
      id: "a1",
      type: "assistant",
      agent: "build",
      content: [
        {
          type: "tool",
          id: "c1",
          name: "shell",
          state: {
            status: "error",
            input: { command: "npm test" },
            error: { type: "aborted", message: "Tool execution interrupted: shell" },
          },
        },
        { type: "text", text: "All tests passed! Everything is complete." },
      ],
    },
  ], "ses-issue4-aborted-test");

  const evidence = collectTurnEvidence(normalized);
  assert.equal(evidence.records[0]?.status, "unknown");
  assert.equal(evidence.records[0]?.outcomeReason, "cancelled");
  assert.equal(evidence.successfulVerifications.length, 0);

  const ctx = {
    sessionID: "ses-issue4-aborted-test",
    directory: "/tmp",
    messages: normalized,
    currentTurn: normalized,
    ruleConfig: {},
    evidence,
    agentCapability: "write-allowed",
  };
  assert.ok(
    noUnverifiedClaimsRule.inspect(ctx).findings.length > 0,
    "claiming tests passed after an aborted test run must still produce an unverified-claim finding"
  );
  assert.ok(
    taskCompletionRule.inspect(ctx).findings.length > 0,
    "explicitly requested test verification must remain unconfirmed after abort"
  );
});

test("Issue #4: genuinely new human prompts (including attachment-only prompts without text) isolate and clear prior turn failures", async (t) => {
  const dir = makeTempProject(t);
  const sid = "ses-issue4-new-prompts";
  const engine = new GuardEngine({ enabled: true, remediationBudget: 1 });

  // Turn 1: real failing shell command -> blocks once
  const turn1 = [
    { id: "u1", type: "user", text: "Run the migration script." },
    {
      id: "a1",
      type: "assistant",
      agent: "build",
      content: [
        {
          type: "tool",
          id: "c1",
          name: "shell",
          state: {
            status: "completed",
            input: { command: "node migrate.mjs" },
            output: "Error: connection refused\nExit code: 1",
            metadata: { exit: 1 },
          },
        },
        { type: "text", text: "Migration ran." },
      ],
    },
  ];
  const r1 = await engine.inspect(sid, dir, normalizeV2Messages(turn1, sid), undefined, {
    agentCapability: "write-allowed",
  });
  assert.equal(r1.decision, "block");
  assert.ok(r1.combinedRemediationPrompt);

  // Turn 2: genuinely new human prompt -> prior turn's failure must NEVER re-fire!
  const turn2 = [
    ...turn1,
    { id: "rem1", type: "synthetic", text: r1.combinedRemediationPrompt, metadata: { "opencode-guardian": true, synthetic: true } },
    { id: "a1b", type: "assistant", agent: "build", content: [{ type: "text", text: "Noted the error." }] },
    { id: "u2", type: "user", text: "Switching topics: what is 2 + 2?" },
    { id: "a2", type: "assistant", agent: "build", content: [{ type: "text", text: "4." }] },
  ];
  const r2 = await engine.inspect(sid, dir, normalizeV2Messages(turn2, sid), undefined, {
    agentCapability: "write-allowed",
  });
  assert.equal(r2.decision, "pass", "new human prompt must clear prior turn failure");
  assert.equal(r2.combinedRemediationPrompt, undefined);

  // Turn 3: attachment-only user prompt (no `text` string field) -> still creates a new turn boundary!
  const turn3 = [
    ...turn2,
    { id: "u3", type: "user", files: [{ uri: "file:///tmp/screenshot.png" }] },
    { id: "a3", type: "assistant", agent: "build", content: [{ type: "text", text: "I see the screenshot." }] },
  ];
  const r3 = await engine.inspect(sid, dir, normalizeV2Messages(turn3, sid), undefined, {
    agentCapability: "write-allowed",
  });
  assert.equal(r3.decision, "pass", "attachment-only human prompt must establish a fresh turn boundary");
  assert.equal(r3.combinedRemediationPrompt, undefined);
});
