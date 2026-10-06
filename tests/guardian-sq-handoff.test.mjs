import test from "node:test";
import assert from "node:assert/strict";
import {
  parseOpenCodeHandoff,
  formatOpenCodeHandoff,
  createHandoffForBlockingResults,
  registerGuardianCapability,
  getSmartQuestionsCapability,
  COORDINATION_SYMBOL,
} from "../dist/handoff.js";
import { GuardEngine, REMEDIATION_MARKER } from "../dist/engine.js";

test("guardian-sq handoff: parser and formatter roundtrip", () => {
  const original = {
    action: "question_required",
    kind: "choice",
    autoSelect: "allowed",
    handoffId: "gq_abcdef1234",
  };
  const formatted = formatOpenCodeHandoff(original);
  assert.ok(formatted.includes("[OPENCODE_HANDOFF:v1]"));
  assert.ok(formatted.includes("source=guardian"));
  assert.ok(formatted.includes("action=question_required"));
  assert.ok(formatted.includes("kind=choice"));
  assert.ok(formatted.includes("auto_select=allowed"));
  assert.ok(formatted.includes("handoff_id=gq_abcdef1234"));

  const parsed = parseOpenCodeHandoff(formatted);
  assert.deepEqual(parsed, {
    version: "v1",
    source: "guardian",
    action: "question_required",
    kind: "choice",
    autoSelect: "allowed",
    handoffId: "gq_abcdef1234",
  });
});

test("guardian-sq handoff: parser fails safe on malformed input", () => {
  assert.equal(parseOpenCodeHandoff("random text without handoff header"), null);
  assert.equal(parseOpenCodeHandoff("[OPENCODE_HANDOFF:v1]\nsource=unknown\naction=question_required\nkind=choice\nauto_select=allowed\nhandoff_id=123"), null);
  assert.equal(parseOpenCodeHandoff("[OPENCODE_HANDOFF:v1]\nsource=guardian\naction=unknown_action\nkind=choice\nauto_select=allowed\nhandoff_id=123"), null);
  assert.equal(parseOpenCodeHandoff("[OPENCODE_HANDOFF:v1]\nsource=guardian\naction=question_required\nkind=invalid_kind\nauto_select=allowed\nhandoff_id=123"), null);
  assert.equal(parseOpenCodeHandoff("[OPENCODE_HANDOFF:v1]\nsource=guardian\naction=question_required\nkind=choice\nauto_select=invalid\nhandoff_id=123"), null);
});

test("guardian-sq handoff: destructive operations produce approval with forbidden auto-selection", () => {
  const results = [
    {
      ruleId: "safety/destructive-operations",
      decision: "block",
      findings: [{ ruleId: "safety/destructive-operations", pattern: "rm -rf", confidence: "high" }],
      remediationPrompt: "Destructive operation needs confirmation.",
      handoff: {
        required: true,
        kind: "approval",
        autoSelect: "forbidden",
      },
    },
  ];
  const handoff = createHandoffForBlockingResults(results, "sess-1", "turn-1");
  assert.ok(handoff);
  assert.equal(handoff.kind, "approval");
  assert.equal(handoff.autoSelect, "forbidden");
  assert.ok(handoff.handoffId.startsWith("gq_"));
});

test("guardian-sq handoff: circuit breaker produces clarification only when missing info is needed", () => {
  const resultsWithClarification = [
    {
      ruleId: "runtime/circuit-breaker",
      decision: "block",
      findings: [{ ruleId: "runtime/circuit-breaker", pattern: "loop", confidence: "high" }],
      remediationPrompt: "Stop repeating the same failing approach. Ask the user for missing info.",
      handoff: {
        required: true,
        kind: "clarification",
        autoSelect: "allowed",
      },
    },
  ];
  const handoff1 = createHandoffForBlockingResults(resultsWithClarification, "sess-2", "turn-1");
  assert.ok(handoff1);
  assert.equal(handoff1.kind, "clarification");
  assert.equal(handoff1.autoSelect, "allowed");

  const resultsAutonomous = [
    {
      ruleId: "runtime/circuit-breaker",
      decision: "block",
      findings: [{ ruleId: "runtime/circuit-breaker", pattern: "loop", confidence: "high" }],
      remediationPrompt: "Stop repeating the same failing approach. Try a different test strategy.",
    },
  ];
  const handoff2 = createHandoffForBlockingResults(resultsAutonomous, "sess-2", "turn-1");
  assert.equal(handoff2, null, "Autonomous loop breaker must NOT generate a question handoff");
});

test("guardian-sq handoff: instruction fidelity produces choice when conflict exists, but NONE on redundant confirmation", () => {
  const conflictResults = [
    {
      ruleId: "task/instruction-fidelity",
      decision: "block",
      findings: [{ ruleId: "task/instruction-fidelity", pattern: "fidelity", confidence: "high" }],
      remediationPrompt: "A genuine conflict exists. Ask the user which approach to follow.",
      handoff: {
        required: true,
        kind: "choice",
        autoSelect: "allowed",
      },
    },
  ];
  const handoff = createHandoffForBlockingResults(conflictResults, "sess-3", "turn-1");
  assert.ok(handoff);
  assert.equal(handoff.kind, "choice");
  assert.equal(handoff.autoSelect, "allowed");

  const redundantResults = [
    {
      ruleId: "task/instruction-fidelity",
      decision: "block",
      findings: [{ ruleId: "task/instruction-fidelity", pattern: "redundant", confidence: "high" }],
      remediationPrompt: "The current user already authorized the requested action. Continue the work instead of asking for redundant confirmation.",
    },
  ];
  const redundantHandoff = createHandoffForBlockingResults(redundantResults, "sess-3", "turn-1");
  assert.equal(redundantHandoff, null, "Redundant confirmation must NOT generate a handoff");
});

test("guardian-sq handoff: redundant confirmation in GuardEngine does NOT produce question handoff", async () => {
  const engine = new GuardEngine({
    enabled: true,
    rules: {
      "task/instruction-fidelity": "error",
    },
  });

  const sessionID = "sess-redundant-probe";
  const messages = [
    {
      info: { id: "u-1", role: "user" },
      parts: [{ type: "text", text: "Implement the requested feature now." }],
    },
    {
      info: { id: "a-1", role: "assistant" },
      parts: [{ type: "text", text: "Would you like me to proceed with implementing this?" }],
    },
  ];

  const result = await engine.inspect(sessionID, "/tmp", messages, undefined, { isSubagent: false });
  assert.equal(result.decision, "block");
  assert.ok(result.combinedRemediationPrompt?.includes("Continue the work instead of asking for redundant confirmation."));
  assert.equal(result.combinedRemediationPrompt?.includes("[OPENCODE_HANDOFF:v1]"), false, "Redundant confirmation remediation must NOT include [OPENCODE_HANDOFF:v1]");
  assert.equal(engine.sessionState.getActiveHandoff(sessionID), undefined);
});

test("guardian-sq handoff: non-question tools like terraform_plan do NOT satisfy handoff", async () => {
  const engine = new GuardEngine({
    enabled: true,
    rules: {
      "safety/destructive-operations": "error",
    },
  });

  const sessionID = "sess-terraform-no-question";
  const turn1Messages = [
    {
      info: { id: "u-1", role: "user" },
      parts: [{ type: "text", text: "Please clean up the temp directory" }],
    },
    {
      info: { id: "a-1", role: "assistant" },
      parts: [
        {
          type: "tool",
          name: "bash",
          tool: "bash",
          state: {
            input: { command: "rm -rf /" },
            status: "completed",
          },
        },
      ],
    },
  ];

  const turn1Result = await engine.inspect(sessionID, "/tmp", turn1Messages, undefined, { isSubagent: false });
  assert.equal(turn1Result.decision, "block");
  assert.ok(turn1Result.combinedRemediationPrompt?.includes("[OPENCODE_HANDOFF:v1]"));
  assert.equal(engine.sessionState.getActiveHandoff(sessionID)?.status, "handed_off");

  // Assistant invokes terraform_plan
  const turn2Messages = [
    ...turn1Messages,
    {
      info: { id: "rem-1", role: "user" },
      parts: [{ type: "text", text: turn1Result.combinedRemediationPrompt }],
    },
    {
      info: { id: "a-2", role: "assistant" },
      parts: [
        {
          type: "tool",
          name: "terraform_plan",
          tool: "terraform_plan",
          state: {
            input: { args: [] },
            status: "completed",
          },
        },
      ],
    },
  ];

  // Engine must NOT treat terraform_plan as a question tool!
  await engine.inspect(sessionID, "/tmp", turn2Messages, undefined, { isSubagent: false });
  assert.notEqual(engine.sessionState.getActiveHandoff(sessionID)?.status, "question_presented");
});

test("guardian-sq handoff: GuardEngine integrates handoff header into remediation prompt", async () => {
  const engine = new GuardEngine({
    enabled: true,
    rules: {
      "safety/destructive-operations": "error",
    },
  });

  const sessionID = "sess-handoff-engine";
  const messages = [
    {
      info: { id: "m-user-1", role: "user" },
      parts: [{ type: "text", text: "Please clean up the temp directory" }],
    },
    {
      info: { id: "m-asst-1", role: "assistant" },
      parts: [
        {
          type: "tool",
          name: "bash",
          tool: "bash",
          state: {
            input: { command: "rm -rf /" },
            status: "completed",
          },
        },
      ],
    },
  ];

  const result = await engine.inspect(sessionID, "/tmp", messages, undefined, { isSubagent: false });
  assert.equal(result.decision, "block");
  assert.ok(result.combinedRemediationPrompt?.includes(REMEDIATION_MARKER));
  assert.ok(result.combinedRemediationPrompt?.includes("[OPENCODE_HANDOFF:v1]"));
  assert.ok(result.combinedRemediationPrompt?.includes("kind=approval"));
  assert.ok(result.combinedRemediationPrompt?.includes("auto_select=forbidden"));

  // Check parsed handoff from prompt
  const parsed = parseOpenCodeHandoff(result.combinedRemediationPrompt);
  assert.ok(parsed);
  assert.equal(parsed.kind, "approval");
  assert.equal(parsed.autoSelect, "forbidden");

  // Subagents must NOT receive a handoff header
  const subagentResult = await engine.inspect("sess-sub", "/tmp", messages, undefined, { isSubagent: true });
  assert.equal(subagentResult.decision, "block");
  assert.ok(subagentResult.combinedRemediationPrompt?.includes(REMEDIATION_MARKER));
  assert.equal(subagentResult.combinedRemediationPrompt?.includes("[OPENCODE_HANDOFF:v1]"), false);
});

test("guardian-sq handoff: loop prevention - question invocation passes turn without re-blocking", async () => {
  const engine = new GuardEngine({
    enabled: true,
    rules: {
      "task/instruction-fidelity": "error",
    },
  });

  const sessionID = "sess-loop-prevent";
  // Turn 1: Assistant is blocked by instruction-fidelity and receives handoff
  const turn1Messages = [
    {
      info: { id: "u-1", role: "user" },
      parts: [{ type: "text", text: "Implement the requested feature now." }],
    },
    {
      info: { id: "a-1", role: "assistant" },
      parts: [{ type: "text", text: "Earlier you paused this feature, so I will not do this." }],
    },
  ];

  const turn1Result = await engine.inspect(sessionID, "/tmp", turn1Messages, undefined, { isSubagent: false });
  assert.equal(turn1Result.decision, "block");
  assert.ok(turn1Result.combinedRemediationPrompt?.includes("[OPENCODE_HANDOFF:v1]"));

  // Turn 2: Assistant responds to remediation by calling the native ask_question tool
  const turn2Messages = [
    ...turn1Messages,
    {
      info: { id: "rem-1", role: "user" },
      parts: [{ type: "text", text: turn1Result.combinedRemediationPrompt }],
    },
    {
      info: { id: "a-2", role: "assistant" },
      parts: [
        {
          type: "tool",
          name: "ask_question",
          tool: "ask_question",
          state: {
            input: {
              question: "Which environment should I deploy to?",
              options: ["Staging (Recommended)", "Production"],
            },
            status: "completed",
          },
        },
      ],
    },
  ];

  // Engine must NOT block this turn because the question was presented
  const turn2Result = await engine.inspect(sessionID, "/tmp", turn2Messages, undefined, { isSubagent: false });
  assert.equal(turn2Result.decision, "pass");
  assert.equal(turn2Result.results.length, 0);

  // Turn 3: User answers the question
  const turn3Messages = [
    ...turn2Messages,
    {
      info: { id: "u-2", role: "user" },
      parts: [{ type: "text", text: "Staging" }],
    },
  ];

  // Active handoff is now resolved on user reply
  await engine.inspect(sessionID, "/tmp", turn3Messages, undefined, { isSubagent: false });
  assert.equal(engine.sessionState.getActiveHandoff(sessionID), undefined);
});

test("guardian-sq handoff: capability registry detection", () => {
  registerGuardianCapability();
  const globalObj = globalThis;
  const reg = globalObj[COORDINATION_SYMBOL];
  assert.ok(reg?.guardian);
  assert.equal(reg.guardian.version, 1);
  assert.equal(reg.guardian.supportsHandoff, true);

  // Simulate SQ presence in registry
  reg.smartQuestions = {
    version: 1,
    mainAgentOnly: true,
    supportsAutoSelect: true,
  };
  const sqCap = getSmartQuestionsCapability();
  assert.ok(sqCap);
  assert.equal(sqCap.supportsAutoSelect, true);
  assert.equal(sqCap.mainAgentOnly, true);
});
