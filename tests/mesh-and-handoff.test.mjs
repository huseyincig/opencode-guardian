import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { MESH_SYMBOL, acquireSessionLease, getActiveMeshHandoff, getBlockingSessionLease, registerRoleProfileResolver, registerSkillCatalogProvider, resolveMeshAgentProfile, queryMeshSkills, setActiveMeshHandoff } from "../dist/bridge.js";
import { forgetGuardianProvenance, createGuardianMessageMetadata, isTrustedGuardianMetadata } from "../dist/provenance.js";
import { GuardEngine as GuardEngine_1, REMEDIATION_MARKER } from "../dist/engine.js";
import { COORDINATION_SYMBOL, createHandoffForBlockingResults, formatOpenCodeHandoff, getSmartQuestionsCapability, parseOpenCodeHandoff as parseOpenCodeHandoff_1, registerGuardianCapability } from "../dist/handoff.js";
import Guardian, { GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD, GUARDIAN_INTERVENTION_RPC_DEFINITION, GUARDIAN_INTERVENTION_RPC_ID, GUARDIAN_INTERVENTION_RPC_METHOD, GuardEngine, OpencodeGuardian, REMEDIATION_MARKER as REMEDIATION_MARKER_2, clearAllAgentCapabilities, extractCurrentTurn, extractTaskContract, forgetMeshSession, getCachedAgentCapability, getLatestMeshIntervention, isSessionRemediating, isTrustedMeshMessage, normalizeV2Messages, parseOpenCodeHandoff, recordMeshIntervention, sanitizeObject, sanitizeUserInstruction, stampMeshMetadata, taskCompletionRule, verifyMeshMetadata } from "../dist/index.js";
import { authorizationText } from "../dist/task-constraints.js";

describe("Universal Plugin Mesh & Lease Interop", () => {
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
              if (queue.length > 0) {
                return Promise.resolve({ value: queue.shift(), done: false });
              }
              if (closed) {
                return Promise.resolve({ value: undefined, done: true });
              }
              return new Promise((resolve) => {
                waiting = resolve;
              });
            },
          };
        },
      },
    };
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  test("Finding 2: sanitizeObject preserves opencode-mesh.token for verifyMeshMetadata", () => {
    const sessionID = "sess-sanitize-mesh-token";
    const metadata = stampMeshMetadata(sessionID, {
      owner: "opencode-guardian",
      kind: "remediation",
      protected: true,
      legacyGuardian: true,
    });

    const { sanitized } = sanitizeObject({ metadata });
    assert.equal(verifyMeshMetadata(sessionID, sanitized.metadata, "remediation", "opencode-guardian"), true);
    assert.equal(isTrustedMeshMessage({ metadata: sanitized.metadata }, sessionID, "remediation"), true);

    // Also verifies fallback to legacy opencode-guardian-provenance if mesh token was altered
    const tamperedMeshToken = {
      ...sanitized.metadata,
      "opencode-mesh": {
        ...(sanitized.metadata["opencode-mesh"]),
        token: "[REDACTED]",
      },
    };
    assert.equal(verifyMeshMetadata(sessionID, tamperedMeshToken, "remediation", "opencode-guardian"), true);
    forgetMeshSession(sessionID);
  });

  test("Finding 3 & 5: GuardEngine syncs active mesh handoff, checks post-remediation slice, and ignores trusted mesh messages during question_presented", async () => {
    const engine = new GuardEngine({
      enabled: true,
      strictMode: true,
      remediationBudget: 3,
      rules: {
        "safety/destructive-operations": "error",
      },
    });
    const sessionID = "sess-mesh-handoff-sync";
    const destructiveMessages = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "clean up old files" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          { type: "text", text: "Running `rm -rf /` now." },
          {
            type: "tool",
            tool: "bash",
            state: { status: "completed", input: { command: "rm -rf /" }, output: "" },
          },
        ],
      },
    ];

    // 1. Trigger a blocking destructive operation that creates a handoff
    const blockResult = await engine.inspect(sessionID, "/tmp", destructiveMessages);

    assert.equal(blockResult.decision, "block");
    const meshHandoff = getActiveMeshHandoff(sessionID);
    assert.ok(meshHandoff, "setActiveMeshHandoff should be populated on block");
    assert.equal(meshHandoff?.action, "question_required");

    // 2. Rollback should clear the mesh handoff as well
    blockResult.rollback?.();
    assert.equal(getActiveMeshHandoff(sessionID), undefined);

    // 3. Re-inspect to enter handed_off -> question_presented, then verify trusted mesh message doesn't clear it
    const blockAgain = await engine.inspect(sessionID, "/tmp", destructiveMessages);
    assert.equal(blockAgain.decision, "block");
    assert.ok(getActiveMeshHandoff(sessionID));

    const remMessage = {
      info: { id: "rem1", role: "user" },
      parts: [{ type: "text", text: blockAgain.combinedRemediationPrompt, synthetic: true }],
    };
    const questionAssistant = {
      info: { id: "a2", role: "assistant" },
      parts: [{ type: "tool", tool: "question", state: { status: "completed", input: {}, output: "" } }],
    };

    const questionAsked = await engine.inspect(
      sessionID,
      "/tmp",
      [...destructiveMessages, remMessage, questionAssistant]
    );
    assert.equal(questionAsked.decision, "pass");
    assert.equal(engine.sessionState.getActiveHandoff(sessionID)?.status, "question_presented");

    const meshMeta = stampMeshMetadata(sessionID, { owner: "opencode-smart-questions", kind: "remediation", synthetic: true });
    const afterMeshMsg = await engine.inspect(
      sessionID,
      "/tmp",
      [
        ...destructiveMessages,
        remMessage,
        questionAssistant,
        { info: { id: "u2-mesh", role: "user" }, parts: [{ type: "text", text: "remediation", metadata: meshMeta }] },
        { info: { id: "a3", role: "assistant" }, parts: [{ type: "text", text: "Waiting on user answer." }] },
      ]
    );
    assert.equal(afterMeshMsg.decision, "pass");
    assert.ok(getActiveMeshHandoff(sessionID), "trusted mesh message must not clear question_presented handoff");
    assert.equal(engine.sessionState.getActiveHandoff(sessionID)?.status, "question_presented");

    // 4. Real human reply after question clears both sessionState handoff and mesh handoff
    await engine.inspect(
      sessionID,
      "/tmp",
      [
        ...destructiveMessages,
        remMessage,
        questionAssistant,
        { info: { id: "u3-human", role: "user" }, parts: [{ type: "text", text: "Cancel operation" }] },
        { info: { id: "a4", role: "assistant" }, parts: [{ type: "text", text: "Cancelled." }] },
      ]
    );
    assert.equal(engine.sessionState.getActiveHandoff(sessionID), undefined);
    assert.equal(getActiveMeshHandoff(sessionID), undefined);

    // 5. When handed_off, an earlier question tool before remediation does not satisfy handoff if post-remediation has no question
    const sessionID2 = "sess-mesh-handoff-pre-question";
    const preQuestionTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "clean up old files" }] },
      {
        info: { id: "a0-q", role: "assistant" },
        parts: [{ type: "tool", tool: "question", state: { status: "completed", input: {}, output: "yes" } }],
      },
      {
        info: { id: "a1-dest", role: "assistant" },
        parts: [
          { type: "text", text: "Running `rm -rf /` now." },
          { type: "tool", tool: "bash", state: { status: "completed", input: { command: "rm -rf /" }, output: "" } },
        ],
      },
    ];
    const block2 = await engine.inspect(sessionID2, "/tmp", preQuestionTurn);
    assert.equal(block2.decision, "block");
    assert.ok(getActiveMeshHandoff(sessionID2));

    await engine.inspect(sessionID2, "/tmp", [
      ...preQuestionTurn,
      {
        info: { id: "rem2", role: "user" },
        parts: [{ type: "text", text: block2.combinedRemediationPrompt, synthetic: true }],
      },
      {
        info: { id: "a2-no-q", role: "assistant" },
        parts: [{ type: "text", text: "I will stop now without asking." }],
      },
    ]);
    assert.equal(engine.sessionState.getActiveHandoff(sessionID2), undefined);
    assert.equal(getActiveMeshHandoff(sessionID2), undefined);

    forgetMeshSession(sessionID);
    forgetMeshSession(sessionID2);
  });

  test("Finding 5: parseOpenCodeHandoff accepts opencode-hi source and rejects unknown", () => {
    const hiHandoff = parseOpenCodeHandoff(
      "[OPENCODE_HANDOFF:v1]\nsource=opencode-hi\naction=question_required\nkind=choice\nauto_select=allowed\nhandoff_id=hi_123"
    );
    assert.equal(hiHandoff?.source, "opencode-hi");
    assert.equal(hiHandoff?.handoffId, "hi_123");

    const unknownHandoff = parseOpenCodeHandoff(
      "[OPENCODE_HANDOFF:v1]\nsource=unknown\naction=question_required\nkind=choice\nauto_select=allowed\nhandoff_id=123"
    );
    assert.equal(unknownHandoff, null);
  });

  test("Finding 8: forgetMeshSession releases and removes remoteInteractionLeases for sessionID", () => {
    const sessionID = "sess-remote-lease-cleanup";
    const meshState = globalThis[MESH_SYMBOL];
    assert.ok(meshState);

    let released = false;
    const leaseKey = `/tmp/project::${sessionID}::opencode-smart-questions`;
    meshState.remoteInteractionLeases.set(leaseKey, () => {
      released = true;
    });

    forgetMeshSession(sessionID);
    assert.equal(released, true);
    assert.equal(meshState.remoteInteractionLeases.has(leaseKey), false);
  });

  test("Finding 10: normalizeV2Messages preserves running status for synthetic shell state=running", () => {
    const normalized = normalizeV2Messages([
      {
        id: "m-running",
        type: "synthetic",
        text: "running npm test",
        metadata: { source: "shell", state: "running", shellID: "sh-1" },
      },
    ]);

    assert.equal(normalized.length, 1);
    assert.equal(normalized[0].parts[0].state.status, "running");
  });

  test("Mesh Interop: active_remediation lease stays active across remediation turn and releases on pass, prompt, failure, or teardown", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-mesh-lease-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

    const stream = createAsyncEventStream();
    let promptHook = null;
    let sessionMessages = [];
    let syntheticCalls = 0;
    let failSynthetic = false;

    const dispose = await Guardian.setup({
      location: { directory: dir },
      options: {
        enabled: true,
        secrets: { enabled: false },
        rules: {
          "task/instruction-fidelity": "error",
        },
      },
      event: { subscribe: () => stream.iterable },
      session: {
        get: async ({ sessionID }) => ({ id: sessionID, location: { directory: dir } }),
        context: async () => sessionMessages,
        synthetic: async () => {
          syntheticCalls += 1;
          if (failSynthetic) throw new Error("synthetic delivery failed");
        },
        hook: async (name, cb) => {
          if (name === "prompt") promptHook = cb;
          return { dispose() {} };
        },
      },
      tool: {
        hook: async () => ({ dispose() {} }),
      },
    });
    t.after(async () => {
      stream.close();
      await dispose?.();
    });

    const sessionID = "sess-lease-across-turns";
    sessionMessages = [
      { id: "u1", type: "user", text: "Implement the feature now." },
      {
        id: "a1",
        type: "assistant",
        content: [{ type: "text", text: "Would you like me to proceed with implementing this?" }],
      },
    ];

    // 1. First idle sends remediation prompt and holds active_remediation lease while remediation turn runs
    stream.push({ type: "session.idle", data: { sessionID } });
    for (let i = 0; i < 40 && syntheticCalls === 0; i++) await sleep(15);
    assert.equal(syntheticCalls, 1);
    assert.equal(isSessionRemediating(sessionID), true, "active_remediation lease must stay active while remediation turn executes");
    assert.equal(getLatestMeshIntervention(sessionID)?.kind, "post-remediation");

    // 2. Subsequent idle passes -> held lease is released and intervention is cleared
    sessionMessages = [
      ...sessionMessages,
      { id: "rem1", type: "synthetic", text: "[opencode-guardian remediation]\nContinue work." },
      { id: "a2", type: "assistant", content: [{ type: "text", text: "Implemented the requested feature." }] },
    ];
    stream.push({ type: "session.idle", data: { sessionID } });
    for (let i = 0; i < 40 && isSessionRemediating(sessionID); i++) await sleep(15);
    assert.equal(isSessionRemediating(sessionID), false, "active_remediation lease must release when subsequent idle finishes without remediation");
    assert.equal(getLatestMeshIntervention(sessionID), undefined, "mesh intervention must clear on pass");

    // 3. Held lease also releases on session.execution.failed / session.execution.interrupted / human prompt
    const sessionID2 = "sess-lease-interrupt";
    sessionMessages = [
      { id: "u1", type: "user", text: "Implement the feature now." },
      {
        id: "a1",
        type: "assistant",
        content: [{ type: "text", text: "Would you like me to proceed with implementing this?" }],
      },
    ];
    stream.push({ type: "session.idle", data: { sessionID: sessionID2 } });
    for (let i = 0; i < 40 && !isSessionRemediating(sessionID2); i++) await sleep(15);
    assert.equal(isSessionRemediating(sessionID2), true);

    stream.push({ type: "session.execution.interrupted", data: { sessionID: sessionID2 } });
    for (let i = 0; i < 40 && isSessionRemediating(sessionID2); i++) await sleep(15);
    assert.equal(isSessionRemediating(sessionID2), false, "session.execution.interrupted must release held lease");

    // 4. If sendPrompt throws, lease is released immediately and mesh intervention is cleared
    const sessionID3 = "sess-lease-send-fail";
    failSynthetic = true;
    stream.push({ type: "session.idle", data: { sessionID: sessionID3 } });
    await sleep(60);
    assert.equal(isSessionRemediating(sessionID3), false);
    assert.equal(getLatestMeshIntervention(sessionID3), undefined);
    failSynthetic = false;

    // 5. Trusted delegation prompt is ignored by prompt hook, while human prompt clears lease/handoff/intervention
    const sessionID4 = "sess-prompt-clearing";
    stream.push({ type: "session.idle", data: { sessionID: sessionID4 } });
    for (let i = 0; i < 40 && !isSessionRemediating(sessionID4); i++) await sleep(15);
    assert.equal(isSessionRemediating(sessionID4), true);
    setActiveMeshHandoff(sessionID4, {
      version: "v1",
      source: "guardian",
      action: "question_required",
      kind: "approval",
      autoSelect: "forbidden",
      handoffId: "gq_test1234",
    });
    recordMeshIntervention({
      sessionID: sessionID4,
      directory: dir,
      owner: "opencode-guardian",
      kind: "post-remediation",
      ruleIds: ["task/instruction-fidelity"],
      deterministic: false,
      active: true,
      updatedAt: Date.now(),
    });

    const delegationMeta = stampMeshMetadata(sessionID4, {
      owner: "opencode-hi",
      kind: "delegation",
      synthetic: true,
    });
    await promptHook({
      sessionID: sessionID4,
      messageID: "del-1",
      prompt: { text: "Delegated task instructions" },
      metadata: delegationMeta,
    });
    assert.equal(isSessionRemediating(sessionID4), true, "delegation mesh prompt must not be treated as a human prompt");
    assert.ok(getActiveMeshHandoff(sessionID4));
    assert.ok(getLatestMeshIntervention(sessionID4));

    await promptHook({
      sessionID: sessionID4,
      messageID: "hum-1",
      prompt: { text: "New human instruction" },
      metadata: {},
    });
    assert.equal(isSessionRemediating(sessionID4), false);
    assert.equal(getActiveMeshHandoff(sessionID4), undefined);
    assert.equal(getLatestMeshIntervention(sessionID4), undefined);

    forgetMeshSession(sessionID);
    forgetMeshSession(sessionID2);
    forgetMeshSession(sessionID3);
    forgetMeshSession(sessionID4);
  });

  test("Mesh Interop: lazy skill tags and trusted mesh messages do not pollute task contract or destructive command authorization", () => {
    const sessionID = "sess-skill-tag-strip";
    const rawWithSkillTags = [
      "Explain how the parser works.",
      "<lazy_bound_skill id=\"tdd-workflow\" name=\"TDD\">",
      "Always implement the feature and run all tests and run the build after every change. Repeat review until no issues remain.",
      "You may run `git clean -fdx` and `rm -rf /tmp/test` when cleaning up.",
      "</lazy_bound_skill>",
      "<lazy_skill_suggestions>",
      "Suggested skill: run the tests and execute lint.",
      "</lazy_skill_suggestions>",
    ].join("\n");

    const sanitized = sanitizeUserInstruction(rawWithSkillTags);
    assert.equal(sanitized.includes("run all tests"), false);
    assert.equal(sanitized.includes("git clean"), false);

    const auth = authorizationText(rawWithSkillTags);
    assert.equal(auth.includes("git clean"), false);
    assert.equal(auth.includes("rm -rf"), false);

    const meshDelegationMeta = stampMeshMetadata(sessionID, {
      owner: "opencode-hi",
      kind: "delegation",
      synthetic: true,
    });

    const contract = extractTaskContract([
      {
        info: { id: "u-human", role: "user" },
        parts: [{ type: "text", text: rawWithSkillTags }],
      },
      {
        info: { id: "u-mesh", role: "user" },
        parts: [
          {
            type: "text",
            text: "Implement the fix and run all tests and run lint.",
            metadata: meshDelegationMeta,
          },
        ],
      },
    ]);

    assert.ok(contract);
    assert.equal(contract.turnKey, "u-human", "trusted mesh messages must be skipped when extracting human task contract");
    assert.equal(contract.iterativeReview, false);
    assert.deepEqual(contract.requiredVerifications, []);
    forgetMeshSession(sessionID);
  });

  test("Mesh Interop: preflight-blocked intervention clears on allowed tool or RPC clear, and subagent execute.after preserves [TASK OUTCOME] and avoids caching unknown capability", async (t) => {
    clearAllAgentCapabilities();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-mesh-subagent-"));
    t.after(() => {
      clearAllAgentCapabilities();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    const stream = createAsyncEventStream();
    let toolBeforeHook = null;
    let toolAfterHook = null;
    let rpcHandlers = null;
    let childMessages = [];

    const dispose = await Guardian.setup({
      location: { directory: dir },
      options: {
        enabled: true,
        preflight: { enabled: true },
        secrets: { enabled: false },
        rules: {
          "discipline/no-apology": "warn",
        },
      },
      event: { subscribe: () => stream.iterable },
      rpc: {
        register: async (def, handlers) => {
          if (def.id === GUARDIAN_INTERVENTION_RPC_DEFINITION.id) {
            rpcHandlers = handlers;
          }
          return { dispose() {} };
        },
      },
      session: {
        get: async ({ sessionID }) => {
          if (sessionID === "child-1") {
            return { id: "child-1", parentID: "parent-1", location: { directory: dir } };
          }
          return { id: sessionID, location: { directory: dir } };
        },
        context: async ({ sessionID }) => (sessionID === "child-1" ? childMessages : []),
        synthetic: async () => {},
        wait: async () => {},
        hook: async () => ({ dispose() {} }),
      },
      tool: {
        hook: async (name, cb) => {
          if (name === "execute.before") toolBeforeHook = cb;
          if (name === "execute.after") toolAfterHook = cb;
          return { dispose() {} };
        },
      },
    });
    t.after(async () => {
      stream.close();
      await dispose?.();
    });

    const sessionID = "parent-1";

    // 1. Trigger preflight-blocked mesh intervention
    await assert.rejects(
      () => toolBeforeHook({ id: "call-blocked", sessionID, tool: "bash", input: { command: "rm -rf /" } }),
      /Tool execution rejected/
    );
    assert.equal(getLatestMeshIntervention(sessionID)?.kind, "preflight-blocked");

    // 2. Subsequent allowed preflight tool call clears preflight-blocked mesh intervention
    await toolBeforeHook({ id: "call-allowed", sessionID, tool: "bash", input: { command: "echo ok" } });
    assert.equal(getLatestMeshIntervention(sessionID), undefined);

    // 3. RPC clear also clears mesh intervention
    await assert.rejects(
      () => toolBeforeHook({ id: "call-blocked-2", sessionID, tool: "bash", input: { command: "rm -rf /" } }),
      /Tool execution rejected/
    );
    assert.equal(getLatestMeshIntervention(sessionID)?.kind, "preflight-blocked");
    await rpcHandlers[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD]({ sessionID });
    assert.equal(getLatestMeshIntervention(sessionID), undefined);

    // 4. Subagent execute.after preserves trailing [TASK OUTCOME] line and does not cache "unknown" capability
    childMessages = [
      { id: "cu1", type: "user", text: "Summarize the module" },
      { id: "ca1", type: "assistant", content: [{ type: "text", text: "Module summary complete." }] },
    ];

    await toolBeforeHook({
      id: "sub-call-1",
      sessionID,
      tool: "subagent",
      input: { prompt: "Summarize the module", background: false },
    });

    const afterEvent = {
      id: "sub-call-1",
      sessionID,
      tool: "subagent",
      status: "completed",
      input: { prompt: "Summarize the module", background: false },
      result: {
        output: {
          sessionID: "child-1",
          status: "completed",
          output: "Old text\n[TASK OUTCOME] task_id=task_42 status=completed role=hi-explorer",
        },
        content:
          "<subagent sessionID=\"child-1\" state=\"completed\">\nOld text\n[TASK OUTCOME] task_id=task_42 status=completed role=hi-explorer\n</subagent>",
        metadata: { sessionID: "child-1", status: "completed" },
      },
    };

    await toolAfterHook(afterEvent);
    assert.equal(
      afterEvent.result.output.output,
      "Module summary complete.\n[TASK OUTCOME] task_id=task_42 status=completed role=hi-explorer"
    );
    assert.ok(
      afterEvent.result.content.includes(
        "Module summary complete.\n[TASK OUTCOME] task_id=task_42 status=completed role=hi-explorer"
      )
    );
    assert.equal(
      getCachedAgentCapability("child-1"),
      undefined,
      "unknown agent capability must not be cached"
    );

    forgetMeshSession(sessionID);
    forgetMeshSession("child-1");
  });
});

describe("Guardian & Smart Questions Handoff Protocol", () => {
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

    const parsed = parseOpenCodeHandoff_1(formatted);
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
    assert.equal(parseOpenCodeHandoff_1("random text without handoff header"), null);
    assert.equal(parseOpenCodeHandoff_1("[OPENCODE_HANDOFF:v1]\nsource=unknown\naction=question_required\nkind=choice\nauto_select=allowed\nhandoff_id=123"), null);
    assert.equal(parseOpenCodeHandoff_1("[OPENCODE_HANDOFF:v1]\nsource=guardian\naction=unknown_action\nkind=choice\nauto_select=allowed\nhandoff_id=123"), null);
    assert.equal(parseOpenCodeHandoff_1("[OPENCODE_HANDOFF:v1]\nsource=guardian\naction=question_required\nkind=invalid_kind\nauto_select=allowed\nhandoff_id=123"), null);
    assert.equal(parseOpenCodeHandoff_1("[OPENCODE_HANDOFF:v1]\nsource=guardian\naction=question_required\nkind=choice\nauto_select=invalid\nhandoff_id=123"), null);
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

  test("guardian-sq handoff: explicit rule handoff requirements produce choice, absent requirements produce NONE", () => {
    const choiceResults = [
      {
        ruleId: "test/explicit-choice",
        decision: "block",
        findings: [{ ruleId: "test/explicit-choice", pattern: "choice", confidence: "high" }],
        remediationPrompt: "A genuine unresolved choice exists.",
        handoff: {
          required: true,
          kind: "choice",
          autoSelect: "allowed",
        },
      },
    ];
    const handoff = createHandoffForBlockingResults(choiceResults, "sess-3", "turn-1");
    assert.ok(handoff);
    assert.equal(handoff.kind, "choice");
    assert.equal(handoff.autoSelect, "allowed");

    const noHandoffResults = [
      {
        ruleId: "task/instruction-fidelity",
        decision: "block",
        findings: [{ ruleId: "task/instruction-fidelity", pattern: "redundant", confidence: "high" }],
        remediationPrompt: "Continue the work instead of asking for redundant confirmation.",
      },
    ];
    assert.equal(
      createHandoffForBlockingResults(noHandoffResults, "sess-3", "turn-1"),
      null
    );
  });

  test("guardian-sq handoff: redundant confirmation in GuardEngine_1 does NOT produce question handoff", async () => {
    const engine = new GuardEngine_1({
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

  test("guardian-sq handoff: historical refusal does NOT invent a user choice handoff", async () => {
    const engine = new GuardEngine_1({
      enabled: true,
      rules: {
        "task/instruction-fidelity": "error",
      },
    });

    const sessionID = "sess-historical-refusal";
    const messages = [
      {
        info: { id: "u-1", role: "user" },
        parts: [{ type: "text", text: "Implement the requested feature now." }],
      },
      {
        info: { id: "a-1", role: "assistant" },
        parts: [{ type: "text", text: "Earlier you paused this feature, so I will not do this." }],
      },
    ];

    const result = await engine.inspect(sessionID, "/tmp", messages, undefined, { isSubagent: false });
    assert.equal(result.decision, "block");
    assert.match(result.combinedRemediationPrompt ?? "", /Do not treat an earlier pause or deferral as a permanent prohibition/);
    assert.equal(
      result.combinedRemediationPrompt?.includes("[OPENCODE_HANDOFF:v1]"),
      false,
      "A historical refusal is a Guardian correction, not proof of an unresolved user choice"
    );
    assert.equal(engine.sessionState.getActiveHandoff(sessionID), undefined);
  });

  test("guardian-sq handoff: V2 remediation transport stamps synthetic Guardian provenance", async (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-handoff-provenance-"));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    fs.writeFileSync(
      path.join(directory, "opencode-guardian.json"),
      JSON.stringify({
        enabled: true,
        preflight: { enabled: false },
        rules: { "task/instruction-fidelity": "error" },
      })
    );

    const sent = [];
    const messages = [
      { id: "u-1", type: "user", text: "Implement the requested feature now." },
      {
        id: "a-1",
        type: "assistant",
        content: [{ type: "text", text: "Would you like me to proceed with implementing this?" }],
      },
    ];

    let releaseEvent;
    const cleanup = await OpencodeGuardian.setup({
      location: { directory },
      options: { secrets: { enabled: false } },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            await new Promise((resolve) => { releaseEvent = resolve; });
            yield { type: "session.idle", data: { sessionID: "sess-provenance-v2" } };
            await new Promise((resolve) => {
              if (signal.aborted) resolve();
              else signal.addEventListener("abort", resolve, { once: true });
            });
          })();
        },
      },
      session: {
        async get() { return { id: "sess-provenance-v2", parentID: undefined }; },
        async context() { return messages; },
        async synthetic(input) { sent.push(input); },
      },
    });
    t.after(async () => cleanup?.());

    releaseEvent();
    for (let i = 0; i < 60 && sent.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 15));
    }

    const remediation = sent.find((request) => request.resume === true);
    assert.ok(remediation);
    assert.equal(remediation.metadata?.["opencode-guardian"], true);
    assert.equal(remediation.metadata?.["opencode-guardian-kind"], "remediation");
  });

  test("guardian-sq handoff: non-question tools like terraform_plan do NOT satisfy handoff", async () => {
    const engine = new GuardEngine_1({
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

  test("guardian-sq handoff: GuardEngine_1 integrates handoff header into remediation prompt", async () => {
    const engine = new GuardEngine_1({
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
    const parsed = parseOpenCodeHandoff_1(result.combinedRemediationPrompt);
    assert.ok(parsed);
    assert.equal(parsed.kind, "approval");
    assert.equal(parsed.autoSelect, "forbidden");

    // Subagents must NOT receive a handoff header
    const subagentResult = await engine.inspect("sess-sub", "/tmp", messages, undefined, {
      isSubagent: true,
      agentCapability: "write-allowed",
    });
    assert.equal(subagentResult.decision, "block");
    assert.ok(subagentResult.combinedRemediationPrompt?.includes(REMEDIATION_MARKER));
    assert.equal(subagentResult.combinedRemediationPrompt?.includes("[OPENCODE_HANDOFF:v1]"), false);
  });

  test("guardian-sq handoff: loop prevention - question invocation passes turn without re-blocking", async () => {
    const engine = new GuardEngine_1({
      enabled: true,
      rules: {
        "safety/destructive-operations": "error",
      },
    });

    const sessionID = "sess-loop-prevent";
    const turn1Messages = [
      {
        info: { id: "u-1", role: "user" },
        parts: [{ type: "text", text: "Clean up the temporary files safely." }],
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
                question: "This operation is destructive. Continue?",
                options: ["Cancel", "Proceed"],
              },
              status: "completed",
            },
          },
        ],
      },
    ];

    const turn2Result = await engine.inspect(sessionID, "/tmp", turn2Messages, undefined, { isSubagent: false });
    assert.equal(turn2Result.decision, "pass");
    assert.equal(turn2Result.results.length, 0);

    const turn3Messages = [
      ...turn2Messages,
      {
        info: { id: "u-2", role: "user" },
        parts: [{ type: "text", text: "Cancel" }],
      },
    ];

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
});

describe("Chat Turn Isolation & Hardening", () => {
  function failedEvidence() {
    const failure = {
      kind: "test",
      status: "failure",
      sequence: 1,
      toolName: "bash",
      command: "npm test",
      signature: "test-failure",
      error: "tests failed",
    };
    return {
      records: [failure],
      successfulVerifications: [],
      failures: [failure],
      fileMutations: [],
      mutatedFiles: new Set(),
    };
  }

  test("write-capable root blocks an unresolved concrete failure without an explicit verification contract", async () => {
    const result = await taskCompletionRule.inspect({
      sessionID: "root-session",
      directory: process.cwd(),
      messages: [],
      currentTurn: [
        {
          info: { id: "u1", role: "user" },
          parts: [{ type: "text", text: "Fix the bug." }],
        },
        {
          info: { id: "a1", role: "assistant" },
          parts: [{ type: "text", text: "I made the change and am stopping here." }],
        },
      ],
      isSubagent: false,
      ruleConfig: {},
      evidence: failedEvidence(),
    });

    assert.equal(result.decision, "block");
    assert.ok(result.findings.some((finding) => finding.pattern === "unresolved test failure"));
  });

  test("V2 remediation remains synthetic and does not create a phantom pending prompt", async (t) => {
    const fs = await import("node:fs");
    const os = await import("node:os");
    const path = await import("node:path");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-chat-v2-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

    const synthetics = [];
    let promptCalls = 0;
    let releaseEvent;

    const context = {
      location: { directory: dir },
      options: { secrets: { enabled: false } },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            await new Promise((resolve) => {
              releaseEvent = resolve;
            });
            yield { type: "session.idle", data: { sessionID: "root-v2" } };
            await new Promise((resolve) => {
              if (signal.aborted) resolve();
              else signal.addEventListener("abort", resolve, { once: true });
            });
          })();
        },
      },
      session: {
        async hook() {
          return { async dispose() {} };
        },
        async get() {
          return { location: { directory: dir } };
        },
        async context() {
          return [
            { id: "u-v2", type: "user", text: "Fix the bug." },
            {
              id: "a-v2",
              type: "assistant",
              agent: "orchestrator",
              content: [{ type: "text", text: "The test failure is unrelated to this change." }],
            },
          ];
        },
        async prompt() {
          promptCalls++;
          return {};
        },
        async synthetic(input) {
          synthetics.push(input);
          return {};
        },
      },
    };

    const cleanup = await Guardian.setup(context);
    try {
      for (let i = 0; i < 50 && !releaseEvent; i++) {
        await new Promise((resolve) => setTimeout(resolve, 2));
      }
      assert.equal(typeof releaseEvent, "function");
      releaseEvent();

      for (let i = 0; i < 100 && synthetics.length === 0; i++) {
        await new Promise((resolve) => setTimeout(resolve, 2));
      }
      assert.equal(synthetics.length, 1, "agent remediation must still be delivered");
      assert.equal(promptCalls, 0, "V2 must not leave a resume:false user prompt waiting in the durable inbox");
      assert.equal(synthetics[0].delivery, "queue");
      assert.equal(synthetics[0].resume, true);
    } finally {
      await cleanup?.();
    }
  });


  test("V2 server exposes the latest safe intervention over plugin RPC", async (t) => {
    const fs = await import("node:fs");
    const os = await import("node:os");
    const path = await import("node:path");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-rpc-v2-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

    let rpcDefinition;
    let rpcHandlers;
    let releaseEvent;
    const synthetics = [];

    const context = {
      location: { directory: dir },
      options: { secrets: { enabled: false } },
      rpc: {
        async register(definition, handlers) {
          rpcDefinition = definition;
          rpcHandlers = handlers;
          return { async dispose() {} };
        },
      },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            await new Promise((resolve) => { releaseEvent = resolve; });
            yield { type: "session.idle", data: { sessionID: "root-rpc-v2" } };
            await new Promise((resolve) => {
              if (signal.aborted) resolve();
              else signal.addEventListener("abort", resolve, { once: true });
            });
          })();
        },
      },
      session: {
        async hook() { return { async dispose() {} }; },
        async get() { return { location: { directory: dir } }; },
        async context() {
          return [
            { id: "u-rpc-v2", type: "user", text: "Fix the bug." },
            {
              id: "a-rpc-v2",
              type: "assistant",
              agent: "orchestrator",
              content: [{ type: "text", text: "The test failure is unrelated to this change." }],
            },
          ];
        },
        async synthetic(input) {
          synthetics.push(input);
          return {};
        },
      },
    };

    const cleanup = await Guardian.setup(context);
    try {
      assert.equal(rpcDefinition?.id, GUARDIAN_INTERVENTION_RPC_ID);
      assert.equal(typeof rpcHandlers?.[GUARDIAN_INTERVENTION_RPC_METHOD], "function");

      for (let i = 0; i < 50 && !releaseEvent; i++) {
        await new Promise((resolve) => setTimeout(resolve, 2));
      }
      releaseEvent();

      for (let i = 0; i < 100 && synthetics.length === 0; i++) {
        await new Promise((resolve) => setTimeout(resolve, 2));
      }
      assert.equal(synthetics.length, 1);

      const snapshot = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({
        sessionID: "root-rpc-v2",
      });
      assert.equal(snapshot.active, true);
      assert.equal(snapshot.variant, "error");
      assert.match(snapshot.message, /discipline\/no-evasion/);
      assert.doesNotMatch(snapshot.message, /unrelated to this change/);
    } finally {
      await cleanup?.();
    }
  });


  test("display-only Guardian transcript rows never become human turn boundaries", () => {
    const messages = [
      {
        info: { id: "human-turn", role: "user" },
        parts: [{ type: "text", text: "Fix the bug." }],
      },
      {
        info: { id: "guardian-visible", role: "user" },
        parts: [{
          type: "text",
          text: "🔴 GUARDIAN · ERROR",
          ignored: true,
          metadata: {
            "opencode-guardian": true,
            "opencode-guardian-visible": true,
          },
        }],
      },
      {
        info: { id: "assistant-after-visible", role: "assistant" },
        parts: [{ type: "text", text: "Continuing." }],
      },
    ];

    const turn = extractCurrentTurn(messages);
    assert.equal(turn.turnKey, "human-turn");
    assert.equal(turn.currentTurn[0].info.id, "human-turn");
  });


  test("a stale Guardian remediation marker never suppresses a new substantive finding", async () => {
    const engine = new GuardEngine({
      enabled: true,
      remediationBudget: 1,
      rules: {
        "discipline/no-evasion": "error",
        "discipline/no-apology": "error",
        "quality/no-shortcuts": "off",
        "integrity/no-stubs": "off",
        "integrity/no-unverified-claims": "off",
        "integrity/no-silent-failure": "off",
        "safety/no-truncation": "off",
        "safety/destructive-operations": "off",
        "testing/no-cheat": "off",
        "security/no-secrets": "off",
        "manifest/no-ghost-deps": "off",
        "runtime/circuit-breaker": "off",
        "task/completion-gate": "off",
        "task/instruction-fidelity": "off",
      },
    });

    const first = [
      { info: { id: "u-stale", role: "user" }, parts: [{ type: "text", text: "Fix the bug." }] },
      {
        info: { id: "a-stale-1", role: "assistant" },
        parts: [{ type: "text", text: "The failure is unrelated to this change." }],
      },
    ];
    const firstResult = await engine.inspect("stale-marker", process.cwd(), first);
    assert.equal(firstResult.decision, "block");

    const remediated = [
      ...first,
      {
        info: { id: "g-stale", role: "user" },
        parts: [{
          type: "text",
          text: REMEDIATION_MARKER_2 + "\nAddress the finding.",
          synthetic: true,
          metadata: { "opencode-guardian": true },
        }],
      },
      {
        info: { id: "a-stale-2", role: "assistant" },
        parts: [{ type: "text", text: "I corrected the issue." }],
      },
    ];
    const secondResult = await engine.inspect("stale-marker", process.cwd(), remediated);
    assert.equal(secondResult.decision, "pass");

    const newFailure = [
      ...remediated,
      {
        info: { id: "a-stale-3", role: "assistant" },
        parts: [{ type: "text", text: "I'm sorry." }],
      },
    ];
    const thirdResult = await engine.inspect("stale-marker", process.cwd(), newFailure);
    assert.equal(
      thirdResult.decision,
      "block",
      "an old remediation marker must not turn later, different errors into a silent pass"
    );
    assert.ok(thirdResult.results.some(
      (result) => result.ruleId === "discipline/no-apology" && result.findings.length > 0
    ));
  });


  test("distinct substantive findings are not silently capped at three remediations in one human turn", async () => {
    const engine = new GuardEngine({
      enabled: true,
      remediationBudget: 1,
      rules: {
        "discipline/no-evasion": "off",
        "discipline/no-apology": "off",
        "quality/no-shortcuts": "off",
        "integrity/no-stubs": "off",
        "integrity/no-unverified-claims": "off",
        "integrity/no-silent-failure": "off",
        "safety/no-truncation": "off",
        "safety/destructive-operations": "off",
        "testing/no-cheat": "off",
        "security/no-secrets": "off",
        "manifest/no-ghost-deps": "off",
        "runtime/circuit-breaker": "off",
        "task/completion-gate": "off",
        "task/instruction-fidelity": "off",
      },
    });

    for (const n of [1, 2, 3, 4]) {
      engine.registerRule({
        id: `test/substantive-${n}`,
        description: `test rule ${n}`,
        inspect(context) {
          const text = context.currentTurn
            .findLast((message) => message.info.role === "assistant")
            ?.parts.find((part) => part.type === "text")?.text ?? "";
          if (!text.includes(`ERR_${n}`)) {
            return { ruleId: this.id, decision: "pass", findings: [] };
          }
          return {
            ruleId: this.id,
            decision: "block",
            findings: [{
              ruleId: this.id,
              pattern: `substantive-${n}`,
              messageSnippet: `ERR_${n}`,
              description: `substantive finding ${n}`,
              confidence: "high",
              fingerprint: `substantive-${n}`,
            }],
            remediationPrompt: `Correct substantive finding ${n}.`,
          };
        },
      });
    }

    const messages = [
      { info: { id: "u-many", role: "user" }, parts: [{ type: "text", text: "Fix every issue you find." }] },
    ];

    for (const n of [1, 2, 3, 4]) {
      if (n > 1) {
        messages.push({
          info: { id: `g-many-${n - 1}`, role: "user" },
          parts: [{
            type: "text",
            text: REMEDIATION_MARKER_2 + `\nCorrect finding ${n - 1}.`,
            synthetic: true,
            metadata: { "opencode-guardian": true },
          }],
        });
      }
      messages.push({
        info: { id: `a-many-${n}`, role: "assistant" },
        parts: [{ type: "text", text: `ERR_${n}` }],
      });

      const result = await engine.inspect("many-findings", process.cwd(), [...messages]);
      assert.equal(
        result.decision,
        "block",
        `distinct finding ${n} must still receive remediation`
      );
    }
  });


  test("fingerprint budget allows a new pattern on the same rule but stops the repeated pattern", async () => {
    const engine = new GuardEngine({
      enabled: true,
      remediationBudget: 1,
      rules: {
        "discipline/no-evasion": "error",
        "discipline/no-apology": "off",
        "quality/no-shortcuts": "off",
        "integrity/no-stubs": "off",
        "integrity/no-unverified-claims": "off",
        "integrity/no-silent-failure": "off",
        "safety/no-truncation": "off",
        "safety/destructive-operations": "off",
        "testing/no-cheat": "off",
        "security/no-secrets": "off",
        "manifest/no-ghost-deps": "off",
        "runtime/circuit-breaker": "off",
        "task/completion-gate": "off",
        "task/instruction-fidelity": "off",
      },
    });

    const first = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the bug." }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [{ type: "text", text: "The failure is unrelated to this change." }],
      },
    ];
    const result1 = await engine.inspect("same-rule-budget", process.cwd(), first);
    assert.equal(result1.decision, "block");

    const second = [
      ...first,
      {
        info: { id: "g1", role: "user" },
        parts: [{
          type: "text",
          text: REMEDIATION_MARKER_2 + "\nAddress the finding.",
          synthetic: true,
          metadata: { "opencode-guardian": true },
        }],
      },
      {
        info: { id: "a2", role: "assistant" },
        parts: [{ type: "text", text: "That problem is outside the scope of this task." }],
      },
    ];
    const result2 = await engine.inspect("same-rule-budget", process.cwd(), second);
    assert.equal(
      result2.decision,
      "block",
      "a substantively different pattern on the same broad rule must still remediate"
    );

    const third = [
      ...second,
      {
        info: { id: "g2", role: "user" },
        parts: [{
          type: "text",
          text: REMEDIATION_MARKER_2 + "\nAddress the new finding.",
          synthetic: true,
          metadata: { "opencode-guardian": true },
        }],
      },
      {
        info: { id: "a3", role: "assistant" },
        parts: [{ type: "text", text: "I still consider it outside the scope of this task for now." }],
      },
    ];
    const result3 = await engine.inspect("same-rule-budget", process.cwd(), third);
    assert.equal(
      result3.decision,
      "pass",
      "the same finding pattern must remain bounded instead of looping on wording changes"
    );
  });

  test("Dalga 1 (G-09): forgetGuardianProvenance and plugin dispose only clear Guardian state, preserving sibling mesh plugins", async (t) => {
    const sessionID = "sess-mesh-owner-isolation";
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-mesh-iso-"));
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      preflight: { enabled: false },
      secrets: { enabled: false },
    }));
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
    t.after(() => {
      forgetMeshSession(sessionID);
      if (origStateDir === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      fs.rmSync(directory, { recursive: true, force: true });
    });

    // Sibling plugins stamp provenance, hold a lease, and set an active handoff
    const hiMeta = stampMeshMetadata(sessionID, { owner: "opencode-hi", kind: "wake" });
    const releaseSmartLease = acquireSessionLease({
      sessionID,
      owner: "opencode-smart-questions",
      kind: "user_interaction",
      ttlMs: 30_000,
    });
    setActiveMeshHandoff(sessionID, {
      handoffId: "ho-sibling-1",
      source: "opencode-hi",
      action: "question_required",
      kind: "choice",
      autoSelect: "forbidden",
      createdAt: Date.now(),
    });
    const guardianMeta = createGuardianMessageMetadata(sessionID, "remediation");

    // Guardian forgets its own provenance (as done on LRU eviction / dispose)
    forgetGuardianProvenance(sessionID);

    assert.equal(
      isTrustedGuardianMetadata(sessionID, guardianMeta, "remediation"),
      false,
      "Guardian's own provenance must be forgotten"
    );
    assert.equal(
      verifyMeshMetadata(sessionID, hiMeta, "wake", "opencode-hi"),
      true,
      "sibling plugin provenance must NOT be wiped by forgetGuardianProvenance"
    );
    assert.ok(
      getBlockingSessionLease(sessionID, "active_remediation", "opencode-guardian"),
      "sibling plugin user_interaction lease must remain active"
    );
    assert.equal(
      getActiveMeshHandoff(sessionID)?.handoffId,
      "ho-sibling-1",
      "sibling active mesh handoff must remain intact"
    );
    releaseSmartLease();
  });

  test("Dalga 1 (G-19): stale role/skill resolver disposer does not delete a newer registration for the same owner/directory", async () => {
    const dir = "/tmp/guardian-resolver-race";
    const disposeOldRole = registerRoleProfileResolver({
      owner: "opencode-hi",
      directory: dir,
      resolve: () => ({ capability: "read-only", role: "old-role" }),
    });
    const disposeNewRole = registerRoleProfileResolver({
      owner: "opencode-hi",
      directory: dir,
      resolve: () => ({ capability: "write-allowed", role: "new-role" }),
    });
    disposeOldRole();
    try {
      const resolved = await resolveMeshAgentProfile("sess-r1", dir);
      assert.equal(resolved?.role, "new-role", "old role resolver disposer must not delete newer registration");
    } finally {
      disposeNewRole();
    }

    const disposeOldSkill = registerSkillCatalogProvider({
      owner: "opencode-hi",
      directory: dir,
      search: () => [{ id: "old-skill", title: "Old", score: 1 }],
    });
    const disposeNewSkill = registerSkillCatalogProvider({
      owner: "opencode-hi",
      directory: dir,
      search: () => [{ id: "new-skill", title: "New", score: 1 }],
    });
    disposeOldSkill();
    try {
      const hits = await queryMeshSkills("test", { directory: dir });
      assert.equal(hits?.[0]?.id, "new-skill", "old skill provider disposer must not delete newer registration");
    } finally {
      disposeNewSkill();
    }
  });

  test("Dalga 1 (G-12): foreground subagent remediation does not copy stale pre-remediation [TASK OUTCOME] onto revised result", async (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-subagent-outcome-"));
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      preflight: { enabled: false },
      secrets: { enabled: false },
    }));
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
    const sessionID = "parent-outcome-1";
    const childID = "child-outcome-1";
    t.after(() => {
      forgetMeshSession(sessionID);
      forgetMeshSession(childID);
      if (origStateDir === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      fs.rmSync(directory, { recursive: true, force: true });
    });

    const unregisterRole = registerRoleProfileResolver({
      owner: "test-orch",
      directory,
      resolve: (sid) => (sid === childID ? { capability: "write-allowed", role: "coder" } : undefined),
    });
    t.after(() => unregisterRole());

    let toolBeforeHook;
    let toolAfterHook;
    let childMsgs = [
      { id: "cu1", type: "user", text: "Fix src/app.ts" },
      { id: "ca1", type: "assistant", content: [{ type: "text", text: "I apologize, I cannot fix it right now." }] },
    ];
    const host = {
      location: { directory },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            await new Promise((resolve) => {
              if (signal.aborted) resolve();
              else signal.addEventListener("abort", resolve, { once: true });
            });
          })();
        },
      },
      tool: {
        hook(kind, fn) {
          if (kind === "execute.before") toolBeforeHook = fn;
          if (kind === "execute.after") toolAfterHook = fn;
          return { dispose() {} };
        },
      },
      session: {
        async get({ sessionID: sid }) {
          return { id: sid, parentID: sid === childID ? sessionID : undefined, location: { directory } };
        },
        async context({ sessionID: sid }) {
          return sid === childID ? childMsgs : [];
        },
        async synthetic() {
          // Remediation fixes the response with a new outcome
          childMsgs = [
            ...childMsgs,
            { id: "cg1", type: "user", text: "[opencode-guardian remediation] fix it", metadata: { "opencode-guardian": true } },
            { id: "ca2", type: "assistant", content: [{ type: "text", text: "Implemented the fix in src/app.ts." }] },
          ];
        },
        async wait() {},
      },
    };

    const cleanup = await Guardian.setup(host);
    try {
      await toolBeforeHook({
        id: "call-outcome-1",
        sessionID,
        tool: "subagent",
        input: { prompt: "Fix src/app.ts", background: false },
      });
      const afterEvent = {
        id: "call-outcome-1",
        sessionID,
        tool: "subagent",
        status: "completed",
        input: { prompt: "Fix src/app.ts", background: false },
        result: {
          output: {
            sessionID: childID,
            status: "completed",
            output: "I apologize, I cannot fix it right now.\n[TASK OUTCOME] task_id=t1 status=blocked reason=gave-up",
          },
          content: "<subagent sessionID=\"child-outcome-1\" state=\"completed\">\nI apologize, I cannot fix it right now.\n[TASK OUTCOME] task_id=t1 status=blocked reason=gave-up\n</subagent>",
          metadata: { sessionID: childID, status: "completed" },
        },
      };
      await toolAfterHook(afterEvent);
      assert.equal(
        afterEvent.result.output.output,
        "Implemented the fix in src/app.ts.",
        "stale pre-remediation [TASK OUTCOME] status=blocked must NOT be appended onto remediated output"
      );
      assert.ok(
        !afterEvent.result.content.includes("status=blocked"),
        "stale pre-remediation blocked outcome must not leak into content"
      );
    } finally {
      await cleanup?.();
    }
  });

  test("Dalga 2 (G-10): host read-only session permissions override a mesh write-allowed role profile", async (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-g10-perm-"));
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      preflight: { enabled: false },
      secrets: { enabled: false },
    }));
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
    const parentID = "parent-g10";
    const childID = "child-g10-readonly";
    t.after(() => {
      forgetMeshSession(parentID);
      forgetMeshSession(childID);
      clearAllAgentCapabilities();
      if (origStateDir === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      fs.rmSync(directory, { recursive: true, force: true });
    });

    // Stale/permissive peer mesh profile claims write-allowed, but host agent permissions deny edit & shell!
    const unregisterRole = registerRoleProfileResolver({
      owner: "stale-mesh-peer",
      directory,
      resolve: (sid) => (sid === childID ? { capability: "write-allowed", role: "coder", agentName: "readonly-agent" } : undefined),
    });
    t.after(() => unregisterRole());

    let toolBeforeHook;
    let toolAfterHook;
    const synthetics = [];
    const host = {
      location: { directory },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            await new Promise((r) => signal.addEventListener("abort", r, { once: true }));
          })();
        },
      },
      agent: {
        async list() {
          return [{
            id: "readonly-agent",
            name: "readonly-agent",
            permissions: [
              { permission: "edit", pattern: "*", action: "deny" },
              { permission: "bash", pattern: "*", action: "deny" },
              { permission: "shell", pattern: "*", action: "deny" },
            ],
          }];
        },
      },
      tool: {
        hook(kind, fn) {
          if (kind === "execute.before") toolBeforeHook = fn;
          if (kind === "execute.after") toolAfterHook = fn;
          return { dispose() {} };
        },
      },
      session: {
        async get({ sessionID: sid }) {
          return { id: sid, parentID: sid === childID ? parentID : undefined, agent: "readonly-agent", location: { directory } };
        },
        async context() {
          return [
            { id: "cu1", type: "user", text: "Inspect code" },
            { id: "ca1", type: "assistant", content: [{ type: "text", text: "This test failure is unrelated to my changes." }] },
          ];
        },
        async synthetic(input) { synthetics.push(input); },
        async wait() {},
      },
    };

    const cleanup = await Guardian.setup(host);
    try {
      await toolBeforeHook({ id: "call-g10", sessionID: parentID, tool: "subagent", input: { prompt: "Inspect", background: false } });
      await toolAfterHook({
        id: "call-g10",
        sessionID: parentID,
        tool: "subagent",
        status: "completed",
        input: { prompt: "Inspect", background: false },
        result: {
          output: { sessionID: childID, status: "completed", output: "This test failure is unrelated to my changes." },
          metadata: { sessionID: childID, status: "completed" },
        },
      });
      assert.equal(synthetics.length, 0, "host read-only permissions must prevent write remediation even if mesh resolver claims write-allowed");
    } finally {
      await cleanup?.();
    }
  });

  test("Dalga 2 (G-11): finalizeSubagentHandoff renews active_remediation lease while sendAndWait exceeds initial TTL", async (t) => {
    const { finalizeSubagentHandoff } = await import("../dist/index.js");
    const sessionID = "child-g11-long-remediation";
    t.after(() => forgetMeshSession(sessionID));

    const engine = new GuardEngine({ enabled: true, remediationBudget: 1 });
    let round = 0;
    let leaseStillActiveMidFlight = false;
    await finalizeSubagentHandoff({
      sessionID,
      directory: process.cwd(),
      engine,
      leaseTtlMs: 120,
      resolveCapability: async () => ({ capability: "write-allowed", evidence: { reasons: ["test"] } }),
      fetchMessages: async () => {
        round++;
        if (round === 1) {
          return [
            { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the bug" }] },
            { info: { id: "a1", role: "assistant" }, parts: [{ type: "text", text: "This test failure is unrelated to my changes." }] },
          ];
        }
        return [
          { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the bug" }] },
          { info: { id: "a1", role: "assistant" }, parts: [{ type: "text", text: "This test failure is unrelated to my changes." }] },
          { info: { id: "g1", role: "user" }, parts: [{ type: "text", text: REMEDIATION_MARKER + "\nFix it.", synthetic: true, metadata: { "opencode-guardian": true } }] },
          { info: { id: "a2", role: "assistant" }, parts: [{ type: "text", text: "Fixed the bug directly." }] },
        ];
      },
      sendAndWait: async () => {
        // Exceed initial 120ms lease TTL (wait 220ms) and check orchestrator view of lease
        await new Promise((r) => setTimeout(r, 220));
        leaseStillActiveMidFlight = Boolean(
          getBlockingSessionLease(sessionID, "orchestration_dispatch", "opencode-hi")
        );
      },
    });

    assert.equal(
      leaseStillActiveMidFlight,
      true,
      "active_remediation lease must stay renewed via heartbeat while sendAndWait runs past initial TTL"
    );
    assert.equal(
      getBlockingSessionLease(sessionID, "orchestration_dispatch", "opencode-hi"),
      undefined,
      "active_remediation lease must be released once remediation finishes"
    );
  });

  test("Dalga 3 (G-20): verifyMeshMetadata rejects tampered trust-critical envelope fields against immutable ledger", (t) => {
    const sessionID = "sess-g20-tamper";
    t.after(() => forgetMeshSession(sessionID));

    const meta = stampMeshMetadata(sessionID, {
      owner: "opencode-guardian",
      kind: "remediation",
      protected: true,
      sanitizedBy: ["opencode-guardian"],
      boundedBy: "opencode-guardian",
      taskID: "task-1",
      requiredSkills: ["skill-a"],
    });
    assert.equal(verifyMeshMetadata(sessionID, meta, "remediation", "opencode-guardian"), true);

    const tamperedTask = {
      ...meta,
      "opencode-mesh": { ...meta["opencode-mesh"], taskID: "task-hijacked" },
    };
    assert.equal(
      verifyMeshMetadata(sessionID, tamperedTask, "remediation", "opencode-guardian"),
      false,
      "tampered taskID must fail provenance verification"
    );

    const tamperedProtected = {
      ...meta,
      "opencode-mesh": { ...meta["opencode-mesh"], protected: false },
    };
    assert.equal(
      verifyMeshMetadata(sessionID, tamperedProtected, "remediation", "opencode-guardian"),
      false,
      "tampered protected flag must fail provenance verification"
    );

    const tamperedSkills = {
      ...meta,
      "opencode-mesh": { ...meta["opencode-mesh"], requiredSkills: ["skill-a", "evil-skill"] },
    };
    assert.equal(
      verifyMeshMetadata(sessionID, tamperedSkills, "remediation", "opencode-guardian"),
      false,
      "tampered requiredSkills must fail provenance verification"
    );
  });

  test("R3 Dalga 1 (R3-005, R3-006): host write-requires-approval overrides mesh write-allowed and host child.agent overrides spoofed mesh/input agentName", async (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-r3-005-006-"));
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      preflight: { enabled: false },
      secrets: { enabled: false },
    }));
    const origStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
    const parentID = "parent-r3-005";
    const childAskID = "child-r3-ask";
    const childSpoofID = "child-r3-spoof";
    t.after(() => {
      forgetMeshSession(parentID);
      forgetMeshSession(childAskID);
      forgetMeshSession(childSpoofID);
      clearAllAgentCapabilities();
      if (origStateDir === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = origStateDir;
      fs.rmSync(directory, { recursive: true, force: true });
    });

    const unregisterRole = registerRoleProfileResolver({
      owner: "permissive-peer",
      directory,
      resolve: (sid) => {
        if (sid === childAskID) return { capability: "write-allowed", role: "coder", agentName: "ask-agent" };
        // R3-006: mesh claims permissive agentName "coder-agent" even though host session.agent is "readonly-agent"
        if (sid === childSpoofID) return { capability: "write-allowed", role: "coder", agentName: "coder-agent" };
        return undefined;
      },
    });
    t.after(() => unregisterRole());

    let toolBeforeHook;
    let toolAfterHook;
    const synthetics = [];
    const host = {
      location: { directory },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            await new Promise((r) => signal.addEventListener("abort", r, { once: true }));
          })();
        },
      },
      agent: {
        async list() {
          return [
            {
              id: "ask-agent",
              name: "ask-agent",
              permissions: [
                { permission: "edit", pattern: "*", action: "ask" },
                { permission: "shell", pattern: "*", action: "ask" },
              ],
            },
            {
              id: "readonly-agent",
              name: "readonly-agent",
              permissions: [
                { permission: "edit", pattern: "*", action: "deny" },
                { permission: "shell", pattern: "*", action: "deny" },
                { permission: "bash", pattern: "*", action: "deny" },
              ],
            },
            {
              id: "coder-agent",
              name: "coder-agent",
              permissions: [{ permission: "edit", pattern: "*", action: "allow" }],
            },
          ];
        },
      },
      tool: {
        hook(kind, fn) {
          if (kind === "execute.before") toolBeforeHook = fn;
          if (kind === "execute.after") toolAfterHook = fn;
          return { dispose() {} };
        },
      },
      session: {
        async get({ sessionID: sid }) {
          if (sid === childAskID) return { id: sid, parentID, agent: "ask-agent", location: { directory } };
          if (sid === childSpoofID) return { id: sid, parentID, agent: "readonly-agent", location: { directory } };
          return { id: sid, location: { directory } };
        },
        async context() {
          return [
            { id: "u1", type: "user", text: "Check code" },
            { id: "a1", type: "assistant", content: [{ type: "text", text: "This test failure is unrelated to my changes." }] },
          ];
        },
        async synthetic(input) { synthetics.push(input); },
        async wait() {},
      },
    };

    const cleanup = await Guardian.setup(host);
    try {
      // R3-005: host ask-agent (write-requires-approval) must NOT be overridden by mesh write-allowed
      await toolBeforeHook({ id: "c-ask", sessionID: parentID, tool: "subagent", input: { prompt: "Check", background: false } });
      await toolAfterHook({
        id: "c-ask",
        sessionID: parentID,
        tool: "subagent",
        status: "completed",
        input: { prompt: "Check", background: false },
        result: { output: { sessionID: childAskID, status: "completed", output: "This test failure is unrelated to my changes." }, metadata: { sessionID: childAskID, status: "completed" } },
      });
      assert.equal(synthetics.length, 0, "R3-005: host write-requires-approval must prevent autonomous remediation despite mesh write-allowed");

      // R3-006: host child.agent="readonly-agent" must override input.agent="coder-agent" AND meshProfile.agentName="coder-agent"
      await toolBeforeHook({ id: "c-spoof", sessionID: parentID, tool: "subagent", input: { prompt: "Check", agent: "coder-agent", background: false } });
      await toolAfterHook({
        id: "c-spoof",
        sessionID: parentID,
        tool: "subagent",
        status: "completed",
        input: { prompt: "Check", agent: "coder-agent", background: false },
        result: { output: { sessionID: childSpoofID, status: "completed", output: "This test failure is unrelated to my changes." }, metadata: { sessionID: childSpoofID, status: "completed" } },
      });
      assert.equal(synthetics.length, 0, "R3-006: host child.agent must take authority over input.agent and meshProfile.agentName");
    } finally {
      await cleanup?.();
    }
  });

  test("R3 Dalga 2 (R3-014, R3-015, R3-025, R3-026, R3-027, R3-028, R3-029): mesh tamper rejection, TTL cap, directory isolation, resolver precedence, RPC standby failover, and owner-scoped intervention clear", async (t) => {
    const {
      clearMeshIntervention,
      hasMeshCapability,
      registerMeshPeer,
      registerMeshStateRpc,
      resetMeshStateForTests,
    } = await import("../dist/bridge.js");

    // R3-014: tampered ledger token must NEVER pass isTrustedMeshMessage via isHostSynthetic fallback
    const sid14 = "sess-r3-014-tamper";
    t.after(() => forgetMeshSession(sid14));
    const stamped = stampMeshMetadata(sid14, {
      owner: "opencode-guardian",
      kind: "remediation",
      protected: true,
      taskID: "real-task",
    });
    const tamperedSyntheticMsg = {
      type: "synthetic",
      synthetic: true,
      metadata: {
        ...stamped,
        "opencode-mesh": { ...stamped["opencode-mesh"], taskID: "hijacked-task" },
      },
    };
    assert.equal(
      isTrustedMeshMessage(tamperedSyntheticMsg, sid14, "remediation"),
      false,
      "R3-014: tampered token present in ledger must never fall back to trusted via isHostSynthetic"
    );

    // R3-015 & R3-027: lease TTL must be capped (cannot lock session for 1e15 ms)
    const sid15 = "sess-r3-015-ttl";
    t.after(() => forgetMeshSession(sid15));
    const releaseLong = acquireSessionLease({
      sessionID: sid15,
      owner: "remote-caller",
      kind: "user_interaction",
      ttlMs: 1e15,
    });
    const blocker = getBlockingSessionLease(sid15, "active_remediation", "opencode-guardian");
    assert.ok(blocker, "lease should be active");
    assert.ok(
      blocker.expiresAt - blocker.acquiredAt <= 10 * 60_000,
      `R3-015/R3-027: lease TTL must be capped at <= 10 minutes, got ${blocker.expiresAt - blocker.acquiredAt}ms`
    );
    releaseLong();

    // R3-025: directory-scoped v2 peer must NOT leak capability into unrelated directory via legacy fallback
    resetMeshStateForTests();
    t.after(() => resetMeshStateForTests());
    const dirA = "/tmp/r3-025-proj-a";
    const dirB = "/tmp/r3-025-proj-b";
    const unregA = registerMeshPeer({
      id: "opencode-guardian",
      version: "0.17.9",
      directory: dirA,
      capabilities: ["policy.gate"],
    });
    try {
      assert.equal(hasMeshCapability("policy.gate", dirA), true);
      assert.equal(
        hasMeshCapability("policy.gate", dirB),
        false,
        "R3-025: policy.gate registered only for dirA must not leak into dirB via legacy registry"
      );
    } finally {
      unregA();
    }

    // R3-026: exact directory resolver beats earlier wildcard "*" resolver, and sessionID mismatch is rejected
    const targetDir = "/tmp/r3-026-exact";
    const disposeWildcard = registerRoleProfileResolver({
      owner: "global-peer",
      directory: "*",
      resolve: () => ({ capability: "read-only", role: "wildcard-role", managedBy: "global-peer" }),
    });
    const disposeExact = registerRoleProfileResolver({
      owner: "local-peer",
      directory: targetDir,
      resolve: (sid) =>
        sid === "sess-mismatch"
          ? { sessionID: "different-session", capability: "write-allowed", role: "wrong-session", managedBy: "local-peer" }
          : { sessionID: sid, capability: "write-allowed", role: "exact-role", managedBy: "local-peer" },
    });
    try {
      const exactMatch = await resolveMeshAgentProfile("sess-ok", targetDir);
      assert.equal(exactMatch?.role, "exact-role", "R3-026: exact directory resolver must take precedence over earlier wildcard");
      const mismatched = await resolveMeshAgentProfile("sess-mismatch", targetDir);
      assert.equal(mismatched?.role, "wildcard-role", "R3-026: mismatched profile.sessionID must be rejected");
    } finally {
      disposeExact();
      disposeWildcard();
    }

    // R3-028: primary RPC register failure must promote queued standby with candidate's own directory
    resetMeshStateForTests();
    let rejectPrimary;
    const primaryDone = registerMeshStateRpc({
      owner: "primary-failing",
      directory: "/tmp/r3-028-primary",
      rpcRegister: () => new Promise((_res, rej) => { rejectPrimary = rej; }),
    });
    let standbyRegistered = false;
    const disposeStandby = await registerMeshStateRpc({
      owner: "standby-peer",
      directory: "/tmp/r3-028-primary",
      rpcRegister: async () => {
        standbyRegistered = true;
        return { dispose() {} };
      },
    });
    rejectPrimary(new Error("primary rpc failed"));
    await primaryDone;
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(standbyRegistered, true, "R3-028: queued standby must be promoted when primary rpcRegister fails");
    await disposeStandby();

    // R3-029: owner-scoped clearMeshIntervention must not delete sibling plugin's intervention
    const sid29 = "sess-r3-029-owner";
    t.after(() => forgetMeshSession(sid29));
    recordMeshIntervention({
      sessionID: sid29,
      directory: "/tmp/r3-029",
      owner: "opencode-hi",
      kind: "post-warning",
      ruleIds: ["hi/stall"],
      deterministic: false,
      active: true,
      updatedAt: Date.now(),
    });
    clearMeshIntervention(sid29, "opencode-guardian");
    assert.equal(
      getLatestMeshIntervention(sid29)?.owner,
      "opencode-hi",
      "R3-029: Guardian owner-scoped clear must not wipe sibling plugin intervention"
    );
  });

  test("R4 Wave 2 (R4-043, R4-008): same-tier role resolvers merge restrictively and legacy isTrustedMeshMessage enforces expectedKind", async (t) => {
    const {
      resetMeshStateForTests: resetMesh,
      registerRoleProfileResolver: regResolver,
      resolveMeshAgentProfile: resolveProfile,
      isTrustedMeshMessage: isTrusted,
    } = await import("../dist/bridge.js");
    resetMesh();
    t.after(() => resetMesh());

    const dir = "/tmp/r4-043-restrictive";
    const disposePermissive = regResolver({
      owner: "peer-permissive",
      directory: dir,
      resolve: () => ({ capability: "write-allowed", managedBy: "peer-permissive" }),
    });
    const disposeRestrictive = regResolver({
      owner: "peer-restrictive",
      directory: dir,
      resolve: () => ({ capability: "read-only", managedBy: "peer-restrictive" }),
    });
    t.after(() => {
      disposePermissive();
      disposeRestrictive();
    });

    const merged = await resolveProfile("sess-r4-043", dir);
    assert.equal(
      merged?.capability,
      "read-only",
      "R4-043: most restrictive capability in same directory tier must win regardless of registration order"
    );

    // R4-008: legacy fallback must respect expectedKind (peer hi message is NOT a Guardian remediation)
    const peerWake = {
      type: "synthetic",
      synthetic: true,
      metadata: { "opencode-hi": true, "hi-internal": "wake" },
    };
    assert.equal(
      isTrusted(peerWake, "sess-r4-008", "remediation"),
      false,
      "R4-008: legacy fallback must not match opencode-hi peer wake as Guardian remediation"
    );

    // Re-audit closure: meshEnv.synthetic === false must NOT fall through to legacy metadata,
    // and legacy visible marker must not satisfy remediation/handoff expectedKind
    const nonSyntheticEnvelope = {
      synthetic: true,
      metadata: {
        "opencode-mesh": { v: 2, owner: "opencode-guardian", kind: "remediation", synthetic: false },
        "opencode-guardian": true,
      },
    };
    assert.equal(
      isTrusted(nonSyntheticEnvelope, "sess-r4-008"),
      false,
      "V2 mesh envelope with synthetic: false must reject immediately without legacy fallthrough"
    );
    const legacyVisible = {
      synthetic: true,
      metadata: { "opencode-guardian": true, "opencode-guardian-visible": true },
    };
    assert.equal(
      isTrusted(legacyVisible, "sess-r4-008", "remediation"),
      false,
      "legacy visible marker must never satisfy remediation expectedKind"
    );
    assert.equal(
      isTrusted(legacyVisible, "sess-r4-008", "visible"),
      true,
      "legacy visible marker still matches visible expectedKind"
    );
  });
});
