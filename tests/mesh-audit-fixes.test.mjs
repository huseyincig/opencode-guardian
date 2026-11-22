import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, {
  GuardEngine,
  parseOpenCodeHandoff,
  sanitizeObject,
  stampMeshMetadata,
  verifyMeshMetadata,
  isTrustedMeshMessage,
  forgetMeshSession,
  normalizeV2Messages,
  extractTaskContract,
  sanitizeUserInstruction,
  isSessionRemediating,
  getLatestMeshIntervention,
  recordMeshIntervention,
  getCachedAgentCapability,
  clearAllAgentCapabilities,
  GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD,
  GUARDIAN_INTERVENTION_RPC_DEFINITION,
} from "../dist/index.js";
import { getActiveMeshHandoff, setActiveMeshHandoff, MESH_SYMBOL } from "../dist/bridge.js";
import { authorizationText } from "../dist/task-constraints.js";

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

