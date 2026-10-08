import test from "node:test";
import assert from "node:assert/strict";
import Guardian, {
  GuardEngine,
  REMEDIATION_MARKER,
  taskCompletionRule,
  extractCurrentTurn,
  GUARDIAN_INTERVENTION_RPC_ID,
  GUARDIAN_INTERVENTION_RPC_METHOD,
} from "../dist/index.js";

const v1Server = Guardian.server;

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


test("V1 remediation creates a visible display-only Guardian transcript message", async (t) => {
  const fs = await import("node:fs");
  const os = await import("node:os");
  const path = await import("node:path");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-chat-v1-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const prompts = [];
  const mockClient = {
    session: {
      get: async () => ({ data: { parentID: undefined } }),
      messages: async () => ({
        data: [
          {
            info: { id: "u1", role: "user" },
            parts: [{ type: "text", text: "Fix the bug." }],
          },
          {
            info: { id: "a1", role: "assistant", time: { completed: 1 } },
            parts: [{ type: "text", text: "The test failure is unrelated to this change." }],
          },
        ],
      }),
      promptAsync: async (request) => {
        prompts.push(request);
        return { data: {} };
      },
    },
  };

  const hooks = await v1Server({ client: mockClient, directory: dir });
  await hooks.event({
    event: {
      type: "session.idle",
      properties: { sessionID: "root-v1" },
    },
  });

  const remediation = prompts.find((request) => request.body?.parts?.[0]?.synthetic === true);
  assert.ok(remediation, "synthetic remediation must still be delivered to the agent");

  const visible = prompts.find((request) =>
    request.body?.noReply === true &&
    request.body?.parts?.[0]?.ignored === true &&
    request.body?.parts?.[0]?.synthetic !== true &&
    request.body?.parts?.[0]?.metadata?.["opencode-guardian-visible"] === true
  );

  assert.ok(visible, "Guardian intervention must also be visible in the transcript");
  const text = visible.body.parts[0].text;
  assert.match(text, /GUARDIAN · ERROR/);
  assert.match(text, /discipline\/no-evasion/);
  assert.doesNotMatch(text, /unrelated to this change/);
});


test("V1 visible Guardian transcript rows never become human task contracts", async () => {
  const mockClient = { session: {} };
  const hooks = await v1Server({ client: mockClient, directory: process.cwd() });

  await hooks["chat.message"](
    { sessionID: "display-only-v1", messageID: "guardian-display-1" },
    {
      parts: [{
        type: "text",
        text: "Implement this change and run tests.",
        ignored: true,
        metadata: {
          "opencode-guardian": true,
          "opencode-guardian-visible": true,
        },
      }],
    }
  );

  const transformed = { system: [] };
  await hooks["experimental.chat.system.transform"](
    { sessionID: "display-only-v1" },
    transformed
  );

  assert.deepEqual(
    transformed.system,
    [],
    "display-only Guardian rows must not replace the actual human task contract"
  );
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
        text: REMEDIATION_MARKER + "\nAddress the finding.",
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
          text: REMEDIATION_MARKER + `\nCorrect finding ${n - 1}.`,
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
        text: REMEDIATION_MARKER + "\nAddress the finding.",
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
        text: REMEDIATION_MARKER + "\nAddress the new finding.",
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
