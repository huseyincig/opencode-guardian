import test from "node:test";
import assert from "node:assert/strict";
import {
  OpencodeGuardian,
  GuardEngine,
  evaluateAgentMutationProfile,
  parseOpenCodeHandoff,
} from "../dist/index.js";

// Scenario 1: Read-only child completion result
test("Scenario 1: Read-only child subagent completion result receives zero remediation (V1 and V2)", async () => {
  // --- V1 Test ---
  let v1PromptCalls = 0;
  const v1Messages = [
    {
      info: { id: "m-user-1", role: "user" },
      parts: [{ type: "text", text: "Run all tests and verify everything before claiming completion." }],
    },
    {
      info: { id: "m-asst-1", role: "assistant", agent: "code-reviewer" },
      parts: [{ type: "text", text: "Review completed. Test execution skipped due to read-only role. All looks good." }],
    },
  ];

  const v1Client = {
    session: {
      get: async () => ({ data: { id: "v1-child-1", parentID: "v1-parent-1" } }),
      messages: async () => ({ data: v1Messages }),
      prompt: async () => { v1PromptCalls++; return { data: {} }; },
      promptAsync: async () => { v1PromptCalls++; return { data: {} }; },
    },
    app: {
      agents: async () => ({
        data: [{
          name: "code-reviewer",
          permission: { edit: "deny", bash: "deny" },
          tools: { read_file: true, grep: true },
        }],
      }),
    },
  };

  const v1Plugin = await OpencodeGuardian.server({ client: v1Client, directory: process.cwd() });
  await v1Plugin["tool.execute.before"](
    { tool: "task", sessionID: "v1-parent-1", callID: "call-1" },
    { args: { agent: "code-reviewer", prompt: "review" } }
  );
  const v1Output = {
    output: "Initial review output",
    metadata: { sessionId: "v1-child-1", background: false },
  };
  await v1Plugin["tool.execute.after"](
    { tool: "task", sessionID: "v1-parent-1", callID: "call-1", args: { agent: "code-reviewer" } },
    v1Output
  );
  await v1Plugin.dispose();
  assert.equal(v1PromptCalls, 0, "V1 read-only child must receive 0 synthetic prompts");
  assert.match(v1Output.output, /Review completed\. Test execution skipped/, "V1 child output flows through safely");

  // --- V2 Test ---
  const v2Hooks = new Map();
  let v2SyntheticCalls = 0;
  const v2Context = {
    location: { directory: process.cwd() },
    event: { subscribe() { return (async function* () {})(); } },
    tool: {
      async hook(name, cb) {
        const list = v2Hooks.get(name) ?? [];
        list.push(cb);
        v2Hooks.set(name, list);
        return { async dispose() {} };
      },
    },
    agent: {
      async list() {
        return {
          data: [{
            name: "code-reviewer",
            permissions: [
              { action: "edit", effect: "deny" },
              { action: "bash", effect: "deny" },
            ],
            tools: { read_file: true },
          }],
        };
      },
    },
    session: {
      async hook() { return { async dispose() {} }; },
      async get({ sessionID }) {
        return {
          id: sessionID,
          parentID: "v2-parent-1",
          location: { directory: process.cwd() },
          permissions: [
            { action: "edit", effect: "deny" },
            { action: "bash", effect: "deny" },
          ],
        };
      },
      async context() {
        return [
          { id: "u1", type: "user", text: "Run all tests and verify everything before claiming completion." },
          { id: "a1", type: "assistant", agent: "code-reviewer", content: [{ type: "text", text: "Review done." }] },
        ];
      },
      async synthetic() { v2SyntheticCalls++; return {}; },
      async wait() {},
    },
  };

  const v2Cleanup = await OpencodeGuardian.setup(v2Context);
  for (const cb of v2Hooks.get("execute.before") ?? []) {
    await cb({
      tool: "subagent",
      sessionID: "v2-parent-1",
      id: "v2-call-1",
      input: { agent: "code-reviewer" },
    });
  }
  const v2Event = {
    tool: "subagent",
    sessionID: "v2-parent-1",
    id: "v2-call-1",
    input: { agent: "code-reviewer" },
    status: "completed",
    result: {
      output: { sessionID: "v2-child-1", status: "completed", output: "Review output preserved" },
      content: '<subagent sessionID="v2-child-1" state="completed">Review output preserved</subagent>',
      metadata: { sessionID: "v2-child-1", status: "completed" },
    },
  };
  for (const cb of v2Hooks.get("execute.after") ?? []) {
    await cb(v2Event);
  }
  await v2Cleanup?.();
  assert.equal(v2SyntheticCalls, 0, "V2 read-only child must receive 0 synthetic prompts");
  assert.equal(v2Event.result.output.output, "Review done.");
});

// Scenario 2: Exact reviewer output regression
test("Scenario 2: Real-world reviewer subagent Turkish output finishes cleanly without loop", async () => {
  const realReviewerText = `İnceleme tamamlandı. Tespit edilen bulgular şunlardır:
1. src/index.ts: Subagent remediation isolasyonu eksik.
2. src/engine.ts: canSelfRemediate kontrolü capability'ye bağlı olmalı.
Öneri: Fixer agent tarafından düzeltilmesi uygundur.`;

  let promptCalls = 0;
  const client = {
    session: {
      get: async () => ({ data: { id: "child-reviewer-real", parentID: "parent-root" } }),
      messages: async () => ({
        data: [
          {
            info: { id: "u-real", role: "user" },
            parts: [{ type: "text", text: "Lütfen tüm dosyaları inceleyin ve testleri çalıştırın." }],
          },
          {
            info: { id: "a-real", role: "assistant", agent: "oracle" },
            parts: [{ type: "text", text: realReviewerText }],
          },
        ],
      }),
      prompt: async () => { promptCalls++; return { data: {} }; },
      promptAsync: async () => { promptCalls++; return { data: {} }; },
    },
    app: {
      agents: async () => ({
        data: [{
          name: "oracle",
          permission: { edit: "deny", bash: "deny" },
          tools: { read_file: true, file_search: true },
        }],
      }),
    },
  };

  const plugin = await OpencodeGuardian.server({ client, directory: process.cwd() });
  await plugin["tool.execute.before"](
    { tool: "task", sessionID: "parent-root", callID: "c-real" },
    { args: { agent: "oracle", prompt: "inceleme yap" } }
  );

  const output = {
    output: "Initial output",
    metadata: { sessionId: "child-reviewer-real", background: false },
  };
  await plugin["tool.execute.after"](
    { tool: "task", sessionID: "parent-root", callID: "c-real", args: { agent: "oracle" } },
    output
  );
  await plugin.dispose();

  assert.equal(promptCalls, 0, "Guardian must NOT inject remediation prompt to the read-only oracle");
  assert.match(output.output, /İnceleme tamamlandı/, "Reviewer output preserved");
  assert.match(output.output, /Öneri: Fixer agent tarafından düzeltilmesi uygundur/);
});

// Scenario 3: Write-allowed child subagent
test("Scenario 3: Write-allowed subagent receives remediation when completion gate blocks", async () => {
  let promptCalls = 0;
  const remediationTexts = [];
  let phase = 0;

  const initialMessages = [
    {
      info: { id: "u-fix", role: "user" },
      parts: [{ type: "text", text: "Run all tests and verify everything before claiming completion." }],
    },
    {
      info: { id: "a-fix-1", role: "assistant", agent: "fixer" },
      parts: [{ type: "text", text: "I fixed the code. The remaining test failure is unrelated to this change." }],
    },
  ];
  const remediatedMessages = () => [
    ...initialMessages,
    {
      info: { id: "g-rem", role: "user" },
      parts: [{ type: "text", text: remediationTexts[0] }],
    },
    {
      info: { id: "a-fix-2", role: "assistant", agent: "fixer" },
      parts: [{ type: "text", text: "Ran tests completely and all tests pass now." }],
    },
  ];

  const client = {
    session: {
      get: async () => ({ data: { id: "child-fixer", parentID: "parent-main" } }),
      messages: async () => ({ data: phase === 0 ? initialMessages : remediatedMessages() }),
      prompt: async ({ body }) => {
        promptCalls++;
        remediationTexts.push(body?.parts?.[0]?.text);
        phase = 1;
        return { data: remediatedMessages().at(-1) };
      },
      promptAsync: async () => ({ data: {} }),
    },
    app: {
      agents: async () => ({
        data: [{
          name: "fixer",
          permission: { edit: "allow", bash: "allow" },
          tools: { edit: true, bash: true, read_file: true },
        }],
      }),
    },
  };

  const plugin = await OpencodeGuardian.server({ client, directory: process.cwd() });
  await plugin["tool.execute.before"](
    { tool: "task", sessionID: "parent-main", callID: "c-fix" },
    { args: { agent: "fixer", prompt: "fix the bug" } }
  );

  const output = {
    output: "Initial fixer output",
    metadata: { sessionId: "child-fixer", background: false },
  };
  await plugin["tool.execute.after"](
    { tool: "task", sessionID: "parent-main", callID: "c-fix", args: { agent: "fixer" } },
    output
  );
  await plugin.dispose();

  assert.equal(promptCalls, 1, "Write-allowed subagent MUST receive remediation when blocked");
  assert.ok(remediationTexts[0]?.includes("[opencode-guardian remediation]"));
  assert.match(output.output, /Ran tests completely and all tests pass now/);
});

// Scenario 4: Write-requires-approval child subagent
test("Scenario 4: Write-requires-approval child subagent does NOT receive auto-remediation", async () => {
  let promptCalls = 0;
  const messages = [
    {
      info: { id: "u-ask", role: "user" },
      parts: [{ type: "text", text: "Run all tests and verify everything before claiming completion." }],
    },
    {
      info: { id: "a-ask", role: "assistant", agent: "ask-subagent" },
      parts: [{ type: "text", text: "Cannot proceed without approval. Done." }],
    },
  ];

  const client = {
    session: {
      get: async () => ({ data: { id: "child-ask", parentID: "parent-main" } }),
      messages: async () => ({ data: messages }),
      prompt: async () => { promptCalls++; return { data: {} }; },
      promptAsync: async () => { promptCalls++; return { data: {} }; },
    },
    app: {
      agents: async () => ({
        data: [{
          name: "ask-subagent",
          permission: { edit: "ask", bash: "ask" },
          tools: { edit: true, bash: true },
        }],
      }),
    },
  };

  const plugin = await OpencodeGuardian.server({ client, directory: process.cwd() });
  await plugin["tool.execute.before"](
    { tool: "task", sessionID: "parent-main", callID: "c-ask" },
    { args: { agent: "ask-subagent" } }
  );

  const output = {
    output: "Initial output",
    metadata: { sessionId: "child-ask", background: false },
  };
  await plugin["tool.execute.after"](
    { tool: "task", sessionID: "parent-main", callID: "c-ask", args: { agent: "ask-subagent" } },
    output
  );
  await plugin.dispose();

  assert.equal(promptCalls, 0, "Write-requires-approval subagent must NOT receive auto-remediation");
  assert.match(output.output, /Cannot proceed without approval/);
});

// Scenario 5: Unknown capability child subagent (fail-safe)
test("Scenario 5: Unknown capability child subagent fails safe with 0 remediation and no crash", async () => {
  let promptCalls = 0;
  const messages = [
    {
      info: { id: "u-unk", role: "user" },
      parts: [{ type: "text", text: "Run all tests and verify everything before claiming completion." }],
    },
    {
      info: { id: "a-unk", role: "assistant", agent: "mysterious-agent" },
      parts: [{ type: "text", text: "Finished my work." }],
    },
  ];

  const client = {
    session: {
      get: async () => ({ data: { id: "child-unk", parentID: "parent-main" } }),
      messages: async () => ({ data: messages }),
      prompt: async () => { promptCalls++; return { data: {} }; },
      promptAsync: async () => { promptCalls++; return { data: {} }; },
    },
    app: {
      // Simulate discovery failure / missing agent
      agents: async () => { throw new Error("Agent registry timeout"); },
    },
  };

  const plugin = await OpencodeGuardian.server({ client, directory: process.cwd() });
  await plugin["tool.execute.before"](
    { tool: "task", sessionID: "parent-main", callID: "c-unk" },
    { args: { agent: "mysterious-agent" } }
  );

  const output = {
    output: "Initial output",
    metadata: { sessionId: "child-unk", background: false },
  };

  // Must not throw/crash
  await assert.doesNotReject(async () => {
    await plugin["tool.execute.after"](
      { tool: "task", sessionID: "parent-main", callID: "c-unk", args: { agent: "mysterious-agent" } },
      output
    );
  });
  await plugin.dispose();

  assert.equal(promptCalls, 0, "Unknown subagent must fail safe with 0 remediation");
  assert.match(output.output, /Finished my work/);
});

// Scenario 6: Root agent behavior unchanged
test("Scenario 6: Root agent behavior is completely preserved and receives remediation", async () => {
  const engine = new GuardEngine({
    enabled: true,
    rules: {
      "safety/destructive-operations": "error",
      "task/completion-gate": "error",
    },
  });

  const rootMessages = [
    {
      info: { id: "u-root", role: "user" },
      parts: [{ type: "text", text: "Remove the temporary folder" }],
    },
    {
      info: { id: "a-root", role: "assistant" },
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

  // Root agent inspection (isSubagent: false or undefined)
  const result = await engine.inspect("sess-root-1", "/tmp", rootMessages, undefined, { isSubagent: false });
  assert.equal(result.decision, "block");
  assert.ok(result.combinedRemediationPrompt, "Root agent must receive combined remediation prompt");
  assert.ok(result.combinedRemediationPrompt.includes("[opencode-guardian remediation]"));
  assert.ok(result.combinedRemediationPrompt.includes("[OPENCODE_HANDOFF:v1]"), "Root agent must include handoff header");

  const parsed = parseOpenCodeHandoff(result.combinedRemediationPrompt);
  assert.ok(parsed, "Parsed handoff must exist for root session");
  assert.equal(parsed.kind, "approval");
});

// Scenario 7: Subagent handoff invariant
test("Scenario 7: Subagent handoff invariant is maintained across all capability states (no handoff header)", async () => {
  const engine = new GuardEngine({
    enabled: true,
    rules: { "safety/destructive-operations": "error" },
  });

  const dangerousMessages = [
    {
      info: { id: "u-test", role: "user" },
      parts: [{ type: "text", text: "Delete everything" }],
    },
    {
      info: { id: "a-test", role: "assistant" },
      parts: [{
        type: "tool",
        name: "bash",
        tool: "bash",
        state: { input: { command: "rm -rf /" }, status: "completed" },
      }],
    },
  ];

  const capabilities = ["read-only", "write-allowed", "write-requires-approval", "unknown"];

  for (const cap of capabilities) {
    const res = await engine.inspect(`sess-sub-${cap}`, "/tmp", dangerousMessages, undefined, {
      isSubagent: true,
      agentCapability: cap,
    });

    assert.equal(res.decision, "block");

    if (cap === "write-allowed") {
      assert.ok(res.combinedRemediationPrompt, "write-allowed subagent can have remediation prompt");
      assert.equal(
        res.combinedRemediationPrompt.includes("[OPENCODE_HANDOFF:v1]"),
        false,
        "Subagent remediation must NOT include handoff header"
      );
      const parsed = parseOpenCodeHandoff(res.combinedRemediationPrompt);
      assert.equal(parsed, null, "Parsed handoff must be null for subagent");
    } else {
      assert.equal(
        res.combinedRemediationPrompt,
        undefined,
        `Subagent with capability ${cap} must NOT receive remediation prompt`
      );
    }
  }
});

// Scenario 8: Smart Questions child isolation verification
test("Scenario 8: Smart Questions child isolation is verified intact", async () => {
  const engine = new GuardEngine({ enabled: true });
  const readOnlyProfile = evaluateAgentMutationProfile({
    name: "reviewer",
    permission: { edit: "deny", bash: "deny" },
    tools: { read_file: true },
  });
  assert.equal(readOnlyProfile.capability, "read-only");

  const inspectResult = await engine.inspect(
    "child-sq-iso",
    "/tmp",
    [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Verify code" }] },
      { info: { id: "a1", role: "assistant" }, parts: [{ type: "text", text: "Done without tests." }] },
    ],
    undefined,
    { isSubagent: true, agentCapability: readOnlyProfile.capability }
  );

  // Remediation is suppressed, preventing interference with SQ or child session
  assert.equal(inspectResult.combinedRemediationPrompt, undefined);
});

// Scenario 9: Bounded retry for write-allowed, 0 rounds for read-only
test("Scenario 9: Bounded retry respects limits for write-allowed, 0 rounds for read-only", async () => {
  // Read-only subagent has 0 rounds
  let readOnlyPrompts = 0;
  const readOnlyClient = {
    session: {
      get: async () => ({ data: { id: "c-ro", parentID: "p-ro" } }),
      messages: async () => ({
        data: [
          { info: { id: "u", role: "user" }, parts: [{ type: "text", text: "Run all tests." }] },
          { info: { id: "a", role: "assistant" }, parts: [{ type: "text", text: "Done." }] },
        ],
      }),
      prompt: async () => { readOnlyPrompts++; return { data: {} }; },
      promptAsync: async () => { readOnlyPrompts++; return { data: {} }; },
    },
    app: {
      agents: async () => ({
        data: [{ name: "ro-agent", permission: { edit: "deny", bash: "deny" } }],
      }),
    },
  };

  const roPlugin = await OpencodeGuardian.server({ client: readOnlyClient, directory: process.cwd() });
  await roPlugin["tool.execute.before"]({ tool: "task", sessionID: "p-ro", callID: "c1" }, { args: { agent: "ro-agent" } });
  await roPlugin["tool.execute.after"]({ tool: "task", sessionID: "p-ro", callID: "c1", args: { agent: "ro-agent" } }, {
    output: "Initial output",
    metadata: { sessionId: "c-ro", background: false },
  });
  await roPlugin.dispose();
  assert.equal(readOnlyPrompts, 0, "Read-only subagent has exactly 0 remediation rounds");

  // Write-allowed subagent loops boundedly under non-convergence
  let simulatedPrompts = 0;
  const writeClient = {
    session: {
      get: async () => ({ data: { id: "c-wr", parentID: "p-wr" } }),
      messages: async () => ({
        data: [
          { info: { id: "u", role: "user" }, parts: [{ type: "text", text: "Run all tests and verify everything before claiming completion." }] },
          { info: { id: "a", role: "assistant" }, parts: [{ type: "text", text: "I fixed the code. The remaining test failure is unrelated to this change." }] },
        ],
      }),
      prompt: async () => {
        simulatedPrompts++;
        return { data: {} };
      },
      promptAsync: async () => ({ data: {} }),
    },
    app: {
      agents: async () => ({
        data: [{ name: "wr-agent", permission: { edit: "allow", bash: "allow" } }],
      }),
    },
  };

  const wrPlugin = await OpencodeGuardian.server({ client: writeClient, directory: process.cwd() });
  await wrPlugin["tool.execute.before"]({ tool: "task", sessionID: "p-wr", callID: "c2" }, { args: { agent: "wr-agent" } });
  await wrPlugin["tool.execute.after"]({ tool: "task", sessionID: "p-wr", callID: "c2", args: { agent: "wr-agent" } }, {
    output: "Initial output",
    metadata: { sessionId: "c-wr", background: false },
  });
  await wrPlugin.dispose();

  assert.ok(simulatedPrompts >= 1, "Write-allowed subagent undergoes bounded remediation");
});

test("Agent names never determine session topology", async () => {
  const { extractCurrentTurn } = await import("../dist/engine.js");
  const makeMessages = (agent) => [
    {
      info: { id: "u-name-neutral", role: "user" },
      parts: [{ type: "text", text: "Inspect the repository." }],
    },
    {
      info: { id: "a-name-neutral", role: "assistant", agent },
      parts: [{ type: "text", text: "Inspection result." }],
    },
  ];

  assert.equal(extractCurrentTurn(makeMessages("orchestrator")).isSubagent, false);
  assert.equal(
    extractCurrentTurn(makeMessages("arbitrary-worker-name")).isSubagent,
    false,
    "A different agent name must not manufacture child-session topology"
  );
});

// Scenario 10: Unknown topology must fail safe without using agent names
test("Scenario 10: V1 unknown session topology never infers root/child from agent name", async () => {
  let promptCalls = 0;
  const client = {
    session: {
      // No session.get(): topology is genuinely unavailable.
      messages: async () => ({
        data: [
          {
            info: { id: "u-unknown-topology", role: "user" },
            parts: [{ type: "text", text: "Run all tests and verify everything before claiming completion." }],
          },
          {
            // Adversarial name: policy must not infer root from this string.
            info: { id: "a-unknown-topology", role: "assistant", agent: "orchestrator" },
            parts: [{ type: "text", text: "Done without running tests." }],
          },
        ],
      }),
      promptAsync: async () => {
        promptCalls++;
        return { data: {} };
      },
    },
  };

  const plugin = await OpencodeGuardian.server({ client, directory: process.cwd() });
  await plugin.event({
    event: {
      type: "session.idle",
      properties: { sessionID: "topology-unknown" },
    },
  });
  await plugin.dispose();

  assert.equal(
    promptCalls,
    0,
    "Unknown topology must fail safe and must not become root solely because of an agent name"
  );
});

// Scenario 11: V1 and V2 parity across normalized capability states
test("Scenario 11: V1 and V2 parity across normalized capability evaluation", async () => {
  // 1. Read-only (edit: deny, bash: deny)
  const v1ReadOnly = evaluateAgentMutationProfile({
    name: "v1-agent",
    permission: { edit: "deny", bash: "deny" },
  });
  const v2ReadOnly = evaluateAgentMutationProfile({
    name: "v2-agent",
    permissions: [
      { action: "edit", effect: "deny" },
      { action: "bash", effect: "deny" },
    ],
  });
  assert.equal(v1ReadOnly.capability, "read-only");
  assert.equal(v2ReadOnly.capability, "read-only");

  // 2. Write-allowed (edit: allow)
  const v1Write = evaluateAgentMutationProfile({
    name: "v1-agent",
    permission: { edit: "allow" },
  });
  const v2Write = evaluateAgentMutationProfile({
    name: "v2-agent",
    permissions: [{ action: "edit", effect: "allow" }],
  });
  assert.equal(v1Write.capability, "write-allowed");
  assert.equal(v2Write.capability, "write-allowed");

  // 3. Write-requires-approval (edit: ask)
  const v1Ask = evaluateAgentMutationProfile({
    name: "v1-agent",
    permission: { edit: "ask" },
  });
  const v2Ask = evaluateAgentMutationProfile({
    name: "v2-agent",
    permissions: [{ action: "edit", effect: "ask" }],
  });
  assert.equal(v1Ask.capability, "write-requires-approval");
  assert.equal(v2Ask.capability, "write-requires-approval");

  // 4. Unknown (no permissions, no tools)
  const v1Unknown = evaluateAgentMutationProfile({
    name: "v1-agent",
  });
  const v2Unknown = evaluateAgentMutationProfile({
    name: "v2-agent",
    permissions: [],
  });
  assert.equal(v1Unknown.capability, "unknown");
  assert.equal(v2Unknown.capability, "unknown");

  // 5. Unknown tools make read-only fail safe to unknown
  const v1WithUnknownTool = evaluateAgentMutationProfile({
    name: "v1-agent",
    permission: { edit: "deny", bash: "deny" },
    tools: { custom_tool_mutation: true },
  });
  assert.equal(v1WithUnknownTool.capability, "unknown");

  // 6. Mutating tool with edit deny still recognized as mutating channel
  const v1MutatingTool = evaluateAgentMutationProfile({
    name: "v1-agent",
    permission: { edit: "deny", bash: "deny" },
    tools: { apply_patch: true },
  });
  assert.equal(v1MutatingTool.capability, "write-allowed");
});
