import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { canSubagentRemediate } from "../dist/agent-capability.js";
import { collectTurnEvidence } from "../dist/evidence.js";
import { GuardEngine, OpencodeGuardian, evaluateAgentMutationProfile, parseOpenCodeHandoff } from "../dist/index.js";
import { classifyAgentReport } from "../dist/locale-intents.js";
import { taskCompletionRule } from "../dist/rules/task-completion.js";

describe("Subagent Capability & Remediation Matrix", () => {
  for (const [name, permissions] of [
    ["ask exception", [{ permission: "edit", pattern: "*", action: "deny" }, { permission: "bash", pattern: "*", action: "allow" }, { permission: "bash", pattern: "git *", action: "ask" }]],
    ["deny exception", [{ permission: "edit", pattern: "*", action: "deny" }, { permission: "bash", pattern: "*", action: "allow" }, { permission: "bash", pattern: "rm *", action: "deny" }]],
    ["allow exception", [{ permission: "edit", pattern: "*", action: "deny" }, { permission: "bash", pattern: "*", action: "deny" }, { permission: "bash", pattern: "npm test", action: "allow" }]],
  ]) {
    test(`V2 scoped bash ${name} does not permit autonomous subagent remediation`, async () => {
      const profile = evaluateAgentMutationProfile({ permissions });
      assert.equal(profile.evidence.bash, "restricted");
      assert.equal(profile.capability, "unknown");
      assert.equal(canSubagentRemediate(profile), false);
      const engine = new GuardEngine({ rules: { "safety/destructive-operations": "error" } });
      const result = await engine.inspect("scoped-child", "/tmp", [
        { info: { id: "u", role: "user" }, parts: [{ type: "text", text: "Inspect the repository." }] },
        { info: { id: "a", role: "assistant" }, parts: [{ type: "tool", tool: "bash",
          state: { status: "completed", input: { command: "rm -rf /" } } }] },
      ], undefined, { isSubagent: true, agentCapability: profile.capability });
      assert.equal(result.decision, "block");
      assert.equal(result.combinedRemediationPrompt, undefined);
    });
  }

  for (const effect of ["allow", "deny", "ask"]) {
    test(`V2 uniform and final wildcard ${effect} retain the channel effect`, () => {
      for (const bashPerms of [
        [{ permission: "bash", pattern: "*", action: effect }],
        [{ permission: "bash", pattern: "*", action: effect }, { permission: "bash", pattern: "npm test", action: effect }],
        [{ permission: "bash", pattern: "npm test", action: effect === "allow" ? "deny" : "allow" }, { permission: "bash", pattern: "*", action: effect }],
      ]) {
        const profile = evaluateAgentMutationProfile({
          permissions: [{ permission: "edit", pattern: "*", action: "deny" }, ...bashPerms],
        });
        assert.equal(profile.evidence.bash, effect);
      }
    });
  }

  test("V2 enabled execution tool survives a disabled alternate alias", () => {
    const profile = evaluateAgentMutationProfile({
      tools: { bash: false, shell: true },
      permissions: [
        { action: "edit", effect: "deny" },
        { action: "shell", effect: "allow" },
      ],
    });
    assert.equal(profile.evidence.bash, "allow");
    assert.equal(profile.capability, "write-allowed");
    assert.equal(canSubagentRemediate(profile), true);
  });

  test("disabled shell channels retain conservative capability classification", () => {
    for (const tools of [{ bash: false }, { shell: false }, { bash: false, shell: false }]) {
      const profile = evaluateAgentMutationProfile({
        tools,
        permissions: [
          { action: "edit", effect: "deny" },
          { action: "bash", effect: "allow" },
        ],
      });
      assert.equal(profile.evidence.bash, "disabled");
      assert.equal(profile.capability, "read-only");
    }
  });

  // Scenario 1: Read-only child completion result
  test("Scenario 1: Read-only child subagent completion result receives zero remediation (V2)", async () => {
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
        output: '<task id="v2-child-1" state="completed">Review output preserved</task>',
        content: '<task id="v2-child-1" state="completed">Review output preserved</task>',
        metadata: { sessionId: "v2-child-1" },
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
    const hooks = new Map();
    const addHook = (name, cb) => {
      const list = hooks.get(name) ?? [];
      list.push(cb);
      hooks.set(name, list);
      return { dispose() {} };
    };
    const cleanup = await OpencodeGuardian.setup({
      location: { directory: process.cwd() },
      options: { secrets: { enabled: false } },
      event: { subscribe: () => (async function* () {})() },
      tool: { hook: async (name, cb) => addHook(name, cb) },
      agent: {
        list: async () => [{
          name: "oracle",
          permissions: [
            { action: "edit", effect: "deny" },
            { action: "bash", effect: "deny" },
          ],
          tools: { read_file: true, file_search: true },
        }],
      },
      session: {
        get: async ({ sessionID }) => ({ id: sessionID, parentID: "parent-root" }),
        context: async () => [
          { id: "u-real", type: "user", text: "Lütfen tüm dosyaları inceleyin ve testleri çalıştırın." },
          { id: "a-real", type: "assistant", agent: "oracle", content: [{ type: "text", text: realReviewerText }] },
        ],
        synthetic: async () => { promptCalls++; },
        wait: async () => {},
      },
    });

    for (const cb of hooks.get("execute.before") ?? []) {
      await cb({
        tool: "subagent", sessionID: "parent-root", id: "c-real",
        input: { agent: "oracle", prompt: "inceleme yap" },
      });
    }

    const event = {
      tool: "subagent", sessionID: "parent-root", id: "c-real",
      input: { agent: "oracle" }, status: "completed",
      result: {
        output: "Initial output",
        metadata: { sessionId: "child-reviewer-real", background: false },
      },
    };
    for (const cb of hooks.get("execute.after") ?? []) {
      await cb(event);
    }
    await cleanup?.();

    assert.equal(promptCalls, 0, "Guardian must NOT inject remediation prompt to the read-only oracle");
    const outText = typeof event.result.output === "string" ? event.result.output : event.result.output?.output;
    assert.match(outText, /İnceleme tamamlandı/, "Reviewer output preserved");
    assert.match(outText, /Öneri: Fixer agent tarafından düzeltilmesi uygundur/);
  });

  // Scenario 3: Write-allowed child subagent
  test("Scenario 3: Write-allowed subagent receives remediation when completion gate blocks", async () => {
    let promptCalls = 0;
    const remediationTexts = [];
    let phase = 0;

    const initialMessages = [
      { id: "u-fix", type: "user", text: "Run all tests and verify everything before claiming completion." },
      { id: "a-fix-1", type: "assistant", agent: "fixer", content: [{ type: "text", text: "I fixed the code. The remaining test failure is unrelated to this change." }] },
    ];
    const remediatedMessages = () => [
      ...initialMessages,
      { id: "g-rem", type: "user", text: remediationTexts[0] },
      { id: "a-fix-2", type: "assistant", agent: "fixer", content: [{ type: "text", text: "Ran tests completely and all tests pass now." }] },
    ];

    const hooks = new Map();
    const addHook = (name, cb) => {
      const list = hooks.get(name) ?? [];
      list.push(cb);
      hooks.set(name, list);
      return { dispose() {} };
    };
    const cleanup = await OpencodeGuardian.setup({
      location: { directory: process.cwd() },
      options: { secrets: { enabled: false } },
      event: { subscribe: () => (async function* () {})() },
      tool: { hook: async (name, cb) => addHook(name, cb) },
      agent: {
        list: async () => [{
          name: "fixer",
          permissions: [
            { action: "edit", effect: "allow" },
            { action: "bash", effect: "allow" },
          ],
          tools: { edit: true, bash: true, read_file: true },
        }],
      },
      session: {
        get: async ({ sessionID }) => ({ id: sessionID, parentID: "parent-main" }),
        context: async () => (phase === 0 ? initialMessages : remediatedMessages()),
        synthetic: async ({ text }) => {
          promptCalls++;
          remediationTexts.push(text);
          phase = 1;
        },
        wait: async () => {},
      },
    });

    for (const cb of hooks.get("execute.before") ?? []) {
      await cb({
        tool: "subagent", sessionID: "parent-main", id: "c-fix",
        input: { agent: "fixer", prompt: "fix the bug" },
      });
    }

    const event = {
      tool: "subagent", sessionID: "parent-main", id: "c-fix",
      input: { agent: "fixer" }, status: "completed",
      result: {
        output: "Initial fixer output",
        metadata: { sessionId: "child-fixer", background: false },
      },
    };
    for (const cb of hooks.get("execute.after") ?? []) {
      await cb(event);
    }
    await cleanup?.();

    assert.equal(promptCalls, 1, "Write-allowed subagent MUST receive remediation when blocked");
    assert.ok(remediationTexts[0]?.includes("[opencode-guardian remediation]"));
    const outText = typeof event.result.output === "string" ? event.result.output : event.result.output?.output;
    assert.match(outText, /Ran tests completely and all tests pass now/);
  });

  // Scenario 4: Write-requires-approval child subagent
  test("Scenario 4: Write-requires-approval child subagent does NOT receive auto-remediation", async () => {
    let promptCalls = 0;
    const hooks = new Map();
    const addHook = (name, cb) => {
      const list = hooks.get(name) ?? [];
      list.push(cb);
      hooks.set(name, list);
      return { dispose() {} };
    };
    const cleanup = await OpencodeGuardian.setup({
      location: { directory: process.cwd() },
      options: { secrets: { enabled: false } },
      event: { subscribe: () => (async function* () {})() },
      tool: { hook: async (name, cb) => addHook(name, cb) },
      agent: {
        list: async () => [{
          name: "ask-subagent",
          permissions: [
            { action: "edit", effect: "ask" },
            { action: "bash", effect: "ask" },
          ],
          tools: { edit: true, bash: true },
        }],
      },
      session: {
        get: async ({ sessionID }) => ({ id: sessionID, parentID: "parent-main" }),
        context: async () => [
          { id: "u-ask", type: "user", text: "Run all tests and verify everything before claiming completion." },
          { id: "a-ask", type: "assistant", agent: "ask-subagent", content: [{ type: "text", text: "Cannot proceed without approval. Done." }] },
        ],
        synthetic: async () => { promptCalls++; },
        wait: async () => {},
      },
    });

    for (const cb of hooks.get("execute.before") ?? []) {
      await cb({
        tool: "subagent", sessionID: "parent-main", id: "c-ask",
        input: { agent: "ask-subagent" },
      });
    }

    const event = {
      tool: "subagent", sessionID: "parent-main", id: "c-ask",
      input: { agent: "ask-subagent" }, status: "completed",
      result: {
        output: "Initial output",
        metadata: { sessionId: "child-ask", background: false },
      },
    };
    for (const cb of hooks.get("execute.after") ?? []) {
      await cb(event);
    }
    await cleanup?.();

    assert.equal(promptCalls, 0, "Write-requires-approval subagent must NOT receive auto-remediation");
    const outText = typeof event.result.output === "string" ? event.result.output : event.result.output?.output;
    assert.match(outText, /Cannot proceed without approval/);
  });

  // Scenario 5: Unknown capability child subagent (fail-safe)
  test("Scenario 5: Unknown capability child subagent fails safe with 0 remediation and no crash", async () => {
    let promptCalls = 0;
    const hooks = new Map();
    const addHook = (name, cb) => {
      const list = hooks.get(name) ?? [];
      list.push(cb);
      hooks.set(name, list);
      return { dispose() {} };
    };
    const cleanup = await OpencodeGuardian.setup({
      location: { directory: process.cwd() },
      options: { secrets: { enabled: false } },
      event: { subscribe: () => (async function* () {})() },
      tool: { hook: async (name, cb) => addHook(name, cb) },
      agent: {
        list: async () => { throw new Error("Agent registry timeout"); },
      },
      session: {
        get: async ({ sessionID }) => ({ id: sessionID, parentID: "parent-main" }),
        context: async () => [
          { id: "u-unk", type: "user", text: "Run all tests and verify everything before claiming completion." },
          { id: "a-unk", type: "assistant", agent: "mysterious-agent", content: [{ type: "text", text: "Finished my work." }] },
        ],
        synthetic: async () => { promptCalls++; },
        wait: async () => {},
      },
    });

    for (const cb of hooks.get("execute.before") ?? []) {
      await cb({
        tool: "subagent", sessionID: "parent-main", id: "c-unk",
        input: { agent: "mysterious-agent" },
      });
    }

    const event = {
      tool: "subagent", sessionID: "parent-main", id: "c-unk",
      input: { agent: "mysterious-agent" }, status: "completed",
      result: {
        output: "Initial output",
        metadata: { sessionId: "child-unk", background: false },
      },
    };

    await assert.doesNotReject(async () => {
      for (const cb of hooks.get("execute.after") ?? []) {
        await cb(event);
      }
    });
    await cleanup?.();

    assert.equal(promptCalls, 0, "Unknown subagent must fail safe with 0 remediation");
    const outText = typeof event.result.output === "string" ? event.result.output : event.result.output?.output;
    assert.match(outText, /Finished my work/);
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
      permissions: [
        { action: "edit", effect: "deny" },
        { action: "bash", effect: "deny" },
      ],
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
    let readOnlyPrompts = 0;
    const roHooks = new Map();
    const roCleanup = await OpencodeGuardian.setup({
      location: { directory: process.cwd() },
      options: { secrets: { enabled: false } },
      event: { subscribe: () => (async function* () {})() },
      tool: { hook: async (n, cb) => { roHooks.set(n, cb); return { dispose() {} }; } },
      agent: { list: async () => [{ name: "ro-agent", permissions: [{ action: "edit", effect: "deny" }, { action: "bash", effect: "deny" }] }] },
      session: {
        get: async ({ sessionID }) => ({ id: sessionID, parentID: "p-ro" }),
        context: async () => [
          { id: "u", type: "user", text: "Run all tests." },
          { id: "a", type: "assistant", content: [{ type: "text", text: "Done." }] },
        ],
        synthetic: async () => { readOnlyPrompts++; },
        wait: async () => {},
      },
    });
    await roHooks.get("execute.before")({ tool: "subagent", sessionID: "p-ro", id: "c1", input: { agent: "ro-agent" } });
    await roHooks.get("execute.after")({
      tool: "subagent", sessionID: "p-ro", id: "c1", input: { agent: "ro-agent" }, status: "completed",
      result: { output: "Initial output", metadata: { sessionId: "c-ro", background: false } },
    });
    await roCleanup?.();
    assert.equal(readOnlyPrompts, 0, "Read-only subagent has exactly 0 remediation rounds");

    let simulatedPrompts = 0;
    const wrHooks = new Map();
    const wrCleanup = await OpencodeGuardian.setup({
      location: { directory: process.cwd() },
      options: { secrets: { enabled: false } },
      event: { subscribe: () => (async function* () {})() },
      tool: {
        hook: async (n, cb) => {
          const list = wrHooks.get(n) ?? [];
          list.push(cb);
          wrHooks.set(n, list);
          return { dispose() {} };
        },
      },
      agent: { list: async () => [{ name: "wr-agent", permissions: [{ action: "edit", effect: "allow" }, { action: "bash", effect: "allow" }] }] },
      session: {
        get: async ({ sessionID }) => ({ id: sessionID, parentID: "p-wr" }),
        context: async () => [
          { id: "u", type: "user", text: "Run all tests and verify everything before claiming completion." },
          { id: "a", type: "assistant", content: [{ type: "text", text: "I fixed the code. The remaining test failure is unrelated to this change." }] },
        ],
        synthetic: async () => { simulatedPrompts++; },
        wait: async () => {},
      },
    });
    for (const cb of wrHooks.get("execute.before") ?? []) {
      await cb({ tool: "subagent", sessionID: "p-wr", id: "c2", input: { agent: "wr-agent" } });
    }
    for (const cb of wrHooks.get("execute.after") ?? []) {
      await cb({
        tool: "subagent", sessionID: "p-wr", id: "c2", input: { agent: "wr-agent" }, status: "completed",
        result: { output: "Initial output", metadata: { sessionId: "c-wr", background: false } },
      });
    }
    await wrCleanup?.();

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
  test("Scenario 10: V2 unknown session topology never infers root/child from agent name", async () => {
    let promptCalls = 0;
    let releaseEvent;
    const cleanup = await OpencodeGuardian.setup({
      location: { directory: process.cwd() },
      options: { secrets: { enabled: false } },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            await new Promise((resolve) => { releaseEvent = resolve; });
            yield { type: "session.idle", data: { sessionID: "topology-unknown" } };
            await new Promise((resolve) => {
              if (signal.aborted) resolve();
              else signal.addEventListener("abort", resolve, { once: true });
            });
          })();
        },
      },
      session: {
        context: async () => [
          { id: "u-unknown-topology", type: "user", text: "Run all tests and verify everything before claiming completion." },
          { id: "a-unknown-topology", type: "assistant", agent: "orchestrator", content: [{ type: "text", text: "Done without running tests." }] },
        ],
        synthetic: async () => { promptCalls++; },
      },
    });
    releaseEvent();
    await new Promise((r) => setTimeout(r, 40));
    await cleanup?.();

    assert.equal(
      promptCalls,
      0,
      "Unknown topology must fail safe and must not become root solely because of an agent name"
    );
  });

  // Scenario 11: V2 normalized capability evaluation
  test("Scenario 11: V2 normalized capability evaluation", async () => {
    const v2ReadOnly = evaluateAgentMutationProfile({
      name: "v2-agent",
      permissions: [
        { action: "edit", effect: "deny" },
        { action: "bash", effect: "deny" },
      ],
    });
    assert.equal(v2ReadOnly.capability, "read-only");

    const v2Write = evaluateAgentMutationProfile({
      name: "v2-agent",
      permissions: [{ action: "edit", effect: "allow" }],
    });
    assert.equal(v2Write.capability, "write-allowed");

    const v2Ask = evaluateAgentMutationProfile({
      name: "v2-agent",
      permissions: [{ action: "edit", effect: "ask" }],
    });
    assert.equal(v2Ask.capability, "write-requires-approval");

    const v2Unknown = evaluateAgentMutationProfile({
      name: "v2-agent",
      permissions: [],
    });
    assert.equal(v2Unknown.capability, "unknown");

    const withUnknownTool = evaluateAgentMutationProfile({
      name: "v2-agent",
      permissions: [
        { action: "edit", effect: "deny" },
        { action: "bash", effect: "deny" },
      ],
      tools: { custom_tool_mutation: true },
    });
    assert.equal(withUnknownTool.capability, "unknown");

    const mutatingTool = evaluateAgentMutationProfile({
      name: "v2-agent",
      permissions: [
        { action: "edit", effect: "deny" },
        { action: "bash", effect: "deny" },
      ],
      tools: { apply_patch: true },
    });
    assert.equal(canSubagentRemediate(mutatingTool), false);
  });
});

describe("Subagent Progress & Completion Gate", () => {
  test("classifyAgentReport accurately identifies Turkish and English in-progress statements", () => {
    const inProgressPhrases = [
      "işlem devam ediyor, ortamı inceliyorum",
      "İşlemler devam ediyor; test adımlarına geçiyorum.",
      "çalışmaya devam ediyorum, 1. dosya tamamlandı",
      "Çalışma devam ediyor.",
      "devam ediyorum, hata analizi yapıyorum",
      "İşlemler sürüyor.",
      "Şu anda dosyayı inceliyorum ve hazırlıyorum.",
      "Görev Fixer oturumuna devredildi.",
      "İlgili alt ajana aktarıldı.",
      "Ara rapor: ilk aşama tamamlandı, devam edilecek.",
      "Durum güncellemesi: testler hazırlanıyor.",
      "İlerleme raporu: 3/5 adım tamamlandı.",
      "work in progress: investigating failures",
      "in progress: step 1 complete, moving to step 2",
      "Processing dependencies and continuing tests.",
      "Working on it, still analyzing logs.",
    ];

    for (const phrase of inProgressPhrases) {
      const report = classifyAgentReport(phrase);
      assert.equal(report.isInProgress, true, `Should detect in-progress for: "${phrase}"`);
      assert.equal(report.isClosing, false, `Should not be closing for: "${phrase}"`);
      assert.equal(report.state, "in-progress", `State should be in-progress for: "${phrase}"`);
    }
  });

  test("classifyAgentReport accurately identifies multilingual in-progress statements across all supported non-English/Turkish languages", () => {
    const multilingualPhrases = [
      { lang: "Spanish", text: "Trabajo en curso: revisando los archivos del proyecto." },
      { lang: "Portuguese", text: "Trabalho em andamento: preparando os testes unitários." },
      { lang: "French", text: "Travail en cours: exécution des étapes intermédiaires." },
      { lang: "German", text: "In Bearbeitung: behebe den ersten Fehler." },
      { lang: "Russian", text: "Работа продолжается: изучаю исходный код." },
      { lang: "Arabic", text: "العمل جار: جاري التحقق من التغييرات." },
      { lang: "Hindi", text: "काम जारी है: त्रुटियों का विश्लेषण किया जा रहा है।" },
      { lang: "Chinese", text: "处理中：正在修复发现的问题。" },
      { lang: "Japanese", text: "進行中：テストケースを分析しています。" },
      { lang: "Korean", text: "작업 진행 중: 변경 사항을 적용하고 있습니다." },
      { lang: "Indonesian", text: "Sedang dikerjakan: memeriksa berkas dan konfigurasi." },
    ];

    for (const { lang, text } of multilingualPhrases) {
      const report = classifyAgentReport(text);
      assert.equal(report.isInProgress, true, `Should detect in-progress for ${lang}: "${text}"`);
      assert.equal(report.isClosing, false, `Should not be closing for ${lang}: "${text}"`);
      assert.equal(report.state, "in-progress", `State should be in-progress for ${lang}: "${text}"`);
    }
  });

  test("subagent reporting 'işlem devam ediyor' with intermediate tool failure does NOT block on completion gate", async () => {
    const turn = [
      {
        info: { id: "u-brief", role: "user" },
        parts: [{ type: "text", text: "Fix the bug and run tests before finishing." }],
      },
      {
        info: { id: "a-prog", role: "assistant", agent: "fixer" },
        parts: [
          {
            type: "tool",
            tool: "bash",
            state: {
              status: "completed",
              input: { command: "npm test" },
              exitCode: 1,
              output: "FAIL: 1 of 5 tests failed",
            },
          },
          {
            type: "text",
            text: "İşlem devam ediyor; başarısız olan testi tespit ettim, düzeltme üzerinde çalışıyorum.",
          },
        ],
      },
    ];

    const result = await taskCompletionRule.inspect({
      sessionID: "subagent-prog-1",
      directory: process.cwd(),
      messages: turn,
      currentTurn: turn,
      isSubagent: true,
      agentCapability: "write-allowed",
      ruleConfig: {},
      evidence: collectTurnEvidence(turn),
    });

    assert.equal(result.decision, "pass", "Subagent reporting ongoing work must pass completion gate");
  });

  test("subagent reporting intermediate findings without claiming completion does NOT block on completion gate", async () => {
    const turn = [
      {
        info: { id: "u-brief", role: "user" },
        parts: [{ type: "text", text: "Run typecheck and fix any errors." }],
      },
      {
        info: { id: "a-prog", role: "assistant", agent: "fixer" },
        parts: [
          {
            type: "tool",
            tool: "write",
            state: {
              status: "completed",
              input: { filePath: "src/file.ts", content: "export const x = 1;" },
            },
          },
          {
            type: "text",
            text: "Gerekli dosya değişikliğini uyguladım. Şimdi tip denetimini koşturacağım.",
          },
        ],
      },
    ];

    const result = await taskCompletionRule.inspect({
      sessionID: "subagent-prog-2",
      directory: process.cwd(),
      messages: turn,
      currentTurn: turn,
      isSubagent: true,
      agentCapability: "write-allowed",
      ruleConfig: {},
      evidence: collectTurnEvidence(turn),
    });

    assert.equal(result.decision, "pass", "Subagent in intermediate step must pass completion gate");
  });

  test("root agent delegating to subagent ('devredildi') does NOT block on completion gate", async () => {
    const turn = [
      {
        info: { id: "u-root", role: "user" },
        parts: [{ type: "text", text: "Fix the build and spec validation." }],
      },
      {
        info: { id: "a-root", role: "assistant", agent: "orchestrator" },
        parts: [
          {
            type: "tool",
            tool: "bash",
            state: {
              status: "completed",
              input: { command: "npm run build" },
              exitCode: 1,
              output: "Build error in apps/cli",
            },
          },
          {
            type: "text",
            text: "Onaylı macOS CLI düzeltmesi mevcut Fixer oturumuna devredildi. Tamamlandığında odaklı testleri ve izole aday kanıtlarını uzlaştıracağım.",
          },
        ],
      },
    ];

    const result = await taskCompletionRule.inspect({
      sessionID: "root-delegation-1",
      directory: process.cwd(),
      messages: turn,
      currentTurn: turn,
      isSubagent: false,
      agentCapability: "write-allowed",
      ruleConfig: {},
      evidence: collectTurnEvidence(turn),
    });

    assert.equal(result.decision, "pass", "Root agent delegating to subagent must pass completion gate");
  });

  test("subagent claiming completion ('iş bitti') with unresolved failure DOES block on completion gate", async () => {
    const turn = [
      {
        info: { id: "u-brief", role: "user" },
        parts: [{ type: "text", text: "Fix the bug and verify tests." }],
      },
      {
        info: { id: "a-done", role: "assistant", agent: "fixer" },
        parts: [
          {
            type: "tool",
            tool: "bash",
            state: {
              status: "completed",
              input: { command: "npm test" },
              exitCode: 1,
              output: "FAIL: 1 test failed",
            },
          },
          {
            type: "text",
            text: "Tüm geliştirmeler tamamlandı, iş bitti.",
          },
        ],
      },
    ];

    const result = await taskCompletionRule.inspect({
      sessionID: "subagent-claim-done",
      directory: process.cwd(),
      messages: turn,
      currentTurn: turn,
      isSubagent: true,
      agentCapability: "write-allowed",
      ruleConfig: {},
      evidence: collectTurnEvidence(turn),
    });

    assert.equal(result.decision, "block", "Subagent claiming completion while tests fail must block");
    assert.ok(result.findings.some((f) => f.ruleId === "task/completion-gate"));
  });
});
