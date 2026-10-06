import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, {
  GuardEngine,
  REMEDIATION_MARKER,
  evaluatePreflight,
  enforcePreflight,
  GuardianPreflightError,
  isFileMutationTool,
  collectTurnEvidence,
  calculateProductFingerprint,
  VerificationSnapshotStore,
  noCheatRule,
  noShortcutsRule,
  noUnverifiedClaimsRule,
  explicitlyAuthorizedTestEdit,
  explicitlyAuthorizedStubOrPlaceholder,
  recordGuardianEvent,
  guardianEventPath,
  sessionFingerprint,
} from "../dist/index.js";

function isolated(t) {
  const dir = path.join(os.tmpdir(), `guardian-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  process.env.OPENCODE_GUARDIAN_STATE_DIR = dir;
  t.after(() => {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
    delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
  });
  return dir;
}

test("Preflight intercepts hardcoded secrets in file mutation tools before disk write", () => {
  const fakeApiKey = "sk-" + "a".repeat(40);
  const fakeGithubPat = "ghp_" + "b".repeat(36);
  const fakeAwsKey = "AKIA" + "C".repeat(16);

  // Shell write tools
  assert.equal(isFileMutationTool("write_to_file"), true);
  assert.equal(isFileMutationTool("replace_file_content"), true);
  assert.equal(isFileMutationTool("edit_file"), true);
  assert.equal(isFileMutationTool("apply_patch"), true);
  assert.equal(isFileMutationTool("mcp__filesystem__write_file"), true);
  assert.equal(isFileMutationTool("read_file"), false);

  // Hardcoded secret in write_to_file
  assert.equal(
    evaluatePreflight("write_to_file", {
      path: "src/config.ts",
      content: `export const API_KEY = "${fakeApiKey}";`,
    }),
    "hardcoded-secret-in-file-write"
  );

  // Hardcoded GitHub PAT in replace_file_content
  assert.equal(
    evaluatePreflight("replace_file_content", {
      filePath: "src/auth.ts",
      ReplacementContent: `const token = "${fakeGithubPat}";`,
    }),
    "hardcoded-secret-in-file-write"
  );

  // Hardcoded AWS key in apply_patch
  assert.equal(
    evaluatePreflight("apply_patch", {
      patch: `--- a/src/aws.ts\n+++ b/src/aws.ts\n@@ -1,2 +1,2 @@\n-const old = 1;\n+const awsKey = "${fakeAwsKey}";`,
    }),
    "hardcoded-secret-in-file-write"
  );

  // enforcePreflight throws GuardianPreflightError
  assert.throws(
    () => enforcePreflight("write_to_file", { path: "src/secret.ts", content: `const k = "${fakeApiKey}";` }),
    (err) => err instanceof GuardianPreflightError && err.reason === "hardcoded-secret-in-file-write"
  );

  // Benign code passes cleanly
  assert.equal(
    evaluatePreflight("write_to_file", {
      path: "src/config.ts",
      content: 'export const API_KEY = process.env.OPENAI_API_KEY ?? "";',
    }),
    undefined
  );

  // Template/example values pass cleanly
  assert.equal(
    evaluatePreflight("write_to_file", {
      path: ".env.example",
      content: "DATABASE_URL=postgres://user:password@localhost:5432/mydb",
    }),
    undefined
  );
});

test("State-bound test evidence invalidates verification when files change after tests", () => {
  const tmpDir = path.join(os.tmpdir(), `test-state-bound-${Date.now()}`);
  fs.mkdirSync(tmpDir, { recursive: true });
  const srcFile = path.join(tmpDir, "calculator.ts");
  fs.writeFileSync(srcFile, "export const add = (a, b) => a + b;");

  // Step 1: Agent mutates file
  const step1 = {
    info: { id: "a1", role: "assistant" },
    parts: [
      {
        type: "tool",
        tool: "write_to_file",
        state: {
          status: "completed",
          input: { path: "calculator.ts", content: "export const add = (a, b) => a + b;" },
        },
      },
    ],
  };

  // Step 2: Agent runs tests successfully
  const step2 = {
    info: { id: "a2", role: "assistant" },
    parts: [
      {
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command: "npm test" },
          metadata: { exit: 0 },
        },
      },
    ],
  };

  // Case A: At step 2, test verification is fresh and matches current state
  const evidenceBeforePostEdit = collectTurnEvidence([step1, step2], tmpDir);
  const claimContextClean = {
    sessionID: "sess-1",
    directory: tmpDir,
    messages: [],
    ruleConfig: {},
    currentTurn: [step1, step2, {
      info: { id: "a3", role: "assistant" },
      parts: [{ type: "text", text: "All tests passing." }],
    }],
    evidence: evidenceBeforePostEdit,
  };
  const cleanResult = noUnverifiedClaimsRule.inspect(claimContextClean);
  assert.equal(cleanResult.decision, "pass");
  assert.equal(cleanResult.findings.length, 0);

  // Step 3: Agent mutates file AGAIN after the test
  fs.writeFileSync(srcFile, "export const add = (a, b) => a - b;"); // altered!
  const step3 = {
    info: { id: "a4", role: "assistant" },
    parts: [
      {
        type: "tool",
        tool: "write_to_file",
        state: {
          status: "completed",
          input: { path: "calculator.ts", content: "export const add = (a, b) => a - b;" },
        },
      },
    ],
  };

  // Case B: Claiming tests passed after a post-test mutation is flagged as stale
  const evidenceAfterPostEdit = collectTurnEvidence([step1, step2, step3], tmpDir);
  const claimContextStale = {
    sessionID: "sess-1",
    directory: tmpDir,
    messages: [],
    ruleConfig: { blockUnverified: true },
    currentTurn: [step1, step2, step3, {
      info: { id: "a5", role: "assistant" },
      parts: [{ type: "text", text: "All tests passing." }],
    }],
    evidence: evidenceAfterPostEdit,
  };
  const staleResult = noUnverifiedClaimsRule.inspect(claimContextStale);
  assert.equal(staleResult.decision, "block");
  assert.equal(staleResult.findings.length, 1);
  assert.equal(staleResult.findings[0].pattern, "tests passing");

  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
});

test("Intent-aware exceptions: user-authorized test edits and stubs are permitted without blocks", () => {
  // 1. Authorized test edit
  assert.equal(explicitlyAuthorizedTestEdit("Lütfen testleri yeni şemaya göre güncelle"), true);
  assert.equal(explicitlyAuthorizedTestEdit("Update the failing tests in test_auth.py"), true);
  assert.equal(explicitlyAuthorizedTestEdit("Refactor tests and remove obsolete test_old"), true);
  assert.equal(explicitlyAuthorizedTestEdit("Fix the calculation bug in finance.ts"), false);

  const testSkipContextAuthorized = {
    sessionID: "sess-cheat",
    directory: "/tmp",
    messages: [
      {
        info: { id: "user-1", role: "user" },
        parts: [{ type: "text", text: "Update the tests in calculator.test.ts to skip unsupported mode" }],
      },
    ],
    ruleConfig: { blockStructuralTestChanges: true },
    currentTurn: [
      {
        info: { id: "user-1", role: "user" },
        parts: [{ type: "text", text: "Update the tests in calculator.test.ts to skip unsupported mode" }],
      },
      {
        info: { id: "asst-1", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "write_to_file",
            state: {
              input: {
                path: "calculator.test.ts",
                content: "describe('calc', () => { it.skip('unsupported', () => {}); });",
              },
            },
          },
        ],
      },
    ],
  };

  const authorizedResult = noCheatRule.inspect(testSkipContextAuthorized);
  assert.equal(authorizedResult.decision, "pass");

  // Unauthorized test skip blocks
  const testSkipContextUnauthorized = {
    ...testSkipContextAuthorized,
    messages: [
      {
        info: { id: "user-2", role: "user" },
        parts: [{ type: "text", text: "Fix the math bug in calculator" }],
      },
    ],
    currentTurn: [
      {
        info: { id: "user-2", role: "user" },
        parts: [{ type: "text", text: "Fix the math bug in calculator" }],
      },
      testSkipContextAuthorized.currentTurn[1],
    ],
  };
  const unauthorizedResult = noCheatRule.inspect(testSkipContextUnauthorized);
  assert.equal(unauthorizedResult.decision, "block");

  // 2. Authorized stub/placeholder
  assert.equal(explicitlyAuthorizedStubOrPlaceholder("Add a placeholder function for now"), true);
  assert.equal(explicitlyAuthorizedStubOrPlaceholder("Add a TODO for tomorrow's migration"), true);
  assert.equal(explicitlyAuthorizedStubOrPlaceholder("Ödeme servisi için bir taslak oluştur"), true);
  assert.equal(explicitlyAuthorizedStubOrPlaceholder("Complete the user service implementation"), false);

  const stubContextAuthorized = {
    sessionID: "sess-stub",
    directory: "/tmp",
    messages: [
      {
        info: { id: "user-3", role: "user" },
        parts: [{ type: "text", text: "Add a stub implementation of the payment gateway" }],
      },
    ],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "user-3", role: "user" },
        parts: [{ type: "text", text: "Add a stub implementation of the payment gateway" }],
      },
      {
        info: { id: "asst-2", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "write_to_file",
            state: {
              input: {
                path: "src/payment.ts",
                content: "// TODO: implement real stripe call\nexport function charge() { return true; }",
              },
            },
          },
        ],
      },
    ],
  };
  assert.equal(noShortcutsRule.inspect(stubContextAuthorized).decision, "pass");
});

test("Closed-loop remediation: verifies fixes and records remediation-verified / remediation-failed", async (t) => {
  const project = isolated(t);
  fs.mkdirSync(path.join(project, "src"), { recursive: true });
  const engine = new GuardEngine({
    enabled: true,
    remediationBudget: 1,
    rules: { "security/no-secrets": "error" },
  });

  const fakeKey = "sk-" + "c".repeat(40);
  fs.writeFileSync(path.join(project, "src/api.ts"), `export const KEY = "${fakeKey}";`);
  const initialTurn = [
    { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Add the API client" }] },
    {
      info: { id: "a1", role: "assistant" },
      parts: [
        {
          type: "tool",
          tool: "write_to_file",
          state: { status: "completed", input: { path: "src/api.ts", content: `export const KEY = "${fakeKey}";` } },
        },
      ],
    },
  ];

  // Round 1: Violation detected, remediation requested
  const blockResult = await engine.inspect("session-remediation", project, initialTurn);
  assert.equal(blockResult.decision, "block");
  assert.ok(blockResult.combinedRemediationPrompt?.includes(REMEDIATION_MARKER));

  // Case A: Agent responds to remediation prompt with CLEAN code -> remediation verified!
  fs.writeFileSync(path.join(project, "src/api.ts"), 'export const KEY = process.env.API_KEY ?? "";');
  const remediationFixedTurn = [
    ...initialTurn,
    {
      info: { id: "rem-1", role: "user" },
      parts: [{ type: "text", text: blockResult.combinedRemediationPrompt, synthetic: true }],
    },
    {
      info: { id: "a2", role: "assistant" },
      parts: [
        {
          type: "tool",
          tool: "write_to_file",
          state: { status: "completed", input: { path: "src/api.ts", content: 'export const KEY = process.env.API_KEY ?? "";' } },
        },
      ],
    },
  ];

  const verifiedResult = await engine.inspect("session-remediation", project, remediationFixedTurn);
  assert.equal(verifiedResult.decision, "pass");
  assert.equal(verifiedResult.remediationStatus, "verified");

  // Case B: In a new session, agent responds with STILL VIOLATING code -> remediation failed, no infinite loop!
  const engine2 = new GuardEngine({
    enabled: true,
    remediationBudget: 1,
    rules: { "security/no-secrets": "error" },
  });

  await engine2.inspect("session-failed", "/tmp", initialTurn); // block 1
  const anotherKey = "sk-" + "d".repeat(40);
  const remediationStillFailingTurn = [
    ...initialTurn,
    {
      info: { id: "rem-2", role: "user" },
      parts: [{ type: "text", text: blockResult.combinedRemediationPrompt, synthetic: true }],
    },
    {
      info: { id: "a3", role: "assistant" },
      parts: [
        {
          type: "tool",
          tool: "write_to_file",
          state: { input: { path: "src/api.ts", content: `export const STILL_KEY = "${anotherKey}";` } },
        },
      ],
    },
  ];

  const failedResult = await engine2.inspect("session-failed", "/tmp", remediationStillFailingTurn);
  assert.equal(failedResult.decision, "pass"); // Stopped cleanly without infinite loop!
  assert.equal(failedResult.remediationStatus, "failed");
});


test("Remediation never claims verified without an observed, relevant correction", async (t) => {
  const project = isolated(t);
  fs.mkdirSync(path.join(project, "src"), { recursive: true });
  const token = "sk-" + "q".repeat(40);
  fs.writeFileSync(path.join(project, "src/config.ts"), 'const key = "' + token + '";');
  const initial = [
    { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Implement the client" }] },
    { info: { id: "a1", role: "assistant" }, parts: [{
      type: "tool", tool: "write_to_file",
      state: { status: "completed", input: { path: "src/config.ts", content: 'const key = "' + token + '";' } },
    }] },
  ];
  const engine = new GuardEngine({ enabled: true, remediationBudget: 1 });
  const blocked = await engine.inspect("no-change", project, initial);
  assert.equal(blocked.decision, "block");
  const followUp = [...initial,
    { info: { id: "r1", role: "user" }, parts: [{
      type: "text", text: blocked.combinedRemediationPrompt, synthetic: true,
    }] },
    { info: { id: "a2", role: "assistant" }, parts: [{ type: "text", text: "Fixed it." }] },
  ];
  const idle = await engine.inspect("no-change", project, followUp);
  assert.equal(idle.remediationStatus, "unverified");
  assert.equal(idle.decision, "pass");
  assert.deepEqual(idle.pendingRemediationRules, ["security/no-secrets"]);

  const restarted = new GuardEngine({ enabled: true, remediationBudget: 1 });
  const cold = await restarted.inspect("no-change", project, followUp);
  assert.equal(cold.remediationStatus, "unverified");
  assert.deepEqual(cold.pendingRemediationRules, []);

  const unrelatedEngine = new GuardEngine({ enabled: true, remediationBudget: 1 });
  const start = await unrelatedEngine.inspect("unrelated", project, initial);
  fs.writeFileSync(path.join(project, "src/other.ts"), "export const ok = true;");
  const unrelated = await unrelatedEngine.inspect("unrelated", project, [
    ...initial, { info: { id: "r2", role: "user" }, parts: [{
      type: "text", text: start.combinedRemediationPrompt, synthetic: true,
    }] },
    { info: { id: "a3", role: "assistant" }, parts: [{
      type: "tool", tool: "write_to_file",
      state: { status: "completed", input: {
        path: "src/other.ts", content: "export const ok = true;",
      } },
    }] },
  ]);
  assert.equal(unrelated.remediationStatus, "unverified");
});

test("Preflight understands Node Command file mutations and rejects opaque write payloads", () => {
  const secret = "sk-" + "p".repeat(40);
  assert.equal(isFileMutationTool("mcp__Node_Command__file_mutate"), true);
  assert.equal(evaluatePreflight("mcp__Node_Command__file_mutate", {
    action: "write", path: "src/key.ts", content: "const key = '" + secret + "';",
  }), "hardcoded-secret-in-file-write");
  assert.equal(evaluatePreflight("mcp__Node_Command__file_mutate", {
    action: "edit", path: "src/key.ts", edits: [{ replacement: "const key = '" + secret + "';" }],
  }), "hardcoded-secret-in-file-write");
  assert.equal(evaluatePreflight("mcp__Node_Command__file_mutate", {
    action: "write", path: "src/key.ts",
  }), "uninspectable-file-input");
  assert.equal(evaluatePreflight("mcp__Node_Command__file_mutate", null),
    "uninspectable-file-input");
  assert.equal(evaluatePreflight("mcp__Node_Command__file_mutate", {
    action: "move", source: "src/key.ts", destination: "src/renamed.ts",
  }), undefined);
});

test("Generic test edits and unrelated mocks cannot waive security checks", () => {
  const human = (text) => ({ info: { id: "u1", role: "user" }, parts: [
    { type: "text", text },
  ] });
  const skip = { info: { id: "a1", role: "assistant" }, parts: [{
    type: "tool", tool: "edit_file", state: { input: {
      path: "tests/payments.test.ts", new_string: "test.skip('payments', () => {});",
    } },
  }] };
  const ctx = (text, event) => ({
    sessionID: "scope-test", directory: "/tmp", ruleConfig: {},
    messages: [human(text), event], currentTurn: [human(text), event],
  });
  assert.equal(noCheatRule.inspect(ctx("Fix the failing tests", skip)).decision, "block");
  assert.equal(noCheatRule.inspect(ctx("Do not skip tests; update failing tests", skip)).decision, "block");
  assert.equal(noCheatRule.inspect(ctx(
    "Explicitly skip unsupported payments test until the feature is available", skip,
  )).decision, "pass");
  const shortcut = { info: { id: "a2", role: "assistant" }, parts: [{
    type: "tool", tool: "write_to_file", state: { input: {
      path: "src/payment.ts", content: "// TODO: implement payment validation",
    } },
  }] };
  assert.equal(noShortcutsRule.inspect(ctx(
    "Create a mock for the HTTP tests and finish payment validation", shortcut,
  )).decision, "block");
  assert.equal(noShortcutsRule.inspect(ctx(
    "Do not add TODO to src/payment.ts; finish payment validation", shortcut,
  )).decision, "block");
});

test("A live test snapshot detects same-size edits with preserved timestamps", (t) => {
  const project = isolated(t);
  const source = path.join(project, "logic.ts");
  const fixed = new Date("2024-01-01T00:00:00Z");
  fs.writeFileSync(source, "export const value = 1;");
  fs.utimesSync(source, fixed, fixed);
  const initial = calculateProductFingerprint(project, ["logic.ts"]);
  const store = new VerificationSnapshotStore();
  store.observe("session", "mutation", "write_to_file", {
    path: "logic.ts", content: "export const value = 1;",
  }, "saved", {}, project);
  store.observe("session", "test-call", "bash", {
    command: "npm test",
  }, "tests passed", { exit: 0 }, project);
  const messages = [
    { info: { id: "u1", role: "user" }, parts: [{
      type: "text", text: "Implement logic and verify",
    }] },
    { info: { id: "a1", role: "assistant" }, parts: [{
      type: "tool", callID: "mutation", tool: "write_to_file",
      state: { status: "completed", input: {
        path: "logic.ts", content: "export const value = 1;",
      } },
    }] },
    { info: { id: "a2", role: "assistant" }, parts: [{
      type: "tool", callID: "test-call", tool: "bash",
      state: { status: "completed", input: {
        command: "npm test",
      }, metadata: { exit: 0 } },
    }] },
    { info: { id: "a3", role: "assistant" }, parts: [{
      type: "text", text: "All tests passing.",
    }] },
  ];
  const snapshot = store.snapshots("session");
  assert.equal(snapshot.has("test-call"), true);
  const before = collectTurnEvidence(messages, project, snapshot);
  assert.equal(noUnverifiedClaimsRule.inspect({
    sessionID: "session", directory: project, messages,
    currentTurn: messages, evidence: before, ruleConfig: { blockUnverified: true },
  }).decision, "pass");

  // A later user turn can verify files changed in an earlier turn.
  store.observe("session", "next-turn-test", "bash", {
    command: "npm test",
  }, "tests passed", { exit: 0 }, project);
  const nextTurn = [
    { info: { id: "u2", role: "user" }, parts: [{ type: "text", text: "Verify again" }] },
    { info: { id: "a4", role: "assistant" }, parts: [{
      type: "tool", callID: "next-turn-test", tool: "bash",
      state: { status: "completed", input: { command: "npm test" },
        metadata: { exit: 0 } },
    }] },
    { info: { id: "a5", role: "assistant" }, parts: [{
      type: "text", text: "All tests passing.",
    }] },
  ];
  const laterEvidence = collectTurnEvidence(nextTurn, project, snapshot);
  assert.deepEqual(laterEvidence.records.find((record) =>
    record.kind === "test").snapshotFiles, ["logic.ts"]);
  assert.equal(noUnverifiedClaimsRule.inspect({
    sessionID: "session", directory: project, messages: nextTurn,
    currentTurn: nextTurn, evidence: laterEvidence,
    ruleConfig: { blockUnverified: true },
  }).decision, "pass");

  fs.writeFileSync(source, "export const value = 2;");
  fs.utimesSync(source, fixed, fixed);
  const current = calculateProductFingerprint(project, ["logic.ts"]);
  assert.notEqual(current, initial, "the content hash must ignore forged mtime equivalence");
  const replay = collectTurnEvidence(messages, project, snapshot);
  assert.equal(replay.records.find((record) => record.kind === "test").stateFingerprint,
    snapshot.get("test-call").fingerprint, "historic snapshot must not be recalculated at idle");
  assert.equal(noUnverifiedClaimsRule.inspect({
    sessionID: "session", directory: project, messages,
    currentTurn: messages, evidence: replay, ruleConfig: { blockUnverified: true },
  }).decision, "block");
});
test("V1 and V2 host adapters register and dispose live evidence hooks", async (t) => {
  const project = isolated(t);
  fs.writeFileSync(path.join(project, "opencode-guardian.json"),
    JSON.stringify({ enabled: true, preflight: { enabled: false } }));
  const v1 = await Guardian.server({ client: { session: {} }, directory: project });
  assert.equal(typeof v1["tool.execute.after"], "function");
  await v1["tool.execute.after"]({
    tool: "write_to_file", sessionID: "s", callID: "m1",
    args: { path: "file.ts", content: "export const value = true;" },
  }, { title: "saved", output: "saved", metadata: {} });
  await v1.dispose();

  let afterHook;
  const disposed = [];
  const v2 = {
    location: { directory: project },
    session: { context: async () => [], synthetic: async () => {} },
    tool: { hook: async (name, callback) => {
      assert.equal(name, "execute.after");
      afterHook = callback;
      return { dispose: async () => { disposed.push(name); } };
    } },
    event: { subscribe: ({ signal }) => ({
      async *[Symbol.asyncIterator]() {
        if (!signal.aborted) await new Promise((resolve) =>
          signal.addEventListener("abort", resolve, { once: true }));
      },
    }) },
  };
  const cleanup = await Guardian.setup(v2);
  assert.equal(typeof afterHook, "function");
  await afterHook({
    tool: "write_to_file", sessionID: "s", id: "m2",
    input: { path: "file.ts", content: "export const value = true;" },
    status: "completed", result: { output: "saved", metadata: {} },
  });
  await cleanup();
  assert.deepEqual(disposed, ["execute.after"]);
});

test("Telemetry records remediation-verified, remediation-failed, and structured error codes", (t) => {
  isolated(t);

  recordGuardianEvent({
    kind: "remediation-verified",
    session: sessionFingerprint("sess-v"),
    rules: ["security/no-secrets"],
    reasons: [{ rule: "security/no-secrets", code: "remediation-verified" }],
  });

  recordGuardianEvent({
    kind: "remediation-failed",
    session: sessionFingerprint("sess-f"),
    rules: ["security/no-secrets"],
    reasons: [{ rule: "security/no-secrets", code: "remediation-failed" }],
  });

  recordGuardianEvent({
    kind: "inspection-error",
    session: sessionFingerprint("sess-err"),
    rules: ["engine-inspection-failed"],
    reasons: [{ rule: "engine-inspection-failed", code: "engine-inspection-failed" }],
  });

  const file = guardianEventPath();
  const content = fs.readFileSync(file, "utf8").trim().split("\n");
  assert.equal(content.length, 3);

  const e1 = JSON.parse(content[0]);
  assert.equal(e1.kind, "remediation-verified");
  assert.equal(e1.action, "remediation-checked");
  assert.equal(e1.outcome, "verified");

  const e2 = JSON.parse(content[1]);
  assert.equal(e2.kind, "remediation-failed");
  assert.equal(e2.action, "remediation-checked");
  assert.equal(e2.outcome, "reported");

  const e3 = JSON.parse(content[2]);
  assert.equal(e3.kind, "inspection-error");
  assert.equal(e3.action, "inspection-failed");
  assert.equal(e3.outcome, "error");
  assert.deepEqual(e3.rules, ["engine-inspection-failed"]);
});
