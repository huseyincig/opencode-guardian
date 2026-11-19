import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import plugin, {
  collectTurnEvidence,
  normalizeV2Messages,
  noUnverifiedClaimsRule,
  noSecretsRule,
  taskCompletionRule,
  resolveV2AgentCapability,
  isSourceReviewEvidence,
  classifyAgentReport,
  sanitizeObject,
  isSensitiveKey,
} from "../dist/index.js";
import { clearGuardianTelemetryConfig } from "../dist/telemetry.js";

function makeTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("v2.3.1 backgrounded/timed-out shell command is never treated as completed success or completed mutation", () => {
  const evidence = collectTurnEvidence([
    {
      info: { id: "a1", role: "assistant" },
      parts: [
        {
          type: "tool",
          tool: "shell",
          callID: "c1",
          state: {
            status: "completed",
            input: { command: "npm test && rm -f tmp.txt" },
            output:
              "Command moved to the background (shell ID: sh_1).\n" +
              "The command did not finish within its timeout of 120 seconds and was moved to the background.",
            metadata: { status: "running", shellID: "sh_1", pid: 4242 },
          },
        },
      ],
    },
  ]);

  assert.equal(evidence.successfulVerifications.length, 0);
  assert.equal(evidence.failures.length, 0);
  assert.equal(evidence.records.find((r) => r.kind === "test")?.status, "unknown");
  assert.equal(evidence.fileMutations[0]?.status, "unknown");
});

test("v2.3.1 synthetic shell completion notification produces verifiable test evidence", () => {
  const passMessages = normalizeV2Messages([
    { id: "u1", type: "user", text: "Run tests and fix." },
    {
      id: "s1",
      type: "synthetic",
      text: '<shell id="job_1" state="completed" command="npm test">\n✔ all 5 tests passed\n</shell>',
      description: "npm test",
      metadata: { source: "shell", shellID: "sh_1", jobID: "job_1", state: "completed", exit: 0 },
    },
    {
      id: "a1",
      type: "assistant",
      content: [{ type: "text", text: "All tests passed." }],
    },
  ]);

  const evidence = collectTurnEvidence(passMessages);
  assert.equal(evidence.successfulVerifications.length, 1);
  assert.equal(evidence.successfulVerifications[0]?.kind, "test");

  const claimResult = noUnverifiedClaimsRule.inspect({
    sessionID: "sess-1",
    directory: process.cwd(),
    messages: passMessages,
    currentTurn: passMessages,
    evidence,
    ruleConfig: {},
  });
  assert.equal(claimResult.decision, "pass");

  const failMessages = normalizeV2Messages([
    { id: "u2", type: "user", text: "Run tests." },
    {
      id: "s2",
      type: "synthetic",
      text: '<shell id="job_2" state="error" command="npm test">\n1 test failed\n</shell>',
      metadata: { source: "shell", shellID: "sh_2", state: "error", exit: 1 },
    },
  ]);
  const failEvidence = collectTurnEvidence(failMessages);
  assert.equal(failEvidence.failures.length, 1);
  assert.equal(failEvidence.failures[0]?.exitCode, 1);
});

test("v2.3.1 shell message with status 'running' is normalized as running, not error", () => {
  const messages = normalizeV2Messages([
    { id: "u1", type: "user", text: "Run long build." },
    { id: "sh1", type: "shell", shellID: "sh_run", command: "npm run build", status: "running" },
    { id: "a1", type: "assistant", content: [{ type: "text", text: "Build is running in the background." }] },
  ]);

  assert.equal(messages[1]?.parts[0]?.state?.status, "running");
  assert.equal(messages[1]?.parts[0]?.state?.metadata?.status, "running");
  const evidence = collectTurnEvidence(messages);
  assert.equal(evidence.failures.length, 0);

  const report = classifyAgentReport("Build is running in the background.");
  assert.equal(report.isInProgress, true);

  const gate = taskCompletionRule.inspect({
    sessionID: "s-run",
    directory: process.cwd(),
    messages,
    currentTurn: messages,
    evidence,
    ruleConfig: {},
  });
  assert.equal(gate.decision, "pass");
});

test("v2.3.1 Code Mode execute expands metadata.toolCalls and catches metadata.error failures", () => {
  const secret = "sk-proj-codemode_secret_key_1234567890abcd";
  const messages = normalizeV2Messages([
    { id: "u1", type: "user", text: "Write config via code mode." },
    {
      id: "a1",
      type: "assistant",
      content: [
        {
          type: "tool",
          id: "exec_1",
          name: "execute",
          state: {
            status: "completed",
            input: { code: "await tools.write({ path: 'cfg.ts', content: '...' })" },
            content: "Error in script",
            metadata: {
              error: true,
              toolCalls: [
                {
                  tool: "write",
                  status: "completed",
                  input: { path: "cfg.ts", content: `export const k = "${secret}";` },
                },
                {
                  tool: "shell",
                  status: "completed",
                  input: { command: "npm test" },
                },
              ],
            },
          },
        },
      ],
    },
  ]);

  const evidence = collectTurnEvidence(messages);
  assert.ok(evidence.failures.some((f) => f.toolName === "execute"), "metadata.error must record failure");
  assert.ok(
    evidence.successfulVerifications.some((v) => v.kind === "test" && v.toolName === "shell"),
    "nested Code Mode shell call must produce test evidence"
  );

  const secretCheck = noSecretsRule.inspect({
    sessionID: "s-cm",
    directory: process.cwd(),
    messages,
    currentTurn: messages,
    evidence,
    ruleConfig: {},
  });
  assert.equal(secretCheck.decision, "block", "Code Mode write toolCall must be inspected by no-secrets");
});

test("v2.3.0+ experimental.idle with active background jobs suppresses premature idle remediation", async (t) => {
  const dir = makeTempDir("guardian-exp-idle-");
  t.after(() => {
    clearGuardianTelemetryConfig();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  fs.writeFileSync(
    path.join(dir, "opencode-guardian.json"),
    JSON.stringify({ enabled: true, telemetry: { level: "off" } })
  );

  let expIdleCb;
  const synthetic = [];
  let pushEvent;
  const stream = {
    async *[Symbol.asyncIterator]() {
      while (true) {
        const next = await new Promise((resolve) => {
          pushEvent = resolve;
        });
        if (!next) break;
        yield next;
      }
    },
  };

  const dispose = await plugin.setup({
    location: { directory: dir },
    event: { subscribe: () => stream },
    tool: { hook: () => ({ dispose() {} }) },
    session: {
      hook: async (name, cb) => {
        if (name === "experimental.idle") expIdleCb = cb;
        return { dispose() {} };
      },
      get: async () => ({ id: "s-bg", location: { directory: dir } }),
      context: async () => [
        { id: "u1", type: "user", text: "Fix and run tests." },
        { id: "a1", type: "assistant", content: [{ type: "text", text: "I apologize for the error." }] },
      ],
      synthetic: async (payload) => {
        synthetic.push(payload);
      },
    },
  });
  t.after(async () => {
    pushEvent?.(null);
    await dispose?.();
  });

  assert.equal(typeof expIdleCb, "function");
  await expIdleCb({
    sessionID: "s-bg",
    background: [{ kind: "codemode", sessionID: "s-bg", jobID: "j1" }],
  });
  pushEvent({ type: "session.idle", data: { sessionID: "s-bg" } });
  await new Promise((r) => setTimeout(r, 40));
  assert.equal(synthetic.length, 0, "Must not remediate while background job is active");

  await expIdleCb({ sessionID: "s-bg", background: [] });
  pushEvent({ type: "session.idle", data: { sessionID: "s-bg" } });
  for (let i = 0; i < 40 && synthetic.length === 0; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
  assert.equal(synthetic.length, 1, "Must inspect normally once background jobs clear");
});

test("v2.3.1 read tool string content and structured output are parsed, while directory listings are not source reviews", () => {
  const msgs = normalizeV2Messages([
    {
      id: "a1",
      type: "assistant",
      content: [
        {
          type: "tool",
          id: "r1",
          name: "read",
          state: {
            status: "completed",
            input: { path: "src" },
            output: { type: "directory", entries: ["index.ts", "engine.ts"] },
            content: "Read directory src, entries 1-2\nindex.ts\nengine.ts",
          },
        },
        {
          type: "tool",
          id: "r2",
          name: "read",
          state: {
            status: "completed",
            input: { path: "src/index.ts" },
            output: { type: "text", content: "export const x = 1;", offset: 1, lineCount: 1 },
            content: "Read file src/index.ts, lines 1-1\n1: export const x = 1;",
          },
        },
      ],
    },
  ]);

  const evidence = collectTurnEvidence(msgs);
  assert.equal(evidence.records.length, 2);
  assert.equal(isSourceReviewEvidence(evidence.records[0]), false, "directory read must not satisfy source review");
  assert.equal(isSourceReviewEvidence(evidence.records[1]), true, "file text read must satisfy source review");
});

test("resolveV2AgentCapability merges agent.list base permissions with session.permissions", async () => {
  const profile = await resolveV2AgentCapability(
    {
      session: {
        get: async () => ({
          id: "child-1",
          agent: "coder",
          permissions: [{ permission: "read", resource: "*", effect: "allow" }],
        }),
      },
      agent: {
        list: async () => [
          {
            id: "coder",
            name: "coder",
            permissions: [{ permission: "edit", resource: "*", effect: "allow" }],
          },
        ],
      },
    },
    "child-1"
  );

  assert.equal(profile.capability, "write-allowed");
  assert.equal(profile.evidence.edit, "allow");
});

test("SENSITIVE_KEY_REGEX ignores 'pass' counters and sanitizeObject preserves null/boolean/number fields", () => {
  assert.equal(isSensitiveKey("pass"), false);
  assert.equal(isSensitiveKey("PASSWORD"), true);
  assert.equal(isSensitiveKey("API_PASSPHRASE"), true);

  const sanitized = sanitizeObject({
    pass: 12,
    fail: 0,
    hasPassword: false,
    token: null,
    secretCount: 3,
    apiKey: "sk-proj-real_secret_value_1234567890",
  }).sanitized;

  assert.equal(sanitized.pass, 12);
  assert.equal(sanitized.hasPassword, false);
  assert.equal(sanitized.token, null);
  assert.equal(sanitized.secretCount, 3);
  assert.equal(sanitized.apiKey, "[REDACTED]");
});
