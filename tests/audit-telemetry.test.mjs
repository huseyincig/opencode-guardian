import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, {
  RULE_IDS, auditReasons, GUARDIAN_MAX_LOG_BYTES,
  guardianEventPath, readGuardianStatus, recordGuardianEvent,
} from "../dist/index.js";

function isolated(t) {
  const previous = process.env.OPENCODE_GUARDIAN_STATE_DIR;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-audit-safety-"));
  process.env.OPENCODE_GUARDIAN_STATE_DIR = dir;
  t.after(() => {
    if (previous === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    else process.env.OPENCODE_GUARDIAN_STATE_DIR = previous;
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return dir;
}

test("fixed audit reason codes explain known findings without persisting pattern or snippet", () => {
  const SECRET = "sk-proj-SECRET-SHOULD-NEVER-BE-LOGGED";
  const results = [
    { ruleId: "integrity/no-silent-failure", decision: "block", findings: [
      { ruleId: "integrity/no-silent-failure", pattern: "masked verification failure",
        messageSnippet: SECRET, description: SECRET },
      { ruleId: "integrity/no-silent-failure", pattern: SECRET,
        messageSnippet: SECRET, description: SECRET },
    ] },
    { ruleId: "task/completion-gate", decision: "block", findings: [
      { ruleId: "task/completion-gate",
        pattern: "iteration ended after a change without a new review",
        messageSnippet: SECRET, description: SECRET },
    ] },
    { ruleId: "quality/no-shortcuts", decision: "pass", findings: [
      { ruleId: "quality/no-shortcuts", pattern: "TODO",
        messageSnippet: SECRET, description: SECRET },
    ] },
  ];
  const reasons = auditReasons(results);
  assert.deepEqual(reasons, [
    { rule: "integrity/no-silent-failure", code: "masked-verification-failure" },
    { rule: "integrity/no-silent-failure", code: "swallowed-error" },
    { rule: "task/completion-gate", code: "missing-follow-up-review" },
    { rule: "quality/no-shortcuts", code: "code-placeholder" },
  ]);
  assert.ok(!JSON.stringify(reasons).includes(SECRET));
});

test("serialized audit events enforce allowlists even for malicious injected metadata", (t) => {
  isolated(t);
  const SECRET = "sk-proj-SECRET-SHOULD-NEVER-BE-LOGGED";
  recordGuardianEvent({
    kind: "post-remediation", outcome: "verified", action: "completed",
    session: SECRET, tool: "bash." + SECRET,
    rules: ["integrity/no-silent-failure", SECRET],
    reasons: [
      { rule: "integrity/no-silent-failure", code: "masked-verification-failure" },
      { rule: "integrity/no-silent-failure", code: SECRET },
      { rule: SECRET, code: "masked-verification-failure" },
    ],
  });
  const raw = fs.readFileSync(guardianEventPath(), "utf8");
  assert.ok(!raw.includes(SECRET));
  const entry = JSON.parse(raw.trim());
  assert.match(entry.id, /^[0-9a-f-]{36}$/);
  assert.equal(entry.session, undefined);
  assert.equal(entry.tool, "custom-shell-tool");
  assert.deepEqual(entry.rules, ["integrity/no-silent-failure"]);
  assert.deepEqual(entry.reasons, [
    { rule: "integrity/no-silent-failure", code: "masked-verification-failure" },
  ]);
  assert.equal(entry.action, "remediation-requested");
  assert.equal(entry.outcome, "unverified");
  assert.equal(readGuardianStatus().remediations, 1);
});

test("preflight block records only a fixed reason and an actually prevented outcome", (t) => {
  isolated(t);
  recordGuardianEvent({
    kind: "preflight-blocked", tool: "bash",
    rules: ["destructive-command"],
  });
  const entry = JSON.parse(fs.readFileSync(guardianEventPath(), "utf8"));
  assert.equal(entry.action, "blocked-before-execution");
  assert.equal(entry.outcome, "prevented");
  assert.deepEqual(entry.reasons, [{ rule: "preflight", code: "destructive-command" }]);
});

test("event log rotates into one user-only archive at 2 MiB and keeps counters bounded", (t) => {
  isolated(t);
  const log = guardianEventPath();
  const line = JSON.stringify({ at: "2026-10-04T00:00:00Z", kind: "post-warning" }) + "\n";
  fs.writeFileSync(log, line.repeat(Math.floor((GUARDIAN_MAX_LOG_BYTES - 80) / line.length)));
  const initialSize = fs.statSync(log).size;
  assert.ok(initialSize < GUARDIAN_MAX_LOG_BYTES);
  const pad = " ".repeat(GUARDIAN_MAX_LOG_BYTES - initialSize - 10);
  fs.appendFileSync(log, pad);
  recordGuardianEvent({ kind: "post-remediation", rules: ["task/completion-gate"],
    reasons: [{ rule: "task/completion-gate", code: "required-verification-unconfirmed" }] });
  assert.ok(fs.existsSync(log + ".1"));
  assert.ok(fs.statSync(log + ".1").size <= GUARDIAN_MAX_LOG_BYTES);
  assert.ok(fs.statSync(log).size < GUARDIAN_MAX_LOG_BYTES);
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(log).mode & 0o777, 0o600);
    assert.equal(fs.statSync(log + ".1").mode & 0o777, 0o600);
  }
  assert.equal(readGuardianStatus().remediations, 1);
  assert.equal(readGuardianStatus().truncated, true);
});

test("log rotation refuses symlink archives without touching their targets", (t) => {
  if (process.platform === "win32") return;
  const dir = isolated(t);
  const log = guardianEventPath();
  const target = path.join(dir, "private-target");
  fs.writeFileSync(log, "x".repeat(GUARDIAN_MAX_LOG_BYTES));
  fs.writeFileSync(target, "SENSITIVE CONTENT");
  fs.symlinkSync(target, log + ".1");
  const before = fs.statSync(log).size;
  const originalError = console.error;
  console.error = () => {};
  try {
    recordGuardianEvent({ kind: "post-warning", rules: ["quality/no-shortcuts"] });
  } finally {
    console.error = originalError;
  }
  assert.equal(fs.readFileSync(target, "utf8"), "SENSITIVE CONTENT");
  assert.equal(fs.statSync(log).size, before);
});

test("real V1 post-turn intervention writes fixed reasons but never raw command text", async (t) => {
  isolated(t);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-real-audit-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
    enabled: true,
    rules: Object.fromEntries(RULE_IDS.map((rule) =>
      [rule, rule === "integrity/no-silent-failure" ? "error" : "off"])),
  }));
  const SECRET = "sk-proj-NEVER-IN-THE-LOG";
  const sent = [];
  const client = { session: {
    async get({ path: requestPath }) {
      return { data: { id: requestPath.id, parentID: undefined } };
    },
    async messages() {
      return { data: [
        { info: { id: "u1", role: "user" },
          parts: [{ type: "text", text: "Run the tests and address failures." }] },
        { info: { id: "a1", role: "assistant", time: { completed: 1 } },
          parts: [
            { type: "tool", tool: "bash",
              state: { input: { command: "npm test || true # " + SECRET }, output: "tests failed" } },
            { type: "text", text: "The work is done." },
          ] },
      ] };
    },
    async promptAsync(input) {
      sent.push(input);
      return { data: {}, error: undefined };
    },
  } };
  const hooks = await Guardian.server({ directory, client });
  try {
    await hooks.event({ event: { type: "session.idle", properties: { sessionID: "private-v1-session" } } });
    const remediation = sent.filter(
      (request) => request.body?.parts?.[0]?.synthetic === true
    );
    const visible = sent.filter(
      (request) =>
        request.body?.noReply === true &&
        request.body?.parts?.[0]?.ignored === true &&
        request.body?.parts?.[0]?.metadata?.["opencode-guardian-visible"] === true
    );
    assert.equal(remediation.length, 1);
    assert.equal(visible.length, 1);
    assert.doesNotMatch(visible[0].body.parts[0].text, /sk-proj-NEVER-IN-THE-LOG|npm test/);

    const data = fs.readFileSync(guardianEventPath(), "utf8");
    assert.ok(!data.includes(SECRET) && !data.includes("npm test"));
    const event = data.split("\n").filter(Boolean).map(JSON.parse)
      .find((entry) => entry.kind === "post-remediation");
    assert.equal(event.outcome, "unverified");
    assert.deepEqual(event.reasons, [
      { rule: "integrity/no-silent-failure", code: "masked-verification-failure" },
    ]);
  } finally { await hooks.dispose?.(); }
});
