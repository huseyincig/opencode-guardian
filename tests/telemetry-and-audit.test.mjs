import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { guardianCommandReport } from "../dist/commands.js";
import { DEFAULT_CONFIG, GuardianConfigError, loadConfig, resolveEffectiveConfig } from "../dist/engine.js";
import Guardian, { GUARDIAN_MAX_LOG_BYTES, RULE_IDS, auditReasons, clearGuardianTelemetryConfig as clearGuardianTelemetryConfig_5, guardianEventPath, readGuardianStatus, recordGuardianEvent, resolveTelemetrySettings, sessionFingerprint } from "../dist/index.js";
import { clearGuardianTelemetryConfig, configureGuardianTelemetry, guardianEventPath as guardianEventPath_3, guardianEventPath as guardianEventPath_4, readGuardianStatus as readGuardianStatus_3, recordGuardianEvent as recordGuardianEvent_3 } from "../dist/telemetry.js";

describe("Telemetry Counters & Persistence", () => {
  function isolated(t) {
    const original = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    const originalLogLevel = process.env.OPENCODE_GUARDIAN_LOG_LEVEL;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-events-test-"));
    process.env.OPENCODE_GUARDIAN_STATE_DIR = dir;
    process.env.OPENCODE_GUARDIAN_LOG_LEVEL = "all";
    t.after(() => {
      if (original === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
      else process.env.OPENCODE_GUARDIAN_STATE_DIR = original;
      if (originalLogLevel === undefined) delete process.env.OPENCODE_GUARDIAN_LOG_LEVEL;
      else process.env.OPENCODE_GUARDIAN_LOG_LEVEL = originalLogLevel;
      fs.rmSync(dir, { recursive: true, force: true });
    });
    return dir;
  }
  function setupConfig(t, config) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-telemetry-config-"));
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify(config));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    return dir;
  }

  test("preflight-disabled project records real rule inspections but no blocked tools", (t) => {
    isolated(t);
    recordGuardianEvent({ kind: "runtime-started", runtime: "v1", preflight: "disabled" });
    recordGuardianEvent({ kind: "post-inspected", session: sessionFingerprint("secret-session") });
    recordGuardianEvent({ kind: "post-warning", rules: ["quality/no-shortcuts"] });
    const status = readGuardianStatus();
    assert.deepEqual([status.preflight, status.inspected, status.blocked, status.warnings], ["disabled", 1, 0, 1]);
    assert.doesNotMatch(fs.readFileSync(guardianEventPath(), "utf8"), /secret-session/);
  });

  test("V2 idle counts a real rule evaluation once, not duplicate idle events", async (t) => {
    isolated(t);
    const directory = setupConfig(t, { enabled: true, updateNotice: { enabled: false }, secrets: { enabled: false } });
    const host = {
      location: { directory },
      event: { subscribe({ signal }) { return (async function* () {
        yield { type: "session.idle", data: { sessionID: "v2-idle" } };
        yield { type: "session.idle", data: { sessionID: "v2-idle" } };
        await new Promise((resolve) => {
          if (signal.aborted) resolve();
          else signal.addEventListener("abort", resolve, { once: true });
        });
      })(); } },
      session: {
        async get({ sessionID }) { return { id: sessionID, location: { directory } }; },
        async context() { return [
          { id: "u2", type: "user", text: "Review the source." },
          { id: "a2", type: "assistant", content: [{ type: "text", text: "Reviewed the source." }] },
        ]; },
        async synthetic() {},
      },
    };
    const dispose = await Guardian.setup(host);
    t.after(() => dispose?.());
    const deadline = Date.now() + 1200;
    while (readGuardianStatus().inspected < 1 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 10));
    }
    await new Promise((r) => setTimeout(r, 25));
    assert.deepEqual([readGuardianStatus().inspected, readGuardianStatus().blocked, readGuardianStatus().errors], [1, 0, 0]);
  });

  test("JSONL events are restrictive, command-free, and have correct bounded counters", (t) => {
    isolated(t);
    assert.equal(readGuardianStatus().preflight, "unknown");
    recordGuardianEvent({ kind: "runtime-started", runtime: "v1", preflight: "active" });
    recordGuardianEvent({ kind: "preflight-allowed", tool: "bash", session: sessionFingerprint("private-session") });
    recordGuardianEvent({ kind: "preflight-blocked", tool: "bash", rules: ["destructive-command"] });
    recordGuardianEvent({ kind: "post-warning", rules: ["integrity/no-silent-failure"] });
    recordGuardianEvent({ kind: "post-remediation", rules: ["integrity/no-silent-failure"] });
    const file = guardianEventPath();
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
    const raw = fs.readFileSync(file, "utf8");
    assert.ok(!raw.includes("private-session"));
    assert.equal(raw.trim().split("\n").length, 5);
    assert.deepEqual(
      (({preflight, inspected, blocked, warnings, remediations, errors, truncated}) => ({preflight, inspected, blocked, warnings, remediations, errors, truncated}))(readGuardianStatus()),
      { preflight: "active", inspected: 2, blocked: 1, warnings: 1, remediations: 1, errors: 0, truncated: false },
    );
    assert.equal(readGuardianStatus(180).truncated, true);
  });

  test("V2 strict preflight records actual pre-execution decisions", async (t) => {
    isolated(t);
    const directory = setupConfig(t, {
      enabled: true,
      preflight: { enabled: true },
      secrets: { enabled: false },
    });
    let before;
    const controller = { context: {
      location: { directory },
      event: { subscribe({ signal }) { return (async function* () {
        await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
      })(); } },
      session: { async context() { return []; }, async synthetic() {}, },
      tool: { async hook(name, fn) { assert.equal(name, "execute.before"); before = fn; return { dispose() {} }; } },
    } };
    const cleanup = await Guardian.setup(controller.context);
    try {
      assert.equal(readGuardianStatus().preflight, "active");
      await before({ tool: "bash", input: { command: "npm test" }, sessionID: "s" });
      await assert.rejects(() => before({ tool: "bash", input: { command: "git clean -fd" }, sessionID: "s" }),
        (error) => error.reason === "destructive-command");
      assert.equal(readGuardianStatus().blocked, 1);
    } finally {
      await cleanup();
    }
  });

  test("existing event logs are restricted to user-only access before appending", (t) => {
    isolated(t);
    fs.writeFileSync(guardianEventPath(), "");
    fs.chmodSync(guardianEventPath(), 0o644);
    recordGuardianEvent({ kind: "runtime-started", runtime: "v1", preflight: "disabled" });
    assert.equal(fs.statSync(guardianEventPath()).mode & 0o777, 0o600);
    assert.equal(readGuardianStatus().preflight, "disabled");
  });

  test("telemetry refuses symlink event logs without modifying their target", (t) => {
    if (process.platform === "win32") return;
    const dir = isolated(t);
    const target = path.join(dir, "target.log");
    fs.writeFileSync(target, "not a guardian log\n");
    fs.symlinkSync(target, guardianEventPath());
    const priorError = console.error;
    console.error = (...args) => { void args; };
    try {
      recordGuardianEvent({ kind: "runtime-started", runtime: "v1", preflight: "active" });
    } finally {
      console.error = priorError;
    }
    assert.equal(fs.readFileSync(target, "utf8"), "not a guardian log\n");
  });

  test("telemetry refuses a pre-existing publicly traversable state directory", (t) => {
    if (process.platform === "win32") return;
    const dir = isolated(t);
    fs.chmodSync(dir, 0o755);
    recordGuardianEvent({ kind: "runtime-started", runtime: "v1", preflight: "active" });
    assert.equal(fs.existsSync(guardianEventPath()), false);
  });

  test("telemetry records project-scoped events in isolated state directory with 0600 file mode without polluting project .opencode", (t) => {
    const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-project-test-"));
    t.after(() => fs.rmSync(projectDir, { recursive: true, force: true }));

    const orig = process.env.OPENCODE_GUARDIAN_STATE_DIR;
    delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    t.after(() => {
      if (orig !== undefined) process.env.OPENCODE_GUARDIAN_STATE_DIR = orig;
    });

    recordGuardianEvent({ kind: "runtime-started", runtime: "v2", preflight: "active" }, projectDir);
    recordGuardianEvent({ kind: "preflight-allowed", tool: "bash" }, projectDir);
    recordGuardianEvent({ kind: "post-warning", rules: ["test-rule"] }, projectDir);

    const eventFile = guardianEventPath(projectDir);
    assert.equal(fs.existsSync(path.join(projectDir, ".opencode", "guardian-events.jsonl")), false);
    assert.equal(fs.existsSync(eventFile), true);
    if (process.platform !== "win32") {
      assert.equal(fs.statSync(eventFile).mode & 0o777, 0o600);
    }

    const status = readGuardianStatus(projectDir);
    assert.equal(status.preflight, "active");
    assert.equal(status.inspected, 1);
    assert.equal(status.warnings, 1);
  });
});

describe("Privacy-Safe Audit Log & Rotation", () => {
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

  test("real V2 post-turn intervention writes fixed reasons but never raw command text", async (t) => {
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
    let releaseEvent;
    const host = {
      location: { directory },
      options: { secrets: { enabled: false } },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            await new Promise((resolve) => { releaseEvent = resolve; });
            yield { type: "session.idle", data: { sessionID: "private-v2-session" } };
            await new Promise((resolve) => {
              if (signal.aborted) resolve();
              else signal.addEventListener("abort", resolve, { once: true });
            });
          })();
        },
      },
      session: {
        async get() { return { id: "private-v2-session", parentID: undefined }; },
        async context() {
          return [
            { id: "u1", type: "user", text: "Run the tests and address failures." },
            {
              id: "a1",
              type: "assistant",
              content: [
                {
                  type: "tool",
                  name: "bash",
                  state: { input: { command: "npm test || true # " + SECRET }, output: "tests failed" },
                },
                { type: "text", text: "The work is done." },
              ],
            },
          ];
        },
        async synthetic(input) {
          sent.push(input);
        },
      },
    };
    const cleanup = await Guardian.setup(host);
    try {
      releaseEvent();
      const deadline = Date.now() + 1500;
      while (sent.length < 1 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 15));
      }
      const remediation = sent.filter(
        (request) => request.resume === true
      );
      assert.equal(remediation.length, 1);

      const data = fs.readFileSync(guardianEventPath(), "utf8");
      assert.ok(!data.includes(SECRET) && !data.includes("npm test"));
      const event = data.split("\n").filter(Boolean).map(JSON.parse)
        .find((entry) => entry.kind === "post-remediation");
      assert.equal(event.outcome, "unverified");
      assert.deepEqual(event.reasons, [
        { rule: "integrity/no-silent-failure", code: "masked-verification-failure" },
      ]);
    } finally { await cleanup?.(); }
  });
});

describe("Telemetry Config Validation", () => {
  test("loadConfig accepts valid telemetry configurations", (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-cfg-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      telemetry: {
        enabled: true,
        level: "violations",
        maxBytes: 1048576,
      },
    }));

    const config = loadConfig(dir);
    assert.equal(config.telemetry?.enabled, true);
    assert.equal(config.telemetry?.level, "violations");
    assert.equal(config.telemetry?.maxBytes, 1048576);
  });

  test("loadConfig rejects invalid telemetry configurations", (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-cfg-err-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

    // Invalid level
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      telemetry: { level: "invalid-level" },
    }));
    assert.throws(() => loadConfig(dir), GuardianConfigError);

    // Invalid maxBytes (negative)
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      telemetry: { maxBytes: -50 },
    }));
    assert.throws(() => loadConfig(dir), GuardianConfigError);

    // Invalid maxBytes (not a number)
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      telemetry: { maxBytes: "one-megabyte" },
    }));
    assert.throws(() => loadConfig(dir), GuardianConfigError);

    // Invalid enabled (not a boolean)
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      telemetry: { enabled: "yes" },
    }));
    assert.throws(() => loadConfig(dir), GuardianConfigError);
  });

  test("resolveEffectiveConfig merges telemetry configuration", () => {
    const base = {
      ...DEFAULT_CONFIG,
      telemetry: { enabled: true, level: "all", maxBytes: 2097152 },
    };

    const effective = resolveEffectiveConfig(base, {
      telemetry: { level: "violations" },
    });

    assert.equal(effective.telemetry?.enabled, true);
    assert.equal(effective.telemetry?.level, "violations");
    assert.equal(effective.telemetry?.maxBytes, 2097152);
  });
});

describe("Low-I/O Telemetry Optimization", () => {
  function setupTestDir(t) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-telem-opt-"));
    t.after(() => {
      clearGuardianTelemetryConfig();
      delete process.env.OPENCODE_GUARDIAN_TELEMETRY;
      delete process.env.OPENCODE_GUARDIAN_LOG_LEVEL;
      delete process.env.OPENCODE_GUARDIAN_MAX_LOG_BYTES;
      fs.rmSync(dir, { recursive: true, force: true });
    });
    return dir;
  }

  test("violations mode suppresses benign events and records security events", (t) => {
    const dir = setupTestDir(t);
    configureGuardianTelemetry(dir, { enabled: true, level: "violations" });

    // Benign events should not be written to disk
    recordGuardianEvent_3({ kind: "preflight-allowed", tool: "bash" }, dir);
    recordGuardianEvent_3({ kind: "post-inspected" }, dir);

    const eventPath = guardianEventPath_3(dir);
    assert.equal(fs.existsSync(eventPath), false, "Benign events must not create or write to the audit file");

    // Critical security events must still be written
    recordGuardianEvent_3({ kind: "preflight-blocked", tool: "bash", rules: ["destructive-command"] }, dir);
    recordGuardianEvent_3({ kind: "post-warning", rules: ["quality/no-shortcuts"] }, dir);

    assert.equal(fs.existsSync(eventPath), true, "Violations must be written to audit file");
    const content = fs.readFileSync(eventPath, "utf8");
    assert.match(content, /preflight-blocked/);
    assert.match(content, /post-warning/);
    assert.doesNotMatch(content, /preflight-allowed/);
    assert.doesNotMatch(content, /post-inspected/);

    const status = readGuardianStatus_3(dir);
    assert.equal(status.blocked, 1);
    assert.equal(status.warnings, 1);
  });

  test("off mode suppresses all disk writes", (t) => {
    const dir = setupTestDir(t);
    configureGuardianTelemetry(dir, { enabled: true, level: "off" });

    recordGuardianEvent_3({ kind: "preflight-blocked", tool: "bash", rules: ["destructive-command"] }, dir);
    recordGuardianEvent_3({ kind: "post-warning", rules: ["quality/no-shortcuts"] }, dir);

    const eventPath = guardianEventPath_3(dir);
    assert.equal(fs.existsSync(eventPath), false, "off level must perform zero disk I/O");
  });

  test("OPENCODE_GUARDIAN_TELEMETRY=off env var disables all telemetry", (t) => {
    const dir = setupTestDir(t);
    process.env.OPENCODE_GUARDIAN_TELEMETRY = "off";

    recordGuardianEvent_3({ kind: "preflight-blocked", tool: "bash", rules: ["destructive-command"] }, dir);
    const eventPath = guardianEventPath_3(dir);
    assert.equal(fs.existsSync(eventPath), false, "OPENCODE_GUARDIAN_TELEMETRY=off must stop all disk writes");
  });

  test("OPENCODE_GUARDIAN_LOG_LEVEL=violations env var suppresses benign events", (t) => {
    const dir = setupTestDir(t);
    process.env.OPENCODE_GUARDIAN_LOG_LEVEL = "violations";

    recordGuardianEvent_3({ kind: "preflight-allowed", tool: "bash" }, dir);
    const eventPath = guardianEventPath_3(dir);
    assert.equal(fs.existsSync(eventPath), false, "violations env var must drop preflight-allowed");

    recordGuardianEvent_3({ kind: "post-warning", rules: ["quality/no-shortcuts"] }, dir);
    assert.equal(fs.existsSync(eventPath), true);
    const content = fs.readFileSync(eventPath, "utf8");
    assert.match(content, /post-warning/);
    assert.doesNotMatch(content, /preflight-allowed/);
  });

  test("custom maxBytes bounds the log file and triggers early rotation", (t) => {
    const dir = setupTestDir(t);
    // Set tiny limit of 350 bytes so two events trigger rotation
    configureGuardianTelemetry(dir, { enabled: true, level: "all", maxBytes: 350 });

    recordGuardianEvent_3({ kind: "runtime-started", runtime: "v2", preflight: "active" }, dir);
    recordGuardianEvent_3({ kind: "post-warning", rules: ["quality/no-shortcuts"] }, dir);
    recordGuardianEvent_3({ kind: "post-warning", rules: ["integrity/no-stubs"] }, dir);

    const eventPath = guardianEventPath_3(dir);
    const archivePath = eventPath + ".1";
    assert.equal(fs.existsSync(archivePath), true, "Archive must exist after bounded rotation");
  });
});

describe("Plugin Telemetry Integration", () => {
  function setupProject(t, config) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-integ-telem-"));
    t.after(() => {
      clearGuardianTelemetryConfig();
      delete process.env.OPENCODE_GUARDIAN_TELEMETRY;
      delete process.env.OPENCODE_GUARDIAN_LOG_LEVEL;
      fs.rmSync(dir, { recursive: true, force: true });
    });
    if (config) {
      fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify(config));
    }
    return dir;
  }

  test("V2 server with telemetry.level='violations' suppresses preflight-allowed but writes preflight-blocked", async (t) => {
    const dir = setupProject(t, {
      enabled: true,
      preflight: { enabled: true },
      telemetry: { level: "violations" },
      updateNotice: { enabled: false },
      secrets: { enabled: false },
    });

    let executeBefore;
    const host = {
      location: { directory: dir },
      event: { subscribe: () => (async function* () {})() },
      session: {
        async context() { return []; },
        async synthetic() {},
      },
      tool: {
        async hook(name, handler) {
          if (name === "execute.before") executeBefore = handler;
          return { dispose() {} };
        },
      },
    };

    const cleanup = await Guardian.setup(host);
    t.after(() => cleanup?.());

    await executeBefore({ sessionID: "s1", callID: "c1", tool: "bash", input: { command: "ls -la" } });

    const eventPath = guardianEventPath_4(dir);
    if (fs.existsSync(eventPath)) {
      const content = fs.readFileSync(eventPath, "utf8");
      assert.doesNotMatch(content, /preflight-allowed/);
    }

    await assert.rejects(
      () => executeBefore({ sessionID: "s1", callID: "c2", tool: "bash", input: { command: "rm -rf /" } }),
      /GuardianPreflightError/
    );

    assert.equal(fs.existsSync(eventPath), true);
    const content = fs.readFileSync(eventPath, "utf8");
    assert.match(content, /preflight-blocked/);
    assert.doesNotMatch(content, /preflight-allowed/);
  });

  test("V2 server with telemetry.level='off' writes no events at all", async (t) => {
    const dir = setupProject(t, {
      enabled: true,
      preflight: { enabled: true },
      telemetry: { level: "off" },
      updateNotice: { enabled: false },
      secrets: { enabled: false },
    });

    let executeBefore;
    const host = {
      location: { directory: dir },
      event: { subscribe: () => (async function* () {})() },
      session: {
        async context() { return []; },
        async synthetic() {},
      },
      tool: {
        async hook(name, handler) {
          if (name === "execute.before") executeBefore = handler;
          return { dispose() {} };
        },
      },
    };

    const cleanup = await Guardian.setup(host);
    t.after(() => cleanup?.());

    await executeBefore({ sessionID: "s1", callID: "c1", tool: "bash", input: { command: "echo ok" } });
    await assert.rejects(
      () => executeBefore({ sessionID: "s1", callID: "c2", tool: "bash", input: { command: "rm -rf /" } }),
      /GuardianPreflightError/
    );

    const eventPath = guardianEventPath_4(dir);
    assert.equal(fs.existsSync(eventPath), false, "telemetry.level='off' must create no event log file");
  });

  test("V2 setup with telemetry.level='violations' suppresses benign events", async (t) => {
    const dir = setupProject(t, {
      enabled: true,
      telemetry: { level: "violations" },
      secrets: { enabled: false },
    });

    const abortController = new AbortController();
    t.after(() => abortController.abort());

    const host = {
      location: { directory: dir },
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
      session: {
        async context() { return []; },
        async synthetic() {},
      },
    };

    const cleanup = await Guardian.setup(host);
    t.after(() => cleanup?.());

    const eventPath = guardianEventPath_4(dir);
    if (fs.existsSync(eventPath)) {
      const content = fs.readFileSync(eventPath, "utf8");
      assert.doesNotMatch(content, /preflight-allowed/);
      assert.doesNotMatch(content, /post-inspected/);
    }
  });
});

describe("Default Telemetry Level Semantics", () => {
  function project(t, config) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-telemetry-level-"));
    if (config) fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify(config));
    t.after(() => { clearGuardianTelemetryConfig_5(); fs.rmSync(dir, { recursive: true, force: true }); });
    clearGuardianTelemetryConfig_5();
    return dir;
  }

  test("an unconfigured process defaults to the documented violations level, not all", t => {
    const dir = project(t);
    assert.equal(resolveTelemetrySettings(dir).level, "violations");
    assert.equal(readGuardianStatus(dir).telemetryLevel, "violations");
  });

  test("/guardian-status in a process that never ran setup shows the default violations mode", async t => {
    const dir = project(t);
    const report = await guardianCommandReport("status", dir, "0.0.0");
    assert.match(report.message, /Telemetry mode: violations/);
  });

  test("/guardian-status reflects an explicit project telemetry level without prior setup", async t => {
    const dir = project(t, { telemetry: { level: "all" } });
    const report = await guardianCommandReport("status", dir, "0.0.0");
    assert.match(report.message, /Telemetry mode: all/);
  });
});
