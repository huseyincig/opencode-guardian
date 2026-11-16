import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  recordGuardianEvent,
  readGuardianStatus,
  guardianEventPath,
  configureGuardianTelemetry,
  clearGuardianTelemetryConfig,
} from "../dist/telemetry.js";

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
  recordGuardianEvent({ kind: "preflight-allowed", tool: "bash" }, dir);
  recordGuardianEvent({ kind: "post-inspected" }, dir);

  const eventPath = guardianEventPath(dir);
  assert.equal(fs.existsSync(eventPath), false, "Benign events must not create or write to the audit file");

  // Critical security events must still be written
  recordGuardianEvent({ kind: "preflight-blocked", tool: "bash", rules: ["destructive-command"] }, dir);
  recordGuardianEvent({ kind: "post-warning", rules: ["quality/no-shortcuts"] }, dir);

  assert.equal(fs.existsSync(eventPath), true, "Violations must be written to audit file");
  const content = fs.readFileSync(eventPath, "utf8");
  assert.match(content, /preflight-blocked/);
  assert.match(content, /post-warning/);
  assert.doesNotMatch(content, /preflight-allowed/);
  assert.doesNotMatch(content, /post-inspected/);

  const status = readGuardianStatus(dir);
  assert.equal(status.blocked, 1);
  assert.equal(status.warnings, 1);
});

test("off mode suppresses all disk writes", (t) => {
  const dir = setupTestDir(t);
  configureGuardianTelemetry(dir, { enabled: true, level: "off" });

  recordGuardianEvent({ kind: "preflight-blocked", tool: "bash", rules: ["destructive-command"] }, dir);
  recordGuardianEvent({ kind: "post-warning", rules: ["quality/no-shortcuts"] }, dir);

  const eventPath = guardianEventPath(dir);
  assert.equal(fs.existsSync(eventPath), false, "off level must perform zero disk I/O");
});

test("OPENCODE_GUARDIAN_TELEMETRY=off env var disables all telemetry", (t) => {
  const dir = setupTestDir(t);
  process.env.OPENCODE_GUARDIAN_TELEMETRY = "off";

  recordGuardianEvent({ kind: "preflight-blocked", tool: "bash", rules: ["destructive-command"] }, dir);
  const eventPath = guardianEventPath(dir);
  assert.equal(fs.existsSync(eventPath), false, "OPENCODE_GUARDIAN_TELEMETRY=off must stop all disk writes");
});

test("OPENCODE_GUARDIAN_LOG_LEVEL=violations env var suppresses benign events", (t) => {
  const dir = setupTestDir(t);
  process.env.OPENCODE_GUARDIAN_LOG_LEVEL = "violations";

  recordGuardianEvent({ kind: "preflight-allowed", tool: "bash" }, dir);
  const eventPath = guardianEventPath(dir);
  assert.equal(fs.existsSync(eventPath), false, "violations env var must drop preflight-allowed");

  recordGuardianEvent({ kind: "post-warning", rules: ["quality/no-shortcuts"] }, dir);
  assert.equal(fs.existsSync(eventPath), true);
  const content = fs.readFileSync(eventPath, "utf8");
  assert.match(content, /post-warning/);
  assert.doesNotMatch(content, /preflight-allowed/);
});

test("custom maxBytes bounds the log file and triggers early rotation", (t) => {
  const dir = setupTestDir(t);
  // Set tiny limit of 350 bytes so two events trigger rotation
  configureGuardianTelemetry(dir, { enabled: true, level: "all", maxBytes: 350 });

  recordGuardianEvent({ kind: "runtime-started", runtime: "v2", preflight: "active" }, dir);
  recordGuardianEvent({ kind: "post-warning", rules: ["quality/no-shortcuts"] }, dir);
  recordGuardianEvent({ kind: "post-warning", rules: ["integrity/no-stubs"] }, dir);

  const eventPath = guardianEventPath(dir);
  const archivePath = eventPath + ".1";
  assert.equal(fs.existsSync(archivePath), true, "Archive must exist after bounded rotation");
});
