import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolveTelemetrySettings, clearGuardianTelemetryConfig, readGuardianStatus } from "../dist/index.js";
import { guardianCommandReport } from "../dist/commands.js";

function project(t, config) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-telemetry-level-"));
  if (config) fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify(config));
  t.after(() => { clearGuardianTelemetryConfig(); fs.rmSync(dir, { recursive: true, force: true }); });
  clearGuardianTelemetryConfig();
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
