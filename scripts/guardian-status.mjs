#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { readGuardianStatus, guardianEventPath, configureGuardianTelemetry } from "../dist/telemetry.js";
import { loadConfig, resolveEffectiveConfig } from "../dist/engine.js";

const cwd = process.cwd();
const targetDir =
  process.argv[2] ||
  (fs.existsSync(guardianEventPath(cwd)) ||
  fs.existsSync(path.join(cwd, ".opencode")) ||
  fs.existsSync(path.join(cwd, ".git"))
    ? cwd
    : undefined);
try {
  if (targetDir) configureGuardianTelemetry(targetDir, resolveEffectiveConfig(loadConfig(targetDir)).telemetry);
} catch {
  // Keep the default telemetry level when the project config is unreadable.
}
const s = readGuardianStatus(targetDir);
const modeNote =
  (s.telemetryLevel ?? "violations") === "violations"
    ? "violations (clean turns omit disk I/O)"
    : (s.telemetryLevel ?? "all");
console.log(`Guardian | preflight at last start: ${s.preflight} | telemetry mode: ${modeNote}`);
console.log(`Inspections (tool + turn): ${s.inspected} | blocked tools (preflight): ${s.blocked} | secret redactions (in-memory): ${s.redacted ?? 0}`);
console.log(`Post-turn warnings: ${s.warnings} | remediations: ${s.remediations} | errors: ${s.errors}`);
console.log(`Stream stops requested: ${s.streamStops} | verified: ${s.streamVerified} | ineffective: ${s.streamIneffective}`);
if (s.truncated) console.log("Note: counters cover only the newest 2 MiB of the log.");
console.log(`Event log: ${guardianEventPath(targetDir)}`);
