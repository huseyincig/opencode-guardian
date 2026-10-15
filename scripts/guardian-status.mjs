#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { readGuardianStatus, guardianEventPath } from "../dist/telemetry.js";

const targetDir = process.argv[2] || (fs.existsSync(path.join(process.cwd(), ".opencode")) ? process.cwd() : undefined);
const s = readGuardianStatus(targetDir);
console.log(`Guardian | preflight at last start: ${s.preflight}`);
console.log(`Inspections (tool + turn): ${s.inspected} | blocked tools (preflight): ${s.blocked}`);
console.log(`Post-turn warnings: ${s.warnings} | remediations: ${s.remediations} | errors: ${s.errors}`);
if (s.truncated) console.log("Note: counters cover only the newest 2 MiB of the log.");
console.log(`Event log: ${guardianEventPath(targetDir)}`);
