import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  guardianEventPath, readGuardianStatus, readGuardianActivity, recordGuardianEvent,
  resetGuardianStatistics,
} from "../dist/telemetry.js";
import {
  GUARDIAN_COMMANDS, guardianCommandReport, guardianResetReport,
} from "../dist/commands.js";
import GuardianTui, {
  registerGuardianV1Commands, registerGuardianV2Commands,
} from "../dist/tui-standalone.js";

function isolated(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-commands-"));
  const old = process.env.OPENCODE_GUARDIAN_STATE_DIR;
  process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "private-events");
  t.after(() => {
    if (old === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    else process.env.OPENCODE_GUARDIAN_STATE_DIR = old;
    fs.rmSync(directory, { recursive: true, force: true });
  });
  return directory;
}

test("seven stable commands have distinct palette and slash identifiers", () => {
  assert.deepEqual(GUARDIAN_COMMANDS.map((c) => c.id),
    ["status", "activity", "doctor", "rules", "config", "version", "reset"]);
  assert.equal(new Set(GUARDIAN_COMMANDS.map((c) => c.title)).size, 7);
});

test("reset preserves audit events and policy state but restarts project counters", (t) => {
  const dir = isolated(t);
  recordGuardianEvent({ kind: "runtime-started", runtime: "v2", preflight: "active" }, dir);
  recordGuardianEvent({ kind: "preflight-blocked", tool: "bash", rules: ["destructive-command"] }, dir);
  recordGuardianEvent({ kind: "post-remediation", rules: ["task/completion-gate"] }, dir);
  recordGuardianEvent({ kind: "remediation-verified", rules: ["task/completion-gate"] }, dir);
  assert.equal(readGuardianStatus(dir).blocked, 1);
  assert.equal(readGuardianStatus(dir).verified, 1);
  const before = fs.readFileSync(guardianEventPath(dir), "utf8");
  assert.equal(resetGuardianStatistics(dir), true);
  const after = fs.readFileSync(guardianEventPath(dir), "utf8");
  assert.ok(after.startsWith(before), "security history must remain byte-for-byte intact");
  assert.equal(after.trim().split("\n").length, 5);
  const status = readGuardianStatus(dir);
  assert.deepEqual([status.preflight, status.inspected, status.blocked,
    status.remediations, status.verified, status.lastKind],
    ["active", 0, 0, 0, 0, "statistics-reset"]);
  assert.equal(readGuardianActivity(dir)[0].kind, "statistics-reset");
  recordGuardianEvent({ kind: "preflight-allowed", tool: "bash" }, dir);
  assert.equal(readGuardianStatus(dir).inspected, 1);
  assert.equal(readGuardianStatus(dir).blocked, 0);
});

test("activity is bounded and strips untrusted log text and unknown fields", (t) => {
  const dir = isolated(t);
  recordGuardianEvent({ kind: "runtime-started", runtime: "v2", preflight: "active" }, dir);
  const file = guardianEventPath(dir);
  fs.appendFileSync(file, JSON.stringify({
    at: "2026-10-04T21:00:00.000Z", kind: "preflight-blocked",
    tool: "bash", command: "TOP_SECRET_COMMAND",
    rules: ["destructive-command", "private-secret-rule"],
    message: "TOP_SECRET_MESSAGE",
    session: "private-session",
  }) + "\n");
  for (let i = 0; i < 50; i++) {
    recordGuardianEvent({ kind: "post-warning", rules: ["quality/no-shortcuts"] }, dir);
  }
  const events = readGuardianActivity(dir, 1000);
  assert.equal(events.length, 30);
  assert.ok(!JSON.stringify(events).includes("TOP_SECRET"));
  assert.ok(!JSON.stringify(events).includes("private-session"));
  assert.ok(!JSON.stringify(readGuardianActivity(dir, 12)).includes("private-secret-rule"));
  assert.equal(readGuardianActivity(dir, 12).length, 12);
});

test("reporting differentiates verified, failed and unverified work without fabrication", async (t) => {
  const dir = isolated(t);
  recordGuardianEvent({ kind: "remediation-verified", rules: ["task/completion-gate"] }, dir);
  recordGuardianEvent({ kind: "remediation-failed", rules: ["task/completion-gate"] }, dir);
  recordGuardianEvent({ kind: "remediation-unverified", rules: ["task/completion-gate"] }, dir);
  const status = await guardianCommandReport("status", dir, "0.6.5");
  assert.match(status.message, /Verified \/ failed \/ unverified: 1 \/ 1 \/ 1/);
  const activity = await guardianCommandReport("activity", dir, "0.6.5");
  assert.match(activity.message, /remediation-verified/);
  const doctor = await guardianCommandReport("doctor", dir, "0.6.5");
  assert.match(doctor.message, /live hook health requires a host test/);
  const config = await guardianCommandReport("config", dir, "0.6.5");
  assert.match(config.message, /Sensitive configuration values are not displayed/);
  const rules = await guardianCommandReport("rules", dir, "0.6.5");
  assert.match(rules.message, /task\/completion-gate/);
});

test("configuration diagnostics fail safely without showing private file contents", async (t) => {
  const dir = isolated(t);
  fs.writeFileSync(path.join(dir, "opencode-guardian.json"), '{"enabled": "TOP_SECRET_VALUE"}');
  const report = await guardianCommandReport("doctor", dir, "0.6.5");
  assert.match(report.message, /Configuration: invalid/);
  assert.doesNotMatch(report.message, /TOP_SECRET_VALUE/);
  const config = await guardianCommandReport("config", dir, "0.6.5");
  assert.doesNotMatch(config.message, /TOP_SECRET_VALUE/);
});

test("reset reports success only after recording the reset event", (t) => {
  const dir = isolated(t);
  const result = guardianResetReport(dir);
  assert.match(result.message, /No audit-log wipe was performed/);
  assert.equal(readGuardianStatus(dir).lastKind, "statistics-reset");
});

test("V1 uses the installed command.register contract and requires reset confirmation", async (t) => {
  const dir = isolated(t);
  let registered;
  let dialogState;
  let dialogCleared = 0;
  const dialog = {
    setSize() {},
    replace(render) { dialogState = render(); },
    clear() { dialogCleared++; },
  };
  const api = {
    state: { path: { directory: dir } },
    command: { register(factory) { registered = factory(); return () => {}; } },
    ui: {
      dialog,
      DialogAlert: (props) => ({ ...props, type: "alert" }),
      DialogConfirm: (props) => ({ ...props, type: "confirm" }),
    },
    slots: { register() {} },
  };
  registerGuardianV1Commands(api);
  assert.equal(registered.length, 7);
  for (const command of registered) {
    assert.match(command.title, /^Guardian:/);
    assert.match(command.slash.name, /^guardian-/);
    assert.equal(typeof command.onSelect, "function");
  }
  recordGuardianEvent({ kind: "preflight-blocked", tool: "bash", rules: ["destructive-command"] }, dir);
  const status = registered.find((c) => c.value.endsWith(".status"));
  await status.onSelect();
  assert.equal(dialogState.type, "alert");
  assert.match(dialogState.message, /Blocked: 1/);
  const reset = registered.find((c) => c.value.endsWith(".reset"));
  await reset.onSelect();
  assert.equal(dialogState.type, "confirm");
  dialogState.onCancel();
  assert.equal(dialogCleared, 1);
  assert.equal(readGuardianStatus(dir).blocked, 1);
  await reset.onSelect();
  dialogState.onConfirm();
  assert.equal(readGuardianStatus(dir).blocked, 0);
  assert.equal(dialogState.type, "alert");
  assert.match(dialogState.message, /Counters reset/);
  assert.equal(typeof GuardianTui.tui, "function");
});

test("V2 registers a pure keymap layer with Ctrl+P and slash and prompts for reset", async (t) => {
  const dir = isolated(t);
  let makeLayer;
  const opened = [];
  let approved = false;
  let confirms = 0;
  const ctx = {
    keymap: { layer(factory) { makeLayer = factory; } },
    ui: { dialog: {
      alert: async (report) => { opened.push(report); },
      confirm: async () => { confirms++; return approved; },
    } },
  };
  registerGuardianV2Commands(ctx, () => dir);
  assert.equal(typeof makeLayer, "function");
  const commands = makeLayer().commands;
  assert.equal(commands.length, 8);
  assert.equal(commands.filter((c) => c.palette === true).length, 7);
  assert.equal(commands.filter((c) => c.group === "Guardian").length, 8);
  assert.equal(commands.filter((c) => c.slash?.name.startsWith("guardian-")).length, 7);
  const help = commands.find((c) => c.slash.name === "guardian");
  assert.equal(help.slash.arguments, true);
  const status = commands.find((c) => c.id === "opencode-guardian.status");
  recordGuardianEvent({ kind: "preflight-blocked", tool: "bash", rules: ["destructive-command"] }, dir);
  await status.run();
  assert.match(opened.at(-1).message, /Blocked: 1/);
  await help.run("/guardian activity");
  assert.match(opened.at(-1).message, /preflight-blocked/);
  await help.run("/guardian unsupported");
  assert.match(opened.at(-1).message, /Use \/guardian status/);
  const reset = commands.find((c) => c.id === "opencode-guardian.reset");
  await reset.run();
  assert.equal(confirms, 1);
  assert.equal(readGuardianStatus(dir).blocked, 1);
  approved = true;
  await help.run("reset");
  assert.equal(confirms, 2);
  assert.equal(readGuardianStatus(dir).blocked, 0);
  assert.match(opened.at(-1).message, /Counters reset/);
});

test("effective rule severities retain the built-in fallback with partial project config", async (t) => {
  const dir = isolated(t);
  fs.writeFileSync(path.join(dir, "opencode-guardian.json"),
    JSON.stringify({ enabled: true, preflight: { enabled: false } }));
  const result = await guardianCommandReport("rules", dir, "0.6.5");
  assert.match(result.message, /safety\/destructive-operations: warn/);
  assert.match(result.message, /security\/no-secrets: error/);
});

test("malformed log data never becomes a status label or a displayed event", (t) => {
  const dir = isolated(t);
  recordGuardianEvent({ kind: "runtime-started", preflight: "active" }, dir);
  const file = guardianEventPath(dir);
  fs.appendFileSync(file, JSON.stringify({
    kind: "TOP_SECRET_KIND", at: new Date().toISOString(), message: "TOP_SECRET_DATA",
  }) + "\n");
  fs.appendFileSync(file, JSON.stringify({
    kind: "preflight-blocked", at: "\u001b[31mTOP_SECRET_TIME",
    tool: "bash", rules: ["destructive-command"],
  }) + "\n");
  assert.equal(readGuardianStatus(dir).lastKind, "runtime-started");
  assert.equal(readGuardianStatus(dir).blocked, 0);
  assert.equal(readGuardianActivity(dir).length, 1);
  assert.doesNotMatch(JSON.stringify(readGuardianActivity(dir)), /TOP_SECRET/);
});

test("failed reset does not claim success or delete any previous audit data", (t) => {
  const dir = isolated(t);
  const validStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
  recordGuardianEvent({ kind: "post-warning", rules: ["quality/no-shortcuts"] }, dir);
  const before = fs.readFileSync(guardianEventPath(dir), "utf8");
  const invalidStateDir = path.join(dir, "a-file-not-a-directory");
  fs.writeFileSync(invalidStateDir, "sentinel");
  const previousError = console.error;
  console.error = () => {};
  let message;
  try {
    process.env.OPENCODE_GUARDIAN_STATE_DIR = invalidStateDir;
    message = guardianResetReport(dir).message;
  } finally {
    process.env.OPENCODE_GUARDIAN_STATE_DIR = validStateDir;
    console.error = previousError;
  }
  assert.match(message, /Reset failed/);
  assert.equal(fs.readFileSync(guardianEventPath(dir), "utf8"), before);
  assert.equal(readGuardianStatus(dir).warnings, 1);
});

test("V2 command actions resolve the current project at invocation time", async (t) => {
  const root = isolated(t);
  delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
  const a = path.join(root, "project-a");
  const b = path.join(root, "project-b");
  fs.mkdirSync(a); fs.mkdirSync(b);
  recordGuardianEvent({ kind: "preflight-blocked", tool: "bash", rules: ["destructive-command"] }, a);
  recordGuardianEvent({ kind: "post-warning", rules: ["quality/no-shortcuts"] }, b);
  let current = a;
  let register;
  const shown = [];
  const ctx = {
    keymap: { layer(cb) { register = cb; } },
    ui: { dialog: {
      alert: async (report) => { shown.push(report); },
      confirm: async () => true,
    } },
  };
  registerGuardianV2Commands(ctx, () => current);
  const commands = register().commands;
  const status = commands.find((c) => c.id === "opencode-guardian.status");
  await status.run();
  assert.match(shown.at(-1).message, /Blocked: 1/);
  current = b;
  await status.run();
  assert.match(shown.at(-1).message, /Blocked: 0/);
  assert.match(shown.at(-1).message, /Warnings: 1/);
  const reset = commands.find((c) => c.id === "opencode-guardian.reset");
  await reset.run();
  assert.equal(readGuardianStatus(a).blocked, 1);
  assert.equal(readGuardianStatus(b).warnings, 0);
});

test("V1 command registration disposes with the verified TUI lifecycle", async (t) => {
  const dir = isolated(t);
  let registered = 0;
  let disposed = 0;
  const cleanup = [];
  await GuardianTui.tui({
    state: { path: { directory: dir } },
    slots: { register() { return "guardian-slot"; } },
    command: { register(factory) {
      registered = factory().length;
      return () => { disposed++; };
    } },
    lifecycle: { onDispose(fn) { cleanup.push(fn); return () => {}; } },
  });
  assert.equal(registered, 7);
  assert.equal(cleanup.length, 1);
  cleanup[0]();
  assert.equal(disposed, 1);
});

test("V2 setup owns global commands independent of sidebar rendering", (t) => {
  const dir = isolated(t);
  const steps = [];
  let factory;
  let released = 0;
  const cleanup = GuardianTui.setup({
    location: { directory: dir },
    keymap: { layer(create) { steps.push("keymap"); factory = create; } },
    ui: { slot(input) {
      steps.push("sidebar");
      assert.equal(input.append, "sidebar.content");
      return () => { released++; };
    } },
  });
  assert.deepEqual(steps, ["keymap", "sidebar"]);
  assert.equal(factory().mode, "global");
  assert.equal(factory().commands.filter((c) => c.palette === true).length, 7);
  assert.equal(typeof cleanup, "function");
  cleanup();
  assert.equal(released, 1);
});
