import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, { GuardEngine, calculateProductFingerprint, evaluatePreflight, isShellExecutionTool, readGuardianStatus } from "../dist/index.js";

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-repair-"));
  const previous = process.env.OPENCODE_GUARDIAN_STATE_DIR;
  process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(root, "events");
  t.after(() => {
    if (previous === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    else process.env.OPENCODE_GUARDIAN_STATE_DIR = previous;
    fs.rmSync(root, { recursive: true, force: true });
  });
  return root;
}
async function until(check) {
  const end = Date.now() + 1000;
  while (!check()) {
    if (Date.now() > end) assert.fail("Host callback not received");
    await new Promise((r) => setTimeout(r, 5));
  }
}
test("strict preflight blocks elevated shell and dangerous process starts", () => {
  assert.equal(isShellExecutionTool("mcp__Node_Command__privileged_shell_exec"), true);
  assert.equal(evaluatePreflight("mcp__Node_Command__privileged_shell_exec", { command: "rm -rf fixtures" }), "destructive-command");
  assert.equal(evaluatePreflight("mcp__Node_Command__privileged_shell_exec", { command: "npm test" }), undefined);
  assert.equal(evaluatePreflight("mcp__Node_Command__process_start", { executable: "/bin/bash", args: ["-lc", "rm -rf fixtures"] }), "destructive-command");
  assert.equal(evaluatePreflight("mcp__Node_Command__process_start", { executable: "/bin/rm", args: ["fixtures"] }), "destructive-command");
  assert.equal(evaluatePreflight("mcp__Node_Command__process_start", { executable: "/usr/bin/node", args: ["--version"] }), undefined);
  assert.equal(evaluatePreflight("mcp__Node_Command__process_start", { executable: "/bin/bash", args: ["-c"] }), "uninspectable-shell-input");
  assert.equal(evaluatePreflight("mcp__Node_Command__process_start", { executable: "/usr/bin/node", args: ["-e", "process.exit(0)"] }), "uninspectable-shell-input");
  assert.equal(evaluatePreflight("mcp__Node_Command__process_start",
    { executable: "C:\\\\Windows\\\\System32\\\\cmd.exe", args: ["/c", "del fixtures"] }), "destructive-command");
  assert.equal(evaluatePreflight("mcp__Node_Command__process_start",
    { executable: "C:\\\\Windows\\\\System32\\\\powershell.exe", args: ["-Command", "Remove-Item fixtures"] }), "destructive-command");
  assert.equal(evaluatePreflight("mcp__Node_Command__process_start",
    { executable: "C:\\\\Windows\\\\System32\\\\cmd.exe", args: ["/c", "echo safe"] }), undefined);
  assert.equal(evaluatePreflight("mcp__Node_Command__process_start",
    { executable: "/bin/sh", args: [] }), "uninspectable-shell-input");
});
test("V1 native idle transfers real after-hook snapshots", async (t) => {
  const root = fixture(t);
  fs.writeFileSync(path.join(root, "src.js"), "export const value=1;");
  let snapshots;
  const original = GuardEngine.prototype.inspect;
  GuardEngine.prototype.inspect = async (_id, _dir, _msgs, data) => {
    snapshots = data; return { decision: "pass", results: [] };
  };
  t.after(() => { GuardEngine.prototype.inspect = original; });
  const hooks = await Guardian.server({
    directory: root,
    client: { session: { messages: async () => ({ data: [] }) } },
  });
  t.after(async () => { await hooks.dispose?.(); });
  await hooks["tool.execute.after"]({ sessionID: "v1", callID: "edit", tool: "write_to_file",
    args: { path: "src.js", content: "export const value=1;" } },
    { output: "ok", metadata: {} });
  await hooks["tool.execute.after"]({ sessionID: "v1", callID: "test", tool: "bash",
    args: { command: "npm test" } }, { output: "ok", metadata: { exitCode: 0 } });
  await hooks.event({ event: { type: "session.idle", properties: { sessionID: "v1" } } });
  assert.equal(snapshots?.has("test"), true);
});
test("V2 after-hook hashes the session root, not the plugin root", async (t) => {
  const root = fixture(t), plugin = path.join(root, "plugin"), session = path.join(root, "session");
  fs.mkdirSync(plugin); fs.mkdirSync(session);
  fs.writeFileSync(path.join(plugin, "src.js"), "old");
  fs.writeFileSync(path.join(session, "src.js"), "new");
  const hooks = new Map();
  let fire; const ready = new Promise((r) => { fire = r; });
  let observed;
  const original = GuardEngine.prototype.inspect;
  GuardEngine.prototype.inspect = async (_id, directory, _msgs, snapshots) => {
    observed = { directory, snapshots }; return { decision: "pass", results: [] };
  };
  t.after(() => { GuardEngine.prototype.inspect = original; });
  const host = {
    location: { directory: plugin },
    options: { secrets: { enabled: false } },
    event: { subscribe: ({ signal }) => (async function* () {
      await ready; yield { type: "session.idle", data: { sessionID: "v2" } };
      await new Promise((r) => {
        if (signal.aborted) r(); else signal.addEventListener("abort", r, { once: true });
      });
    })() },
    tool: { hook: async (name, handler) => {
      hooks.set(name, handler); return { dispose() { hooks.delete(name); } };
    } },
    session: { get: async () => ({ location: { directory: session } }),
      context: async () => [], synthetic: async () => {} },
  };
  const cleanup = await Guardian.setup(host);
  t.after(async () => { await cleanup?.(); });
  await hooks.get("execute.after")({ status: "completed", sessionID: "v2", id: "edit",
    tool: "write_to_file", input: { path: "src.js", content: "new" }, result: { output: "ok" } });
  await hooks.get("execute.after")({ status: "completed", sessionID: "v2", id: "test",
    tool: "bash", input: { command: "npm test" }, result: { output: "ok", metadata: { exitCode: 0 } } });
  fire(); await until(() => observed !== undefined);
  assert.equal(observed.directory, session);
  assert.equal(observed.snapshots.get("test")?.fingerprint, "sha256:" + calculateProductFingerprint(session, ["src.js"]));
  assert.notEqual(observed.snapshots.get("test")?.fingerprint, "sha256:" + calculateProductFingerprint(plugin, ["src.js"]));
});
test("V2 disposal prevents synthetic remediation from a pending context request", async (t) => {
  const root = fixture(t);
  let release; const pending = new Promise((r) => { release = r; });
  let enter; const entered = new Promise((r) => { enter = r; });
  let sent = 0;
  const host = {
    location: { directory: root },
    options: { secrets: { enabled: false } },
    event: { subscribe: ({ signal }) => (async function* () {
      yield { type: "session.idle", data: { sessionID: "v2" } };
      await new Promise((r) => {
        if (signal.aborted) r(); else signal.addEventListener("abort", r, { once: true });
      });
    })() },
    session: { context: async () => { enter(); return pending; },
      synthetic: async () => { sent++; } } };
  const cleanup = await Guardian.setup(host);
  await entered; await cleanup();
  release([{ type: "user", id: "u", text: "Implement checkout" }, { type: "assistant", id: "a", content:
    [{ type: "text", text: "This implementation is good enough for now, and the checkout failure is unrelated to this change." }] }]);
  await new Promise((r) => setTimeout(r, 25));
  assert.equal(sent, 0);
  assert.equal(readGuardianStatus().errors, 0);
});
test("TUI distinguishes remediation success, failure and uncertainty", () => {
  const source = fs.readFileSync(new URL("../src/tui.tsx", import.meta.url), "utf8");
  for (const kind of ["remediation-verified", "remediation-failed",
    "remediation-unverified", "verification-unavailable"]) {
    assert.match(source, new RegExp('case "' + kind + '":'));
  }
});
test("V1 strict hook blocks process_start and logs only its safe action name", async (t) => {
  const root = fixture(t);
  fs.writeFileSync(path.join(root, "opencode-guardian.json"),
    JSON.stringify({ enabled: true, preflight: { enabled: true } }));
  const hooks = await Guardian.server({
    directory: root,
    client: { session: { messages: async () => ({ data: [] }) } },
  });
  t.after(async () => { await hooks.dispose?.(); });
  await assert.rejects(
    hooks["tool.execute.before"](
      { tool: "mcp__Node_Command__process_start", sessionID: "v1", callID: "danger" },
      { args: { executable: "/bin/rm", args: ["fixtures"] } },
    ), (error) => error.reason === "destructive-command");
  const entries = fs.readFileSync(path.join(root, "events", "guardian-events.jsonl"), "utf8")
    .trim().split("\n").map(JSON.parse);
  assert.ok(entries.some((event) => event.kind === "preflight-blocked" &&
    event.tool === "process_start" && !JSON.stringify(event).includes("fixtures")));
});
