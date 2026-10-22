import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, { evaluatePreflight, collectTurnEvidence, evaluateTaskPolicy,
  sanitizeString, noGhostDepsRule, VerificationSnapshotStore } from "../dist/index.js";

function projects(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-source-fixes-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const create = (name, config) => {
    const directory = path.join(root, name);
    fs.mkdirSync(directory);
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
      updateNotice: { enabled: false }, ...config,
    }));
    return directory;
  };
  return { root, create };
}

async function host(t, directory, sessionDirectory, overrides = {}) {
  const tools = new Map(), sessions = new Map();
  const events = [];
  let wake;
  const cleanup = await Guardian.setup({
    location: { directory },
    tool: { async hook(name, handler) {
      tools.set(name, handler);
      return { dispose() { tools.delete(name); } };
    } },
    session: {
      async get() { return { location: { directory: sessionDirectory } }; },
      async context() { return []; },
      async synthetic() {},
      async hook(name, handler) {
        sessions.set(name, handler);
        return { dispose() { sessions.delete(name); } };
      },
      ...overrides,
    },
    event: { subscribe({ signal }) { return (async function* () {
      const onAbort = () => wake?.();
      signal.addEventListener("abort", onAbort, { once: true });
      try {
        while (!signal.aborted) {
          if (!events.length) await new Promise(resolve => { wake = resolve; });
          while (!signal.aborted && events.length) yield events.shift();
        }
      } finally { signal.removeEventListener("abort", onAbort); }
    })(); } },
  });
  t.after(cleanup);
  return { tools, sessions, cleanup, async emit(event) {
    events.push(event); wake?.();
    await new Promise(resolve => setImmediate(resolve));
  } };
}

test("native write preflight checks V1/V2 paths, secrets and truncation", async t => {
  const { create } = projects(t);
  const directory = create("strict", { preflight: { enabled: true }, secrets: { enabled: false } });
  const v1 = await Guardian.server({ directory, client: { session: {} } });
  t.after(() => v1.dispose());
  const v2 = await host(t, directory, directory);
  for (const field of ["filePath", "path"]) {
    for (const [content, reason] of [
      ["// ... existing code unchanged ...", "truncation-placeholder-in-file-write"],
      ["const token = 'sk-proj-" + "A".repeat(30) + "';", "hardcoded-secret-in-file-write"],
    ]) {
      const args = { [field]: "src/a.ts", content };
      assert.equal(evaluatePreflight("write", args), reason);
      await assert.rejects(v1["tool.execute.before"](
        { tool: "write", sessionID: "s", callID: "c" }, { args }), e => e.reason === reason);
      await assert.rejects(async () => v2.tools.get("execute.before")(
        { tool: "write", sessionID: "s", id: "c", input: args }), e => e.reason === reason);
    }
  }
  assert.equal(evaluatePreflight("write", { path: "a.ts", content: "export const value = 1;" }), undefined);
});

test("V2 first tool in an existing second-project session uses its own preflight", async t => {
  const { create } = projects(t);
  const base = create("base", { preflight: { enabled: false }, secrets: { enabled: false } });
  const other = create("other", { preflight: { enabled: true }, secrets: { enabled: false } });
  const h = await host(t, base, other);
  await h.emit({ type: "session.created", data: { sessionID: "s" } });
  await assert.rejects(async () => h.tools.get("execute.before")({
    sessionID: "s", id: "c", tool: "bash", input: { command: "rm -rf ./fixture" },
  }), e => e.reason === "destructive-command");
});

test("V2 teardown while resolving a tool directory prevents late policy work", async t => {
  const { create } = projects(t);
  const base = create("base", { secrets: { enabled: false }, preflight: { enabled: true } });
  let release;
  const h = await host(t, base, base, { get: () => new Promise(resolve => { release = resolve; }) });
  const pending = h.tools.get("execute.before")({ sessionID: "s", id: "c", tool: "bash", input: { command: "rm -rf fixture" } });
  assert.equal(typeof release, "function");
  await h.cleanup();
  release({ location: { directory: base } });
  await pending;
});

test("V2 incomplete session lookups and move events never cache a guessed project", async t => {
  const { create } = projects(t);
  const base = create("base", { secrets: { enabled: false }, preflight: { enabled: false } });
  const other = create("other", { secrets: { enabled: false }, preflight: { enabled: true } });
  for (const first of [{}, { location: { directory: " " } }, { location: { directory: base } }]) {
    let calls = 0;
    const h = await host(t, base, other, { async get() {
      return ++calls === 1 ? first : { location: { directory: other } };
    } });
    await h.tools.get("execute.before")({ sessionID: "s", id: "c1", tool: "bash", input: { command: "npm test" } });
    if (first.location?.directory === base) {
      await h.emit({ type: "session.moved", data: { sessionID: "s" } });
    }
    await assert.rejects(async () => h.tools.get("execute.before")({
      sessionID: "s", id: "c2", tool: "bash", input: { command: "rm -rf fixture" },
    }), e => e.reason === "destructive-command");
    assert.equal(calls, 2);
    await h.cleanup();
  }
});

test("V2 auxiliary registration failure rolls back even when initial secrets are off", async t => {
  const { create } = projects(t);
  const base = create("base", { secrets: { enabled: false } });
  for (const failure of ["compaction", "generate", "title"]) {
    const active = new Set();
    await assert.rejects(host(t, base, base, { async hook(name) {
      if (name === failure) throw new Error("fixture registration failure");
      active.add(name);
      return { dispose() { active.delete(name); } };
    } }), /session context security hook registration failed/);
    assert.deepEqual([...active], []);
  }
});

test("native empty-file writes remain inspectable while missing content is rejected", () => {
  assert.equal(evaluatePreflight("write", { path: "empty.ts", content: "" }), undefined);
  assert.equal(evaluatePreflight("write", { path: "empty.ts" }), "uninspectable-file-input");
});

test("V2 auxiliary requests respect each project and subsequent config changes", async t => {
  const { create } = projects(t);
  const base = create("base", { secrets: { enabled: false } });
  const other = create("other", { secrets: { enabled: true } });
  const h = await host(t, base, other);
  for (const kind of ["context", "compaction", "generate", "title"]) {
    assert.equal(typeof h.sessions.get(kind), "function", kind);
    const request = { sessionID: "s", messages: [{ type: "user", text: "TOKEN=audit_dummy_secret_123" }], system: [{ type: "text", text: "TOKEN=audit_dummy_secret_123" }] };
    await h.sessions.get(kind)(request);
    assert.ok(!JSON.stringify(request).includes("audit_dummy_secret_123"), kind);
  }
  fs.writeFileSync(path.join(other, "opencode-guardian.json"), JSON.stringify({ secrets: { enabled: false } }));
  await h.emit({ type: "config.updated", data: {} });
  const disabled = { sessionID: "s", messages: [{ type: "user", text: "TOKEN=audit_dummy_secret_123" }], system: [] };
  await h.sessions.get("title")(disabled);
  assert.ok(JSON.stringify(disabled).includes("audit_dummy_secret_123"));
  fs.writeFileSync(path.join(other, "opencode-guardian.json"), JSON.stringify({ secrets: { enabled: true } }));
  await h.emit({ type: "config.updated", data: {} });
  await h.sessions.get("title")(disabled);
  assert.ok(!JSON.stringify(disabled).includes("audit_dummy_secret_123"));
});

test("connection-string redaction handles empty usernames, missing paths and IPv6", () => {
  for (const url of [
    "redis://:audit_dummy_pass_123@localhost:6379",
    "redis://:audit_dummy_pass_123@localhost:6379/0",
    "mysql://user:audit_dummy_pass_123@localhost:3306",
    "postgresql://user:audit_dummy_pass_123@[::1]:5432/db?sslmode=require",
    "mongodb+srv://user:audit_dummy_pass_123@cluster.example/db",
  ]) {
    assert.equal(sanitizeString(`Connect to (${url}).`, { includeRuntimeEnv: false }).sanitized,
      `Connect to (${url.replace("audit_dummy_pass_123", "[REDACTED]")}).`);
  }
  assert.equal(sanitizeString("https://example.com/public", { includeRuntimeEnv: false }).sanitized, "https://example.com/public");
});

test("structured edits invalidate earlier tests and snapshot all edited files including deletions", t => {
  const { root } = projects(t);
  fs.writeFileSync(path.join(root, "a.ts"), "export const a = 1;");
  fs.writeFileSync(path.join(root, "b.ts"), "");
  const input = { edits: [
    { path: "a.ts", oldText: "a = 0", newText: "a = 1" },
    { path: "b.ts", oldText: "remove this", replacement: "" },
  ] };
  const part = (tool, input, callID) => ({ type: "tool", tool, callID, state: { status: "completed", input, metadata: { exit: 0 } } });
  const turn = [{ info: { id: "a", role: "assistant" }, parts: [
    part("bash", { command: "npm test" }, "test-before"), part("multiedit", input, "edit"),
  ] }];
  const evidence = collectTurnEvidence(turn);
  assert.deepEqual(evidence.fileMutations.map(r => r.filePath).sort(), ["a.ts", "b.ts"]);
  const policy = evaluateTaskPolicy({ iterativeReview: false, requiredVerifications: ["test"] }, evidence);
  assert.equal(policy.verifications[0].status, "unknown");
  const store = new VerificationSnapshotStore();
  store.observe("s", "edit", "multiedit", input, "updated", {}, root);
  store.observe("s", "test-after", "bash", { command: "npm test" }, "passed", { exit: 0 }, root);
  assert.deepEqual(store.snapshots("s").get("test-after").files.sort(), ["a.ts", "b.ts"]);
});

test("ghost dependency checks preserve each unified/native patch file and manifest", async t => {
  const { root } = projects(t);
  fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "fixture", dependencies: {} }));
  fs.mkdirSync(path.join(root, "child"));
  fs.writeFileSync(path.join(root, "child", "package.json"), JSON.stringify({ dependencies: { allowed: "1.0.0" } }));
  const unified = (name, text) => `--- a/${name}\n+++ b/${name}\n@@ -0,0 +1 @@\n+${text}\n`;
  const native = (name, text) => `*** Add File: ${name}\n+${text}\n`;
  for (const format of [unified, native]) {
    const doc = format("README.md", "# Example");
    const js = format("main.ts", 'import missing from "guardian-missing-package";');
    const child = format("child/main.ts", 'import allowed from "allowed";');
    for (const patch of [doc + js + child, child + js + doc]) {
      const result = await noGhostDepsRule.inspect({ sessionID: "s", directory: root,
        messages: [], ruleConfig: {}, currentTurn: [{ info: { id: "a", role: "assistant" }, parts: [
          { type: "tool", state: { input: { patchText: patch } } },
        ] }] });
      assert.equal(result.decision, "block");
      assert.deepEqual(result.findings.map(f => f.pattern), ["guardian-missing-package"]);
    }
  }
});
