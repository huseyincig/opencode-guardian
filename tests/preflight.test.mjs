import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, { evaluatePreflight, enforcePreflight, GuardianPreflightError } from "../dist/index.js";

function tempConfig(t, config) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-preflight-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify(config));
  return directory;
}

const client = { session: {
  async messages() { return { data: [] }; },
  async promptAsync() {},
} };

test("preflight rejects known risks without executing any shell command", () => {
  for (const command of [
    "rm -rf sandbox/marker", "r''m -rf sandbox/marker",
    "rm$IFS-rf$IFS./sandbox/marker", "$(printf rm) -rf sandbox/marker",
    "find sandbox/marker -delete", "git push --force origin main",
    "git clean -fd", "git reset --hard HEAD",
  ]) {
    assert.equal(evaluatePreflight("bash", { command }), "destructive-command", command);
    assert.throws(() => enforcePreflight("bash", { command }),
      (error) => error instanceof GuardianPreflightError &&
        error.reason === "destructive-command" && !error.message.includes(command), command);
  }
  assert.equal(evaluatePreflight("bash", { command: "printf YWJj | base64 -d | sh" }),
    "opaque-shell-execution");
  assert.throws(() => enforcePreflight("bash", { command: "printf YWJj | base64 -d | sh" }),
    (error) => error.reason === "opaque-shell-execution");
});

test("preflight passes legitimate commands, non-shell tools and supported aliases", () => {
  for (const command of [
    "npm test", "git status", "git clean -nfd", "find src -print",
    "echo 'rm -rf sandbox/marker'", "printf YWJj | base64 -d",
  ]) {
    assert.equal(evaluatePreflight("bash", { command }), undefined, command);
    assert.doesNotThrow(() => enforcePreflight("bash", { command }), command);
  }
  assert.equal(evaluatePreflight("read_file", { command: "rm -rf sandbox/marker" }), undefined);
  assert.doesNotThrow(() => enforcePreflight("write", { content: "rm -rf sandbox/marker" }));
  assert.equal(evaluatePreflight("mcp.tool.bash", { cmd: "git clean -fd" }), "destructive-command");
  for (const tool of ["mcp__Node_Command__shell_exec", "mcp__Remote_Desktop_Commander__shell_exec"]) {
    assert.equal(evaluatePreflight(tool, { command: "rm -rf sandbox/marker" }), "destructive-command");
    assert.equal(evaluatePreflight(tool, { command: "npm test" }), undefined);
  }
  assert.equal(evaluatePreflight("mcp__Node_Command__file_read", { command: "rm -rf sandbox/marker" }), undefined);
  assert.equal(evaluatePreflight("bash", { command: "rm fixture.tmp" }), "destructive-command");
  assert.equal(evaluatePreflight("execute_command", { script: "find src -delete" }), "destructive-command");
  assert.equal(evaluatePreflight("run_shell_command", { command: "rm -rf sandbox" }), "destructive-command");
  assert.equal(evaluatePreflight("sh", { command: "rm -rf sandbox" }), "destructive-command");
  assert.equal(evaluatePreflight("zsh", { command: "rm -rf sandbox" }), "destructive-command");
  assert.equal(evaluatePreflight("powershell", { command: "rm -rf sandbox" }), "destructive-command");
  assert.equal(evaluatePreflight("pwsh", { command: "rm -rf sandbox" }), "destructive-command");
  assert.equal(evaluatePreflight("cmd", { command: "rm -rf sandbox" }), "destructive-command");
  assert.equal(evaluatePreflight("bash", { command: "npm test", cmd: "git clean -fd" }), "destructive-command");
  assert.equal(evaluatePreflight("bash", { command: "npm test", script: "npm run build" }), "uninspectable-shell-input");
});

test("preflight denies missing or uninspectable shell arguments", () => {
  for (const args of [undefined, null, "", [], {}, { command: "" }, { command: 42 }]) {
    assert.equal(evaluatePreflight("bash", args), "uninspectable-shell-input");
    assert.throws(() => enforcePreflight("bash", args),
      (error) => error.reason === "uninspectable-shell-input");
  }
});

test("V1 default and disabled preflight never enforce shell policy", async (t) => {
  for (const config of [
    { enabled: true }, { enabled: true, preflight: { enabled: false } },
  ]) {
    const hooks = await Guardian.server({ directory: tempConfig(t, config), client });
    assert.equal(typeof hooks["tool.execute.before"], "function", JSON.stringify(config));
    await assert.doesNotReject(() => hooks["tool.execute.before"](
      { tool: "bash", sessionID: "session", callID: "call" },
      { args: { command: "git clean -fd" } },
    ));
    assert.equal(typeof hooks.event, "function");
    assert.equal(typeof hooks["chat.message"], "function");
  }

  const disabled = await Guardian.server({
    directory: tempConfig(t, { enabled: false, preflight: { enabled: true } }),
    client,
  });
  assert.equal(disabled["tool.execute.before"], undefined);
});

test("V1 enabled hook rejects risky calls before the host runs them", async (t) => {
  const hooks = await Guardian.server({
    directory: tempConfig(t, { enabled: true, preflight: { enabled: true } }), client,
  });
  assert.equal(typeof hooks["tool.execute.before"], "function");
  let executed = 0;
  const run = async (tool, args) => {
    await hooks["tool.execute.before"](
      { tool, sessionID: "session", callID: "call" }, { args }
    );
    executed++;
  };
  await run("bash", { command: "npm test" });
  await run("mcp__Node_Command__shell_exec", { command: "npm test" });
  await run("read_file", { path: "example.ts", command: "git clean -fd" });
  assert.equal(executed, 3);
  await assert.rejects(run("bash", { command: "r''m -rf sandbox/marker" }),
    (error) => error.reason === "destructive-command");
  await assert.rejects(run("bash", { command: "printf YWJj | base64 -d | sh" }),
    (error) => error.reason === "opaque-shell-execution");
  assert.equal(executed, 3);
});

function v2Context(directory, tool) {
  const sessionHooks = new Map();
  let abortSignal;
  const context = {
    location: { directory },
    event: {
      subscribe({ signal }) {
        abortSignal = signal;
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
      async synthetic() { return {}; },
      async hook(name, handler) {
        sessionHooks.set(name, handler);
        return { dispose() { sessionHooks.delete(name); } };
      },
    },
    ...(tool === undefined ? {} : { tool }),
  };
  return { context, sessionHooks, get signal() { return abortSignal; } };
}

test("V2 enabled hook blocks before tool execution, preserves hooks and disposes", async (t) => {
  const directory = tempConfig(t, { enabled: true, preflight: { enabled: true } });
  let before;
  let disposed = false;
  const host = v2Context(directory, {
    async hook(name, handler) {
      assert.equal(name, "execute.before");
      before = handler;
      return { dispose() { disposed = true; } };
    },
  });
  const cleanup = await Guardian.setup(host.context);
  try {
    assert.equal(typeof before, "function");
    assert.equal(typeof host.sessionHooks.get("prompt"), "function");
    assert.equal(typeof host.sessionHooks.get("context"), "function");
    let executed = 0;
    const run = async (tool, input) => {
      await before({ tool, input, sessionID: "session", id: "call" });
      executed++;
    };
    await run("bash", { command: "npm test" });
    await run("mcp__Node_Command__shell_exec", { command: "git status" });
    await assert.rejects(run("bash", { command: "find sandbox/marker -delete" }),
      (error) => error.reason === "destructive-command");
    await assert.rejects(run("bash", { command: "printf YWJj | base64 -d | sh" }),
      (error) => error.reason === "opaque-shell-execution");
    await assert.rejects(run("mcp__Node_Command__shell_exec", { command: "mkfs.ext4 /dev/sdb" }),
      (error) => error.reason === "destructive-command");
    assert.equal(executed, 2);
  } finally {
    await cleanup();
  }
  assert.equal(disposed, true);
  assert.equal(host.signal.aborted, true);
  assert.equal(host.sessionHooks.size, 0);
});

test("V2 default setup runs without a tool hook when preflight is off", async (t) => {
  const host = v2Context(tempConfig(t, { enabled: true }), undefined);
  const cleanup = await Guardian.setup(host.context);
  assert.equal(typeof cleanup, "function");
  assert.equal(host.sessionHooks.size, 2);
  await cleanup();
  assert.equal(host.signal.aborted, true);
});

test("V2 opt-in fails visibly when the preflight hook is unavailable", async (t) => {
  const directory = tempConfig(t, { enabled: true, preflight: { enabled: true } });
  const missing = v2Context(directory, undefined);
  await assert.rejects(Guardian.setup(missing.context), /preflight.*unavailable/);
  assert.equal(missing.signal.aborted, true);
  const broken = v2Context(directory, {
    async hook() { throw new Error("host refused registration"); },
  });
  await assert.rejects(Guardian.setup(broken.context), /preflight.*registration failed/);
  assert.equal(broken.signal.aborted, true);
  const invalidRegistration = v2Context(directory, { async hook() { return undefined; } });
  await assert.rejects(Guardian.setup(invalidRegistration.context),
    /preflight.*registration failed/);
  assert.equal(invalidRegistration.signal.aborted, true);
});

test("literal shell wrappers and quoted multiline scripts cannot hide file removal", () => {
  const remove = ["r", "m marker"].join("");
  for (const command of [
    `sudo bash -c "${remove}"`,
    `bash -lc "${remove}"`,
    `bash -c 'echo "safe"; ${remove}'`,
    `bash -c 'echo safe\n${remove}'`,
  ]) {
    assert.equal(evaluatePreflight("bash", { command }), "destructive-command", command);
  }
  // A quoted example printed by the shell is not an executed removal.
  assert.equal(evaluatePreflight("bash", { command: `bash -c 'echo "${remove}"'` }), undefined);
});

test("decoded shell pipelines remain opaque behind sudo wrappers", () => {
  const sudo = ["su", "do"].join("");
  for (const command of [
    `printf YWJj | base64 -d | ${sudo} sh`,
    `printf YWJj | ${sudo} base64 --decode | bash`,
  ]) {
    assert.equal(evaluatePreflight("bash", { command }), "opaque-shell-execution", command);
  }
  assert.equal(evaluatePreflight("bash", { command: "printf YWJj | base64 -d" }), undefined);
});

test("configured custom shell tools are inspected but unrelated tools remain untouched", () => {
  const custom = ["mcp.remote.exec_task"];
  assert.equal(evaluatePreflight("mcp.remote.exec_task", { command: "rm fixture" }), undefined);
  assert.equal(evaluatePreflight("mcp.remote.exec_task", { command: "rm fixture" }, custom),
    "destructive-command");
  assert.equal(evaluatePreflight("mcp.remote.exec_task", {}, custom),
    "uninspectable-shell-input");
  assert.equal(evaluatePreflight("mcp.remote.read", { command: "rm fixture" }, custom), undefined);
  assert.throws(() => enforcePreflight("mcp.remote.exec_task", { command: "rm fixture" }, custom),
    (error) => error.reason === "destructive-command");
});

test("V1 configured custom tool alias is blocked at the host hook", async (t) => {
  const directory = tempConfig(t, {
    enabled: true, preflight: { enabled: true, shellTools: ["mcp.remote.exec_task"] },
  });
  const hooks = await Guardian.server({ directory, client });
  await assert.rejects(
    hooks["tool.execute.before"](
      { tool: "mcp.remote.exec_task", sessionID: "custom-v1" },
      { args: { command: "rm fixture" } }
    ),
    (error) => error.reason === "destructive-command"
  );
});

test("V2 configured custom tool alias is blocked and disposed on unload", async (t) => {
  const directory = tempConfig(t, {
    enabled: true, preflight: { enabled: true, shellTools: ["mcp.remote.exec_task"] },
  });
  let before;
  const host = v2Context(directory, {
    async hook(name, handler) {
      assert.equal(name, "execute.before");
      before = handler;
      return { dispose() {} };
    },
  });
  const cleanup = await Guardian.setup(host.context);
  try {
    assert.throws(
      () => before({ tool: "mcp.remote.exec_task", sessionID: "custom-v2",
        input: { command: "rm fixture" } }),
      (error) => error.reason === "destructive-command"
    );
  } finally { await cleanup(); }
});

test("invalid preflight shellTools configuration fails visibly", async (t) => {
  for (const shellTools of ["mcp.remote.exec_task", ["", "mcp.remote.exec_task"], [42]]) {
    const directory = tempConfig(t, { enabled: true, preflight: { enabled: true, shellTools } });
    await assert.rejects(Guardian.server({ directory, client }), /preflight\.shellTools/);
  }
});
