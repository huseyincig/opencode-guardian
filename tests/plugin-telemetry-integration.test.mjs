import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian from "../dist/index.js";
import { guardianEventPath, clearGuardianTelemetryConfig } from "../dist/telemetry.js";

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

test("V1 server with telemetry.level='violations' suppresses preflight-allowed but writes preflight-blocked", async (t) => {
  const dir = setupProject(t, {
    enabled: true,
    preflight: { enabled: true },
    telemetry: { level: "violations" },
    updateNotice: { enabled: false },
    secrets: { enabled: false },
  });

  const host = {
    session: {
      async get() { return { data: { id: "s1" } }; },
      async messages() { return { data: [] }; },
      async promptAsync() { return { data: {} }; },
    },
  };

  const hooks = await Guardian.server({ directory: dir, client: host });
  t.after(() => hooks.dispose());

  // Allowed command -> inspectPreflight -> preflight-allowed
  await hooks["tool.execute.before"]({ sessionID: "s1", callID: "c1", tool: "bash" }, { args: { command: "ls -la" } });

  const eventPath = guardianEventPath(dir);
  // File might exist if runtime-started was written, but must NOT have preflight-allowed
  if (fs.existsSync(eventPath)) {
    const content = fs.readFileSync(eventPath, "utf8");
    assert.doesNotMatch(content, /preflight-allowed/);
  }

  // Blocked command -> inspectPreflight -> preflight-blocked
  await assert.rejects(
    () => hooks["tool.execute.before"]({ sessionID: "s1", callID: "c2", tool: "bash" }, { args: { command: "rm -rf /" } }),
    /GuardianPreflightError/
  );

  assert.equal(fs.existsSync(eventPath), true);
  const content = fs.readFileSync(eventPath, "utf8");
  assert.match(content, /preflight-blocked/);
  assert.doesNotMatch(content, /preflight-allowed/);
});

test("V1 server with telemetry.level='off' writes no events at all", async (t) => {
  const dir = setupProject(t, {
    enabled: true,
    preflight: { enabled: true },
    telemetry: { level: "off" },
    updateNotice: { enabled: false },
    secrets: { enabled: false },
  });

  const host = {
    session: {
      async get() { return { data: { id: "s1" } }; },
      async messages() { return { data: [] }; },
      async promptAsync() { return { data: {} }; },
    },
  };

  const hooks = await Guardian.server({ directory: dir, client: host });
  t.after(() => hooks.dispose());

  await hooks["tool.execute.before"]({ sessionID: "s1", callID: "c1", tool: "bash" }, { args: { command: "echo ok" } });
  await assert.rejects(
    () => hooks["tool.execute.before"]({ sessionID: "s1", callID: "c2", tool: "bash" }, { args: { command: "rm -rf /" } }),
    /GuardianPreflightError/
  );

  const eventPath = guardianEventPath(dir);
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

  const eventPath = guardianEventPath(dir);
  if (fs.existsSync(eventPath)) {
    const content = fs.readFileSync(eventPath, "utf8");
    assert.doesNotMatch(content, /preflight-allowed/);
    assert.doesNotMatch(content, /post-inspected/);
  }
});
