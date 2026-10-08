import test from "node:test";
import assert from "node:assert/strict";
import Guardian, {
  formatGuardianToast,
  sanitizeToastRuleId,
  dispatchGuardianToast,
  createGuardianToastNotifier,
  registerToastListener,
  clearToastListeners,
} from "../dist/index.js";
import TuiPlugin from "../dist/tui.js";

const v1Server = Guardian.server;
const v2Setup = Guardian.setup;

test("toast format: differentiates variants and titles for all three intervention types", () => {
  const preflight = formatGuardianToast({
    kind: "preflight-blocked",
    ruleId: "destructive-command",
    tool: "bash",
  });
  assert.equal(preflight.variant, "error");
  assert.equal(preflight.title, "Guardian — Blocked");
  assert.equal(preflight.duration, 5000);
  assert.match(preflight.message, /\[destructive-command\] Execution of "bash" was blocked for safety\./);

  const preflightNoTool = formatGuardianToast({
    kind: "preflight-blocked",
    ruleId: "destructive-command",
  });
  assert.equal(preflightNoTool.variant, "error");
  assert.equal(preflightNoTool.title, "Guardian — Blocked");
  assert.match(preflightNoTool.message, /\[destructive-command\] Command execution was blocked for safety\./);

  const remediation = formatGuardianToast({
    kind: "remediation",
    ruleIds: ["task/completion-gate"],
  });
  assert.equal(remediation.variant, "error");
  assert.equal(remediation.title, "Guardian — Remediation");
  assert.equal(remediation.duration, 5000);
  assert.match(remediation.message, /Blocked: task\/completion-gate\nAgent was asked to correct the issue\./);

  const warning = formatGuardianToast({
    kind: "warning",
    ruleIds: ["integrity/no-unverified-claims"],
  });
  assert.equal(warning.variant, "warning");
  assert.equal(warning.title, "Guardian — Warning");
  assert.equal(warning.duration, 4000);
  assert.match(warning.message, /Advisory finding: integrity\/no-unverified-claims\./);
});

test("toast format: sanitizes rule IDs and prevents leak of code, secrets, or raw text", () => {
  // Test rule sanitization
  assert.equal(sanitizeToastRuleId("task/completion-gate"), "task/completion-gate");
  assert.equal(sanitizeToastRuleId("destructive-command"), "destructive-command");
  assert.equal(sanitizeToastRuleId("rm -rf /some/dangerous/path"), "guardian/policy");
  assert.equal(sanitizeToastRuleId("AKIAIOSFODNN7EXAMPLE"), "guardian/policy");
  assert.equal(sanitizeToastRuleId("<script>alert(1)</script>"), "guardian/policy");
  assert.equal(sanitizeToastRuleId("a".repeat(50)), "guardian/policy");
  assert.equal(sanitizeToastRuleId(null), "guardian/policy");
  assert.equal(sanitizeToastRuleId(undefined), "guardian/policy");

  // Format with raw/untrusted input
  const toast = formatGuardianToast({
    kind: "remediation",
    ruleIds: [
      "task/completion-gate",
      "eval(malicious_code)",
      "task/completion-gate", // duplicate
      "quality/no-shortcuts",
      "integrity/no-stubs",
      "extra-rule-that-should-overflow",
    ],
  });

  assert.equal(toast.title, "Guardian — Remediation");
  assert.equal(toast.variant, "error");
  // Deduplicated unique list has 4 items: task/completion-gate, guardian/policy, quality/no-shortcuts, integrity/no-stubs
  assert.match(toast.message, /Blocked: task\/completion-gate, guardian\/policy, quality\/no-shortcuts \(\+1 more\)/);
  assert.doesNotMatch(toast.message, /eval\(malicious_code\)/);
});

test("toast format: warning formatting deduplicates and limits rule count cleanly", () => {
  const toast = formatGuardianToast({
    kind: "warning",
    ruleIds: [
      "integrity/no-unverified-claims",
      "integrity/no-unverified-claims",
      "discipline/no-apology",
    ],
  });
  assert.equal(toast.title, "Guardian — Warning");
  assert.equal(toast.variant, "warning");
  assert.equal(toast.message, "Advisory finding: integrity/no-unverified-claims, discipline/no-apology.");
});

test("dispatchGuardianToast: dispatches to in-memory listeners and deduplicates rapid identical calls", () => {
  clearToastListeners();
  const received = [];
  const unregister = registerToastListener((toast) => {
    received.push(toast);
  });

  const payload = {
    title: "Guardian — Blocked",
    message: "[destructive-command] Execution was blocked.",
    variant: "error",
    duration: 5000,
  };

  dispatchGuardianToast(payload);
  assert.equal(received.length, 1);
  assert.equal(received[0].title, "Guardian — Blocked");

  // Duplicate call within dedupe window should be skipped
  dispatchGuardianToast(payload);
  assert.equal(received.length, 1);

  // Unregister listener
  unregister();
  clearToastListeners();
  dispatchGuardianToast({
    title: "Guardian — Warning",
    message: "Different message",
    variant: "warning",
    duration: 4000,
  });
  assert.equal(received.length, 1);
});

test("dispatchGuardianToast: calls V1 client.tui.showToast with correct contract and query", () => {
  clearToastListeners();
  let v1ToastCall = null;
  const mockClient = {
    tui: {
      showToast: async (opts) => {
        v1ToastCall = opts;
      },
    },
  };

  const payload = {
    title: "Guardian — Remediation",
    message: "Blocked: task/completion-gate — Agent requested to fix.",
    variant: "error",
    duration: 5000,
  };

  dispatchGuardianToast(payload, { client: mockClient, directory: "/workspace/my-project" });
  assert.notEqual(v1ToastCall, null);
  assert.equal(v1ToastCall.body.title, "Guardian — Remediation");
  assert.equal(v1ToastCall.body.message, payload.message);
  assert.equal(v1ToastCall.body.variant, "error");
  assert.equal(v1ToastCall.body.duration, 5000);
  assert.equal(v1ToastCall.query.directory, "/workspace/my-project");
});

test("dispatchGuardianToast: calls V2 context.ui.toast.show and fails soft if it throws", () => {
  clearToastListeners();
  let v2UiToast = null;
  const mockContext = {
    ui: {
      toast: {
        show: (opts) => {
          v2UiToast = opts;
        },
      },
    },
  };

  const payload = {
    title: "Guardian — Warning",
    message: "Advisory finding: integrity/no-unverified-claims.",
    variant: "warning",
    duration: 4000,
  };

  dispatchGuardianToast(payload, { context: mockContext });
  assert.notEqual(v2UiToast, null);
  assert.equal(v2UiToast.title, "Guardian — Warning");
  assert.equal(v2UiToast.variant, "warning");

  // Verify error in UI toast handler fails soft
  assert.doesNotThrow(() => {
    dispatchGuardianToast(
      { title: "Test", message: "Boom", variant: "error", duration: 1000 },
      {
        context: {
          ui: {
            toast: {
              show: () => {
                throw new Error("TUI destroyed");
              },
            },
          },
        },
      }
    );
  });
});

test("createGuardianToastNotifier: respects notifications.enabled: false config", () => {
  clearToastListeners();
  let toastCalled = false;
  const mockClient = {
    tui: {
      showToast: async () => {
        toastCalled = true;
      },
    },
  };

  const notifier = createGuardianToastNotifier({
    client: mockClient,
    enabled: false,
  });

  notifier.notify({
    kind: "preflight-blocked",
    ruleId: "destructive-command",
  });

  assert.equal(toastCalled, false);
});

test("V1 server integration: strict preflight block triggers error toast", async (t) => {
  clearToastListeners();
  const fs = await import("node:fs");
  const os = await import("node:os");
  const path = await import("node:path");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-toast-test-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
    enabled: true,
    preflight: { enabled: true },
  }));

  let toastData = null;
  const mockClient = {
    session: {},
    tui: {
      showToast: async (opts) => {
        toastData = opts;
      },
    },
  };

  const hooks = await v1Server({ client: mockClient, directory: dir });

  // Attempt a destructive command that preflight blocks
  await assert.rejects(async () => {
    await hooks["tool.execute.before"](
      { tool: "bash", sessionID: "sess-1", callID: "c1" },
      { args: { command: "rm -rf /ultra-private-file" } }
    );
  }, (err) => err.reason === "destructive-command");

  assert.notEqual(toastData, null);
  assert.equal(toastData.body.variant, "error");
  assert.equal(toastData.body.title, "Guardian — Blocked");
  assert.match(toastData.body.message, /blocked for safety/i);
});

test("V2 TUI setup: registers listener with context.ui.toast.show and disposes cleanly", () => {
  clearToastListeners();
  const toasts = [];
  const mockContext = {
    location: { directory: process.cwd() },
    ui: {
      slot: () => () => {},
      toast: {
        show: (toast) => {
          toasts.push(toast);
        },
      },
    },
    theme: {
      text: { base: "#fff", action: { primary: { base: "#000" } }, muted: "#888" },
      status: {},
    },
  };

  const cleanup = TuiPlugin.setup(mockContext);
  assert.equal(typeof cleanup, "function");

  // Dispatch a toast via notifier
  const notifier = createGuardianToastNotifier({
    directory: process.cwd(),
  });
  notifier.notify({
    kind: "warning",
    ruleIds: ["integrity/no-unverified-claims"],
  });

  assert.equal(toasts.length, 1);
  assert.equal(toasts[0].variant, "warning");
  assert.equal(toasts[0].title, "Guardian — Warning");

  // Dispose setup
  cleanup();

  // Next toast should not be received by the disposed context
  notifier.notify({
    kind: "preflight-blocked",
    ruleId: "destructive-command",
  });
  assert.equal(toasts.length, 1);
});

test("V1 server integration: idle turn remediation sends error toast to user", async (t) => {
  clearToastListeners();
  const fs = await import("node:fs");
  const os = await import("node:os");
  const path = await import("node:path");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-toast-v1-idle-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
    enabled: true,
    rules: { "integrity/no-evasion": "error" },
  }));

  const toasts = [];
  const promptsSent = [];
  const mockClient = {
    session: {
      get: async () => ({ data: { parentID: undefined } }),
      messages: async () => ({
        data: [
          { info: { id: "p1", role: "user" }, parts: [{ type: "text", text: "Implement fully and run tests." }] },
          {
            info: { id: "a1", role: "assistant", time: { completed: 123456 } },
            parts: [{ type: "text", text: "The test failure is unrelated to this change." }],
          },
        ],
      }),
      promptAsync: async (req) => {
        promptsSent.push(req);
        return { data: {} };
      },
    },
    tui: {
      showToast: async (opts) => {
        toasts.push(opts);
      },
    },
  };

  const hooks = await v1Server({ client: mockClient, directory: dir });

  // Simulate prompt contract registration
  await hooks["chat.message"](
    { sessionID: "s1", messageID: "p1" },
    { parts: [{ type: "text", text: "Please write a function with tests" }] }
  );

  // Trigger session.idle event
  await hooks.event({
    event: {
      type: "session.idle",
      properties: { sessionID: "s1" },
    },
  });

  // Verify remediation was sent to agent
  assert.ok(promptsSent.length >= 1);
  // Verify visible toast was sent to user with variant "error"
  assert.ok(toasts.length >= 1);
  const toast = toasts[0];
  assert.equal(toast.body.variant, "error");
  assert.equal(toast.body.title, "Guardian — Remediation");
  assert.match(toast.body.message, /Blocked:/);
  assert.match(toast.body.message, /Agent was asked to correct the issue/);
});

test("V1 server integration: idle turn advisory warning sends yellow/warning toast to user", async (t) => {
  clearToastListeners();
  const fs = await import("node:fs");
  const os = await import("node:os");
  const path = await import("node:path");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-toast-v1-warn-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
    enabled: true,
    rules: {
      "integrity/no-unverified-claims": "warn",
    },
  }));

  const toasts = [];
  const mockClient = {
    session: {
      get: async () => ({ data: { parentID: undefined } }),
      messages: async () => ({
        data: [
          { info: { id: "p1", role: "user" }, parts: [{ type: "text", text: "Just say hello" }] },
          { info: { id: "a1", role: "assistant" }, parts: [{ type: "text", text: "All tests pass with 100% coverage and zero bugs!" }] },
        ],
      }),
      promptAsync: async () => ({ data: {} }),
    },
    tui: {
      showToast: async (opts) => {
        toasts.push(opts);
      },
    },
  };

  const hooks = await v1Server({ client: mockClient, directory: dir });

  await hooks.event({
    event: {
      type: "session.idle",
      properties: { sessionID: "s1" },
    },
  });

  // Warning findings should fire warning toast
  const warnToast = toasts.find((t) => t.body.variant === "warning");
  assert.ok(warnToast, "Expected warning toast to be dispatched");
  assert.equal(warnToast.body.title, "Guardian — Warning");
  assert.match(warnToast.body.message, /Advisory finding: integrity\/no-unverified-claims/);
});

test("V2 server integration: strict preflight block triggers error toast via in-memory bridge", async (t) => {
  clearToastListeners();
  const fs = await import("node:fs");
  const os = await import("node:os");
  const path = await import("node:path");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-toast-v2-preflight-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
    enabled: true,
    preflight: { enabled: true },
  }));

  const toasts = [];
  registerToastListener((toast) => {
    toasts.push(toast);
  });

  let toolHookHandler = null;
  const mockContext = {
    location: { directory: dir },
    event: {
      subscribe: () => ({
        [Symbol.asyncIterator]() {
          return {
            async next() {
              return { done: true, value: undefined };
            },
          };
        },
      }),
    },
    session: {
      context: async () => [],
      synthetic: async () => {},
      hook: async () => ({ dispose: () => {} }),
    },
    tool: {
      hook: async (name, handler) => {
        if (name === "execute.before") {
          toolHookHandler = handler;
        }
        return { dispose: () => {} };
      },
    },
  };

  await v2Setup(mockContext);
  assert.notEqual(toolHookHandler, null);

  // Trigger preflight block
  assert.throws(() => {
    toolHookHandler({
      tool: "bash",
      input: { command: "rm -rf /critical-data" },
      sessionID: "sess-v2",
    });
  }, (err) => err.reason === "destructive-command");

  assert.equal(toasts.length, 1);
  assert.equal(toasts[0].variant, "error");
  assert.equal(toasts[0].title, "Guardian — Blocked");
  assert.match(toasts[0].message, /\[destructive-command\] Execution of "bash" was blocked for safety\./);
});



test("toast listeners are isolated by project directory", () => {
  clearToastListeners();
  const projectA = [];
  const projectB = [];
  const offA = registerToastListener(
    (toast) => projectA.push(toast),
    { directory: "/workspace/project-a" }
  );
  const offB = registerToastListener(
    (toast) => projectB.push(toast),
    { directory: "/workspace/project-b" }
  );

  dispatchGuardianToast(
    {
      title: "Guardian — Warning",
      message: "Advisory finding: integrity/no-unverified-claims.",
      variant: "warning",
      duration: 4000,
    },
    { directory: "/workspace/project-a" }
  );

  assert.equal(projectA.length, 1);
  assert.equal(projectB.length, 0);
  offA();
  offB();
  clearToastListeners();
});

test("toast dedupe is session-scoped so identical findings in two sessions are both visible", () => {
  clearToastListeners();
  const received = [];
  const off = registerToastListener(
    (toast, scope) => received.push({ toast, scope }),
    { directory: "/workspace/project" }
  );
  const payload = {
    title: "Guardian — Remediation",
    message: "Blocked: task/completion-gate\nAgent was asked to correct the issue.",
    variant: "error",
    duration: 5000,
  };

  dispatchGuardianToast(payload, {
    directory: "/workspace/project",
    sessionID: "session-a",
  });
  dispatchGuardianToast(payload, {
    directory: "/workspace/project",
    sessionID: "session-b",
  });

  assert.equal(received.length, 2);
  assert.equal(received[0].scope.sessionID, "session-a");
  assert.equal(received[1].scope.sessionID, "session-b");
  off();
  clearToastListeners();
});
