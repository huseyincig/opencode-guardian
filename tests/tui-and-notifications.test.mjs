import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { GUARDIAN_COMMANDS, guardianCommandReport, guardianResetReport } from "../dist/commands.js";
import Guardian, { GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD, GUARDIAN_INTERVENTION_RPC_DEFINITION, GUARDIAN_INTERVENTION_RPC_METHOD, clearToastListeners, createGuardianToastNotifier, dispatchGuardianToast, formatGuardianToast, isTrustedGuardianMetadata, loadConfig, registerToastClearListener, registerToastListener, sanitizeToastRuleId } from "../dist/index.js";
import OpencodeGuardian from "../dist/index.js";
import { GUARDIAN_INTERVENTION_RPC_ID, GUARDIAN_INTERVENTION_RPC_METHOD as GUARDIAN_INTERVENTION_RPC_METHOD_4 } from "../dist/intervention-rpc.js";
import * as RpcPlugin from "../dist/intervention-rpc.js";
import { guardianEventPath, readGuardianActivity, readGuardianStatus, recordGuardianEvent, resetGuardianStatistics } from "../dist/telemetry.js";
import GuardianTui, { registerGuardianV2Commands as registerGuardianV2Commands_5 } from "../dist/tui-standalone.js";
import TuiPlugin, { registerGuardianV2Commands } from "../dist/tui.js";
import { announceGuardianUpdate, checkGuardianUpdate, newerStableVersion } from "../dist/version-notice.js";
import RootTui, { default as LocalPathTui } from "../tui.js";

describe("V2 TUI Slots, Sidebar & Packaging", () => {
  test("V2 TUI registers additive sidebar and main-conversation intervention slots", () => {
    const claims = [];
    let disposed = 0;
    const cleanup = TuiPlugin.setup({
      ui: {
        slot(input) {
          claims.push(input);
          return () => { disposed++; };
        },
      },
    });
    assert.equal(TuiPlugin.id, "opencode-guardian.tui");

    const sidebar = claims.find((claim) => claim.append === "sidebar.content");
    const conversation = claims.find((claim) => claim.append === "session.composer.top");

    assert.ok(sidebar, "Guardian sidebar slot must remain registered");
    assert.equal(sidebar.replace, undefined);
    assert.equal(typeof sidebar.render, "function");

    assert.ok(conversation, "Guardian intervention must render in the main conversation column");
    assert.equal(conversation.replace, undefined);
    assert.equal(typeof conversation.render, "function");

    assert.equal(typeof cleanup, "function");
    cleanup();
    assert.equal(disposed, 2);
  });

  test("V2 TUI exports pure V2 entrypoint and intervention RPC export exists", () => {
    assert.equal(typeof registerGuardianV2Commands, "function");
    assert.equal(TuiPlugin.tui, undefined);
    assert.equal(TuiPlugin.server, undefined);
    assert.equal(OpencodeGuardian.server, undefined);
    assert.notEqual(typeof RpcPlugin, "undefined");
    assert.equal(typeof TuiPlugin.setup, "function");
  });

  test("root tui.js resolves the same V2 sidebar plugin for local path loading", () => {
    assert.equal(RootTui, TuiPlugin);
    assert.equal(LocalPathTui, TuiPlugin);
    assert.equal(RootTui.id, "opencode-guardian.tui");
  });

  test("V2 TUI honors disabled Guardian configuration", async (t) => {
    const fs = await import("node:fs");
    const os = await import("node:os");
    const path = await import("node:path");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v2-tui-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), '{"enabled":false}');
    let called = false;
    const result = TuiPlugin.setup({
      location: { directory: dir },
      ui: { slot() { called = true; return () => {}; } },
    });
    assert.equal(called, false);
    assert.equal(result, undefined);
  });


  test("TUI build uses Solid Universal and shares the OpenCode host runtime", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const root = path.resolve(import.meta.dirname, "..");
    const runtime = fs.readFileSync(path.join(root, "dist/tui-runtime.js"), "utf8");
    const standalone = fs.readFileSync(path.join(root, "dist/tui-standalone.js"), "utf8");
    const loader = fs.readFileSync(path.join(root, "dist/tui.js"), "utf8");
    assert.match(runtime, /opentui:runtime-module:%40opentui%2Fsolid/);
    assert.match(runtime, /opentui:runtime-module:solid-js/);
    assert.doesNotMatch(runtime, /@opentui\/solid\/jsx-runtime|from ["']@opentui\/solid["']|from ["']solid-js["']/);
    assert.doesNotMatch(runtime, /from ["']@opencode\/plugin\/tui["']/);
    assert.doesNotMatch(runtime, /_jsx\(|_jsxs\(/);
    assert.match(standalone, /@opentui\/solid/);
    assert.match(loader, /tui-runtime\.js/);
    assert.match(loader, /tui-standalone\.js/);
    assert.equal(TuiPlugin.tui, undefined);
    assert.equal(typeof TuiPlugin.setup, "function");
  });


  test("Guardian sidebar is compact by default and contains expandable details", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const root = path.resolve(import.meta.dirname, "..");
    const source = fs.readFileSync(path.join(root, "src/tui.tsx"), "utf8");
    const runtime = fs.readFileSync(path.join(root, "dist/tui-runtime.js"), "utf8");
    assert.match(source, /createSignal\(false\)/);
    assert.match(source, /onMouseDown=\{\(\) => setOpen/);
    assert.match(source, /<Show when=\{!open\(\)\}>/);
    assert.match(source, /<Show when=\{open\(\)\}>/);
    assert.match(source, /guardianVersion/);
    assert.match(source, /status\(\)\.warnings/);
    assert.match(source, /label="Preflight"/);
    assert.match(source, /StatRow/);
    assert.match(source, /value=\{status\(\)\.blocked\}/);
    assert.match(source, /value=\{status\(\)\.remediations\}/);
    assert.doesNotMatch(source, /totalBlocked/, "remediations are not blocked commands");
    assert.match(source, /○ Idle/);
    assert.match(source, /disposed = true/);
    assert.match(runtime, /opentui:runtime-module:solid-js/);
    assert.match(runtime, /onMouseDown/);
    assert.match(runtime, /\(↑\)/);
    assert.doesNotMatch(runtime, /@opentui\/solid\/jsx-runtime/);
  });

  test("V2 SDK entrypoints and Node package contract", async () => {
    const { readFileSync } = await import("node:fs");
    const { readFile } = await import("node:fs/promises");
    const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
    assert.equal(pkg.engines.node, ">=22.0.0");
    assert.equal(pkg.peerDependencies["@opencode/plugin"], ">=2.3.0");
    assert.equal(pkg.peerDependencies["@opentui/core"], ">=0.8.4");
    assert.equal(pkg.peerDependencies["@opentui/solid"], ">=0.8.4");
    assert.equal(pkg.exports["."].import, "./dist/index.js");
    assert.equal(pkg.exports["./tui"].import, "./dist/tui.js");
    assert.equal(pkg.exports["./rpc"].import, "./dist/intervention-rpc.js");
    assert.equal(pkg.exports["./server"], undefined);
    const v2 = readFileSync(new URL(import.meta.resolve("@opencode/plugin/tui")), "utf8");
    assert.equal(typeof v2, "string");
    assert.equal(TuiPlugin.tui, undefined);
    assert.equal(typeof TuiPlugin.setup, "function");
  });


  test("V2 accent never relies on the possibly transparent action background", async () => {
    const { readFileSync } = await import("node:fs");
    const source = readFileSync(new URL("../src/tui.tsx", import.meta.url), "utf8");
    assert.match(source, /accent: context\.theme\?\.status\?\.success\?\.base \?\? context\.theme\?\.text\?\.base/);
    assert.doesNotMatch(source, /accent: context\.theme\?\.background\?\.action\?\.primary\?\.base/);
  });

  test("available update is the first sidebar row in both collapsed and expanded views", async () => {
    const { readFileSync } = await import("node:fs");
    const source = readFileSync(new URL("../src/tui.tsx", import.meta.url), "utf8");
    const runtime = readFileSync(new URL("../dist/tui-runtime.js", import.meta.url), "utf8");
    const standalone = readFileSync(new URL("../dist/tui-standalone.js", import.meta.url), "utf8");
    const header = source.indexOf("onMouseDown={() => setOpen");
    const update = source.indexOf('label="Update available"');
    const collapsed = source.indexOf("<Show when={!open()}>");
    const expanded = source.indexOf("<Show when={open()}>");
    const errors = source.indexOf('label="Errors"');
    assert.ok(header >= 0 && header < update && update < collapsed && collapsed < expanded && expanded < errors);
    assert.equal(source.match(/label="Update available"/g)?.length, 1);
    assert.match(source.slice(header, collapsed), /<Show when=\{hasUpdate\(\) && latestVersion\(\)\}>/);
    assert.match(source.slice(header, collapsed), /value=\{.*latestVersion\(\).*\}/);
    assert.match(runtime, /Update available/);
    assert.match(standalone, /Update available/);
  });
});

describe("TUI Runtime Probe", () => {
  const probe=spawnSync(process.execPath,['--experimental-vm-modules',fileURLToPath(new URL('./helpers/feedback-tui-probe.mjs',import.meta.url))],{encoding:'utf8',timeout:10000});
  assert.equal(probe.status,0,probe.stderr);
  const rows=probe.stdout.trim().split('\n').map(line=>JSON.parse(line));
  for(const id of [9,19,10,21])test(`F${id} TUI lifecycle/config regression`,()=>{
   assert.equal(rows.find(row=>row.id===id)?.status,'NOT_REPRODUCED',probe.stdout);
  });
});

describe("Toast Notifications & Scope Isolation", () => {
  const v2Setup = Guardian.setup;

  async function eventually(check, limit = 1500) {
    const until = Date.now() + limit;
    while (!check()) {
      if (Date.now() > until) throw new Error("Timed out waiting for condition");
      await new Promise((r) => setTimeout(r, 15));
    }
  }

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

  test("V2 server integration: idle turn remediation sends error toast to user", async (t) => {
    clearToastListeners();
    const fs = await import("node:fs");
    const os = await import("node:os");
    const path = await import("node:path");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-toast-v2-idle-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      rules: { "discipline/no-evasion": "error" },
    }));

    const toasts = [];
    registerToastListener((toast) => {
      toasts.push(toast);
    }, { directory: dir });

    const promptsSent = [];
    let promptHook = null;
    let emitEvent = null;
    const mockContext = {
      location: { directory: dir },
      event: {
        subscribe: () => ({
          [Symbol.asyncIterator]() {
            return {
              next() {
                if (!emitEvent) {
                  return new Promise((resolve) => {
                    emitEvent = resolve;
                  });
                }
                return Promise.resolve({ done: true, value: undefined });
              },
            };
          },
        }),
      },
      session: {
        get: async () => ({ id: "s1", parentID: undefined }),
        context: async () => [
          { id: "p1", type: "user", text: "Implement fully and run tests." },
          { id: "a1", type: "assistant", content: [{ type: "text", text: "The test failure is unrelated to this change." }] },
        ],
        synthetic: async (req) => {
          promptsSent.push(req);
        },
        hook: async (name, handler) => {
          if (name === "prompt") promptHook = handler;
          return { dispose: () => {} };
        },
      },
      tool: {
        hook: async () => ({ dispose: () => {} }),
      },
    };

    const cleanup = await v2Setup(mockContext);
    await promptHook({ sessionID: "s1", prompt: { text: "Please write a function with tests" } });

    emitEvent({
      done: false,
      value: { type: "session.idle", data: { sessionID: "s1" } },
    });
    await eventually(() => promptsSent.length >= 1 && toasts.length >= 1);
    await cleanup();

    assert.ok(promptsSent.length >= 1);
    assert.ok(toasts.length >= 1);
    const toast = toasts[0];
    assert.equal(toast.variant, "error");
    assert.equal(toast.title, "Guardian — Remediation");
    assert.match(toast.message, /Blocked:/);
    assert.match(toast.message, /Agent was asked to correct the issue/);
  });

  test("V2 server integration: idle turn advisory warning sends yellow/warning toast to user", async (t) => {
    clearToastListeners();
    const fs = await import("node:fs");
    const os = await import("node:os");
    const path = await import("node:path");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-toast-v2-warn-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      rules: {
        "integrity/no-unverified-claims": "warn",
      },
    }));

    const toasts = [];
    registerToastListener((toast) => {
      toasts.push(toast);
    }, { directory: dir });

    let emitEvent = null;
    const mockContext = {
      location: { directory: dir },
      event: {
        subscribe: () => ({
          [Symbol.asyncIterator]() {
            return {
              next() {
                if (!emitEvent) {
                  return new Promise((resolve) => {
                    emitEvent = resolve;
                  });
                }
                return Promise.resolve({ done: true, value: undefined });
              },
            };
          },
        }),
      },
      session: {
        get: async () => ({ id: "s1", parentID: undefined }),
        context: async () => [
          { id: "p1", type: "user", text: "Just say hello" },
          { id: "a1", type: "assistant", content: [{ type: "text", text: "All tests pass with 100% coverage and zero bugs!" }] },
        ],
        synthetic: async () => {},
        hook: async () => ({ dispose: () => {} }),
      },
      tool: {
        hook: async () => ({ dispose: () => {} }),
      },
    };

    const cleanup = await v2Setup(mockContext);

    emitEvent({
      done: false,
      value: { type: "session.idle", data: { sessionID: "s1" } },
    });
    await eventually(() => toasts.some((t) => t.variant === "warning"));
    await cleanup();

    const warnToast = toasts.find((t) => t.variant === "warning");
    assert.ok(warnToast, "Expected warning toast to be dispatched");
    assert.equal(warnToast.title, "Guardian — Warning");
    assert.match(warnToast.message, /Advisory finding: integrity\/no-unverified-claims/);
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
        get: async () => ({ id: "s1", parentID: undefined }),
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
    await assert.rejects(async () => {
      await toolHookHandler({
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
});

describe("Intervention Banner TTL & Clear Lifecycle", () => {
  function createAsyncEventStream() {
    const queue = [];
    let waiting = null;
    let closed = false;
    return {
      push(event) {
        if (closed) return;
        if (waiting) {
          const resolve = waiting;
          waiting = null;
          resolve({ value: event, done: false });
        } else {
          queue.push(event);
        }
      },
      close() {
        closed = true;
        if (waiting) {
          const resolve = waiting;
          waiting = null;
          resolve({ value: undefined, done: true });
        }
      },
      iterable: {
        [Symbol.asyncIterator]() {
          return {
            next() {
              if (queue.length > 0) {
                return Promise.resolve({ value: queue.shift(), done: false });
              }
              if (closed) {
                return Promise.resolve({ value: undefined, done: true });
              }
              return new Promise((resolve) => {
                waiting = resolve;
              });
            },
          };
        },
      },
    };
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  test("Issue #3 (V2): stream-interrupt-requested banner clears after subsequent clean turn", async (t) => {
    clearToastListeners();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-issue3-v2-"));
    t.after(() => {
      clearToastListeners();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    const stream = createAsyncEventStream();
    let rpcHandlers = null;
    let promptHook = null;
    let sessionMessages = [];

    const receivedToasts = [];
    const clearedScopes = [];
    registerToastListener((payload, scope) => {
      receivedToasts.push({ payload, scope });
    }, { directory: dir });
    registerToastClearListener((scope) => {
      clearedScopes.push(scope);
    }, { directory: dir });

    const dispose = await Guardian.setup({
      location: { directory: dir },
      options: { enabled: true },
      event: {
        subscribe: () => stream.iterable,
      },
      rpc: {
        register: async (def, handlers) => {
          if (def.id === GUARDIAN_INTERVENTION_RPC_DEFINITION.id) {
            rpcHandlers = handlers;
          }
          return { dispose() {} };
        },
      },
      session: {
        get: async ({ sessionID }) => ({ id: sessionID, location: { directory: dir } }),
        context: async () => sessionMessages,
        synthetic: async () => {},
        interrupt: async () => true,
        hook: async (name, cb) => {
          if (name === "prompt") promptHook = cb;
          return { dispose() {} };
        },
      },
      tool: {
        hook: async () => ({ dispose() {} }),
      },
    });
    t.after(async () => {
      stream.close();
      await dispose?.();
    });

    const sessionID = "ses-issue3-v2";
    // Turn 1: prompt + repetitive stream delta
    await promptHook({ sessionID, messageID: "u1", prompt: { text: "Write a helper" }, metadata: {} });
    stream.push({
      type: "session.text.delta",
      data: {
        sessionID,
        assistantMessageID: "a1",
        ordinal: 0,
        delta: "repeating phrase ".repeat(12),
      },
    });
    await sleep(60);

    assert.equal(receivedToasts.length, 1);
    assert.equal(receivedToasts[0].payload.variant, "warning");
    const afterInterrupt = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID });
    assert.equal(afterInterrupt.active, true);

    // Turn 1 goes idle cleanly (short interrupted output) -> banner must remain visible on Turn 1
    sessionMessages = [
      { id: "u1", type: "user", text: "Write a helper" },
      { id: "a1", type: "assistant", content: [{ type: "text", text: "Done." }] },
    ];
    stream.push({ type: "session.idle", data: { sessionID } });
    await sleep(60);

    const afterTurn1Idle = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID });
    assert.equal(afterTurn1Idle.active, true, "banner should remain visible right after interrupted turn idle");
    assert.equal(clearedScopes.length, 0);

    // Turn 2: new human prompt + clean assistant response -> banner must clear
    await promptHook({ sessionID, messageID: "u2", prompt: { text: "Continue cleanly" }, metadata: {} });
    sessionMessages = [
      ...sessionMessages,
      { id: "u2", type: "user", text: "Continue cleanly" },
      { id: "a2", type: "assistant", content: [{ type: "text", text: "Here is the clean answer." }] },
    ];
    stream.push({ type: "session.idle", data: { sessionID } });
    await sleep(60);

    const afterTurn2Idle = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID });
    assert.equal(afterTurn2Idle.active, false, "banner must clear after subsequent clean turn");
    assert.equal(clearedScopes.length, 1);
    assert.equal(clearedScopes[0].sessionID, sessionID);
  });

  test("Issue #3 (V2): RPC clear method clears both session-scoped and directory-wide interventions", async (t) => {
    clearToastListeners();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-issue3-rpc-"));
    t.after(() => {
      clearToastListeners();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    const stream = createAsyncEventStream();
    let rpcHandlers = null;
    let toolBeforeHook = null;

    const clearedScopes = [];
    registerToastClearListener((scope) => {
      clearedScopes.push(scope);
    }, { directory: dir });

    const dispose = await Guardian.setup({
      location: { directory: dir },
      options: { enabled: true, preflight: { enabled: true } },
      event: { subscribe: () => stream.iterable },
      rpc: {
        register: async (_def, handlers) => {
          rpcHandlers = handlers;
          return { dispose() {} };
        },
      },
      session: {
        get: async ({ sessionID }) => ({ id: sessionID, location: { directory: dir } }),
        context: async () => [],
        synthetic: async () => {},
        hook: async () => ({ dispose() {} }),
      },
      tool: {
        hook: async (name, cb) => {
          if (name === "execute.before") toolBeforeHook = cb;
          return { dispose() {} };
        },
      },
    });
    t.after(async () => {
      stream.close();
      await dispose?.();
    });

    const sessionID = "ses-rpc-clear";
    await assert.rejects(
      () => toolBeforeHook({ id: "c1", sessionID, tool: "bash", input: { command: "rm -rf /" } }),
      /Tool execution rejected/
    );

    const activeSnap = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID });
    assert.equal(activeSnap.active, true);

    const res = await rpcHandlers[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD]({ sessionID });
    assert.deepEqual(res, { cleared: true });

    const clearedSnap = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID });
    assert.equal(clearedSnap.active, false);
    assert.equal(clearedScopes.some((s) => s.sessionID === sessionID), true);

    // Trigger again, then test directory-wide clear (no sessionID, e.g. /guardian-reset from home)
    await assert.rejects(
      () => toolBeforeHook({ id: "c2", sessionID, tool: "bash", input: { command: "rm -rf /" } }),
      /Tool execution rejected/
    );
    assert.equal((await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID })).active, true);

    const globalRes = await rpcHandlers[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD]({});
    assert.deepEqual(globalRes, { cleared: true });
    assert.equal((await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID })).active, false);
  });

  test("Issue #3 (V2): session.moved dispatches toast clear for same-process listeners", async (t) => {
    clearToastListeners();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-issue3-move-"));
    t.after(() => {
      clearToastListeners();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    const stream = createAsyncEventStream();
    let toolBeforeHook = null;
    const clearedScopes = [];
    registerToastClearListener((scope) => {
      clearedScopes.push(scope);
    });

    const dispose = await Guardian.setup({
      location: { directory: dir },
      options: { enabled: true, preflight: { enabled: true } },
      event: { subscribe: () => stream.iterable },
      session: {
        get: async ({ sessionID }) => ({ id: sessionID, location: { directory: dir } }),
        context: async () => [],
        synthetic: async () => {},
        hook: async () => ({ dispose() {} }),
      },
      tool: {
        hook: async (name, cb) => {
          if (name === "execute.before") toolBeforeHook = cb;
          return { dispose() {} };
        },
      },
    });
    t.after(async () => {
      stream.close();
      await dispose?.();
    });

    const sessionID = "ses-move";
    await assert.rejects(
      () => toolBeforeHook({ id: "c1", sessionID, tool: "bash", input: { command: "rm -rf /" } }),
      /Tool execution rejected/
    );
    stream.push({ type: "session.moved", data: { sessionID, location: { directory: dir } } });
    await sleep(50);

    assert.equal(clearedScopes.some((s) => s.sessionID === sessionID), true);
  });

  test("Issue #3 (V2): post-turn GUARDIAN WARNING auto-expires after duration without requiring /guardian reset", async (t) => {
    clearToastListeners();
    const prevTtl = process.env.OPENCODE_GUARDIAN_INTERVENTION_TTL_MS;
    process.env.OPENCODE_GUARDIAN_INTERVENTION_TTL_MS = "120";
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-warning-ttl-"));
    t.after(() => {
      if (prevTtl === undefined) delete process.env.OPENCODE_GUARDIAN_INTERVENTION_TTL_MS;
      else process.env.OPENCODE_GUARDIAN_INTERVENTION_TTL_MS = prevTtl;
      clearToastListeners();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    const stream = createAsyncEventStream();
    let rpcHandlers = null;
    const clearedScopes = [];
    registerToastClearListener((scope) => {
      clearedScopes.push(scope);
    }, { directory: dir });

    const sessionID = "ses-warning-ttl";
    const dispose = await Guardian.setup({
      location: { directory: dir },
      options: {
        enabled: true,
        secrets: { enabled: false },
        rules: {
          "discipline/no-apology": "warn",
        },
      },
      event: { subscribe: () => stream.iterable },
      rpc: {
        register: async (def, handlers) => {
          if (def.id === GUARDIAN_INTERVENTION_RPC_DEFINITION.id) {
            rpcHandlers = handlers;
          }
          return { dispose() {} };
        },
      },
      session: {
        get: async () => ({ id: sessionID, location: { directory: dir } }),
        context: async () => [
          { id: "u1", type: "user", text: "Explain the function" },
          {
            id: "a1",
            type: "assistant",
            content: [
              { type: "text", text: "I deeply apologize, I am terribly sorry, my apologies for the confusion." },
            ],
          },
        ],
        synthetic: async () => {},
        hook: async () => ({ dispose() {} }),
      },
      tool: {
        hook: async () => ({ dispose() {} }),
      },
    });
    t.after(async () => {
      stream.close();
      await dispose?.();
    });

    stream.push({ type: "session.idle", data: { sessionID } });
    await sleep(40);

    // Immediately after idle, the warning snapshot is active
    const activeSnap = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID });
    assert.equal(activeSnap.active, true);
    assert.equal(activeSnap.variant, "warning");

    // After TTL (120ms) elapses with NO new prompt and NO /guardian reset, it must auto-clear
    await sleep(140);
    const expiredSnap = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID });
    assert.equal(expiredSnap.active, false, "GUARDIAN WARNING must auto-expire after duration");
    assert.equal(clearedScopes.some((s) => s.sessionID === sessionID), true);
  });

  test("Issue #3 (V2): new user prompt immediately clears previous turn warning before Turn 2 completes", async (t) => {
    clearToastListeners();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-prompt-clear-"));
    t.after(() => {
      clearToastListeners();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    const stream = createAsyncEventStream();
    let rpcHandlers = null;
    let promptHook = null;
    const sessionID = "ses-prompt-immediate-clear";

    const dispose = await Guardian.setup({
      location: { directory: dir },
      options: {
        enabled: true,
        secrets: { enabled: false },
        rules: {
          "discipline/no-apology": "warn",
        },
      },
      event: { subscribe: () => stream.iterable },
      rpc: {
        register: async (def, handlers) => {
          if (def.id === GUARDIAN_INTERVENTION_RPC_DEFINITION.id) {
            rpcHandlers = handlers;
          }
          return { dispose() {} };
        },
      },
      session: {
        get: async () => ({ id: sessionID, location: { directory: dir } }),
        context: async () => [
          { id: "u1", type: "user", text: "Explain the function" },
          {
            id: "a1",
            type: "assistant",
            content: [
              { type: "text", text: "I deeply apologize, I am terribly sorry, my apologies for the confusion." },
            ],
          },
        ],
        synthetic: async () => {},
        hook: async (name, cb) => {
          if (name === "prompt") promptHook = cb;
          return { dispose() {} };
        },
      },
      tool: {
        hook: async () => ({ dispose() {} }),
      },
    });
    t.after(async () => {
      stream.close();
      await dispose?.();
    });

    stream.push({ type: "session.idle", data: { sessionID } });
    await sleep(40);
    assert.equal((await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID })).active, true);

    // User submits a new prompt -> warning must clear IMMEDIATELY without waiting for Turn 2 idle
    await promptHook({ sessionID, messageID: "u2", prompt: { text: "Next task" }, metadata: {} });
    const afterPrompt = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID });
    assert.equal(afterPrompt.active, false, "new user prompt must clear stale warning immediately");
  });
});

describe("Detailed Conversation Notices & Context Guard", () => {
  const loop = "我想想".repeat(70);

  async function harness(t, notifications) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-transcript-"));
    const isolatedGlobal = path.join(directory, "_global_cfg");
    fs.mkdirSync(isolatedGlobal, { recursive: true });
    const prevConfigDir = process.env.OPENCODE_CONFIG_DIR;
    process.env.OPENCODE_CONFIG_DIR = isolatedGlobal;
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
      ...(notifications ? { notifications } : {}),
      secrets: { enabled: false }, updateNotice: { enabled: false },
    }));
    t.after(() => {
      if (prevConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
      else process.env.OPENCODE_CONFIG_DIR = prevConfigDir;
      fs.rmSync(directory, { recursive: true, force: true });
    });
    const synthetics = [];
    const rpcHandlers = new Map();
    let wake;
    const queue = [];
    const cleanup = await Guardian.setup({
      location: { directory },
      rpc: {
        async register(def, handlers) {
          rpcHandlers.set(def.id, handlers);
          return { dispose() { rpcHandlers.delete(def.id); } };
        },
      },
      session: {
        async context() { return []; },
        async synthetic(req) { synthetics.push(req); return {}; },
        async get() { return { location: { directory } }; },
        async interrupt() {},
      },
      event: { subscribe({ signal }) { return (async function* () {
        signal.addEventListener("abort", () => wake?.(), { once: true });
        while (!signal.aborted) {
          if (!queue.length) await new Promise(resolve => { wake = resolve; });
          const entry = queue.shift();
          if (entry) { yield entry.event; entry.resolve(); }
        }
      })(); } },
    });
    t.after(cleanup);
    const send = async event => {
      await new Promise(resolve => { queue.push({ event, resolve }); wake?.(); });
      await new Promise(resolve => setImmediate(resolve));
    };
    const delta = value => send({ type: "session.text.delta",
      data: { sessionID: "s", assistantMessageID: "a", ordinal: 0, delta: value } });
    const latestIntervention = async (sessionID = "s") => {
      const handlers = rpcHandlers.get(GUARDIAN_INTERVENTION_RPC_ID);
      assert.ok(handlers, "intervention RPC must be registered");
      return handlers[GUARDIAN_INTERVENTION_RPC_METHOD_4]({ sessionID });
    };
    return { directory, synthetics, delta, latestIntervention };
  }

  test("notifications.transcript delivers detailed banner via TUI RPC and never enqueues visible session.synthetic", async t => {
    const h = await harness(t, { transcript: true });
    await h.delta(loop);
    await new Promise(resolve => setTimeout(resolve, 30));
    const visibleSynthetics = h.synthetics.filter(
      s => isTrustedGuardianMetadata("s", s.metadata, "visible") || /\[Guardian\]/.test(s.text)
    );
    assert.equal(
      visibleSynthetics.length,
      0,
      "display-only notices must never enqueue into session_inbox via session.synthetic (prevents TrailingAssistantHistoryError)"
    );
    const snap = await h.latestIntervention("s");
    assert.equal(snap.active, true);
    assert.match(snap.message, /- runtime\/circuit-breaker:/);
    assert.match(snap.message, /Action:/);
    assert.doesNotMatch(snap.message, /我想想/, "no raw model text in the detailed notice");
    assert.ok(snap.duration > 5000, "detailed conversation notice should stay visible long enough to read");
  });

  test("default notifications (transcript off) keeps compact conversation banner and never enqueues visible synthetic", async t => {
    const h = await harness(t);
    await h.delta(loop);
    await new Promise(resolve => setTimeout(resolve, 30));
    assert.equal(h.synthetics.filter(s => /\[Guardian\]/.test(s.text)).length, 0);
    const snap = await h.latestIntervention("s");
    assert.equal(snap.active, true);
    assert.doesNotMatch(snap.message, /Action:/, "compact banner should stay concise when transcript detail mode is off");
  });

  test("notifications.transcript must be a boolean", t => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-transcript-cfg-"));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({ notifications: { transcript: "yes" } }));
    assert.throws(() => loadConfig(directory), /notifications/);
  });

  test("notifications.transcript delivers detailed per-finding bullets via RPC on remediation without enqueueing visible synthetic", async t => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-transcript-detail-"));
    const isolatedGlobal = path.join(directory, "_global_cfg");
    fs.mkdirSync(isolatedGlobal, { recursive: true });
    const prevConfigDir = process.env.OPENCODE_CONFIG_DIR;
    process.env.OPENCODE_CONFIG_DIR = isolatedGlobal;
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
      notifications: { enabled: true, transcript: true },
      updateNotice: { enabled: false },
    }));
    t.after(() => {
      if (prevConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
      else process.env.OPENCODE_CONFIG_DIR = prevConfigDir;
      fs.rmSync(directory, { recursive: true, force: true });
    });

    const synthetics = [];
    const rpcHandlers = new Map();
    let wake;
    const queue = [];
    const messages = [
      { id: "u1", type: "user", text: "Fix the failing unit test." },
      {
        id: "a1",
        type: "assistant",
        agent: "build",
        content: [
          {
            type: "tool",
            id: "c1",
            name: "write",
            state: {
              status: "completed",
              input: {
                filePath: path.join(directory, "src", "demo.ts"),
                content: "export function handle() { try { work(); } catch {} }\n",
              },
            },
          },
          { type: "text", text: "The test failure is unrelated to this change and pre-existing." },
        ],
      },
    ];
    const cleanup = await Guardian.setup({
      location: { directory },
      rpc: {
        async register(def, handlers) {
          rpcHandlers.set(def.id, handlers);
          return { dispose() { rpcHandlers.delete(def.id); } };
        },
      },
      session: {
        async context() { return messages; },
        async synthetic(req) { synthetics.push(req); return { id: `syn-${synthetics.length}` }; },
        async get({ sessionID }) { return { id: sessionID, location: { directory } }; },
        async hook() { return { dispose() {} }; },
      },
      tool: { async hook() { return { dispose() {} }; } },
      shell: { async hook() { return { dispose() {} }; } },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            signal.addEventListener("abort", () => wake?.(), { once: true });
            while (!signal.aborted) {
              if (!queue.length) await new Promise(resolve => { wake = resolve; });
              const entry = queue.shift();
              if (entry) { yield entry.event; entry.resolve(); }
            }
          })();
        },
      },
    });
    t.after(cleanup);

    await new Promise(resolve => {
      queue.push({
        event: { type: "session.execution.succeeded", location: { directory }, data: { sessionID: "s-detail" } },
        resolve,
      });
      wake?.();
    });
    await new Promise(resolve => setTimeout(resolve, 50));

    // Only the actual remediation prompt may use session.synthetic — NEVER a visible display notice!
    const visibleNotices = synthetics.filter(
      s => isTrustedGuardianMetadata("s-detail", s.metadata, "visible") || s.description === "OpenCode Guardian notice"
    );
    assert.equal(visibleNotices.length, 0, "must never enqueue visible display notices into session_inbox");
    const remediations = synthetics.filter(s => isTrustedGuardianMetadata("s-detail", s.metadata, "remediation"));
    assert.equal(remediations.length, 1, "remediation prompt must still be delivered normally");

    const snap = await rpcHandlers.get(GUARDIAN_INTERVENTION_RPC_ID)[GUARDIAN_INTERVENTION_RPC_METHOD_4]({
      sessionID: "s-detail",
    });
    assert.equal(snap.active, true);
    assert.match(snap.title, /Remediation/);
    assert.match(snap.message, /- discipline\/no-evasion\b/, "must include bullet for triggered rule");
    assert.match(snap.message, /- integrity\/no-silent-failure\b/, "must include bullet for silent failure rule");
    assert.match(snap.message, /empty JavaScript\/TypeScript catch/i, "must include finding pattern/detail");
    assert.match(snap.message, /Action: Agent was asked to correct the issue\./, "must clearly state the action taken");
  });

  test("notifications.transcript redacts any secret-like tokens in finding descriptions and never leaks raw secrets", async () => {
    const { formatGuardianToast, formatGuardianTranscriptNotice } = await import("../dist/toast.js");
    const secret = "sk-proj-abcdef1234567890abcdef1234567890";
    const input = {
      kind: "remediation",
      ruleIds: ["security/no-secrets"],
      details: [{
        ruleId: "security/no-secrets",
        pattern: "OpenAI API key",
        description: `Hardcoded credential detected near ${secret}`,
        filePath: "src/client.ts",
      }],
    };
    const text = formatGuardianTranscriptNotice(input);
    assert.match(text, /\[Guardian\] ↻ REMEDIATION/);
    assert.match(text, /security\/no-secrets/);
    assert.match(text, /OpenAI API key/);
    assert.match(text, /src\/client\.ts/);
    assert.equal(text.includes(secret), false, "raw secret must never appear in detailed notice");

    const detailedToast = formatGuardianToast(input, { detailed: true });
    assert.match(detailedToast.message, /- security\/no-secrets/);
    assert.match(detailedToast.message, /OpenAI API key/);
    assert.match(detailedToast.message, /src\/client\.ts/);
    assert.equal(detailedToast.message.includes(secret), false, "raw secret must never appear in detailed TUI banner");
  });

  test("session.context never strips a trailing visible message if doing so would leave history ending on assistant", async t => {
    const { createGuardianMessageMetadata } = await import("../dist/provenance.js");
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-trailing-asst-"));
    const isolatedGlobal = path.join(directory, "_global_cfg");
    fs.mkdirSync(isolatedGlobal, { recursive: true });
    const prevConfigDir = process.env.OPENCODE_CONFIG_DIR;
    process.env.OPENCODE_CONFIG_DIR = isolatedGlobal;
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
      notifications: { enabled: true, transcript: true },
      secrets: { enabled: false },
      updateNotice: { enabled: false },
    }));
    t.after(() => {
      if (prevConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
      else process.env.OPENCODE_CONFIG_DIR = prevConfigDir;
      fs.rmSync(directory, { recursive: true, force: true });
    });

    let contextHook;
    const cleanup = await Guardian.setup({
      location: { directory },
      session: {
        async context() { return []; },
        async synthetic() { return {}; },
        async get({ sessionID }) { return { id: sessionID, location: { directory } }; },
        async hook(kind, cb) {
          if (kind === "context") contextHook = cb;
          return { dispose() {} };
        },
      },
      tool: { async hook() { return { dispose() {} }; } },
      shell: { async hook() { return { dispose() {} }; } },
      event: { subscribe() { return (async function* () {})(); } },
    });
    t.after(cleanup);
    assert.equal(typeof contextHook, "function");

    const sid = "ses-trailing";
    const visibleMeta = createGuardianMessageMetadata(sid, "visible");

    // Case 1: trailing visible synthetic after assistant -> must NOT leave trailing assistant!
    const trailingEvent = {
      sessionID: sid,
      system: [],
      messages: [
        { role: "user", content: "hi" },
        { role: "assistant", content: "done" },
        { role: "user", content: "[Guardian] notice", metadata: visibleMeta },
      ],
    };
    await contextHook(trailingEvent);
    assert.notEqual(
      trailingEvent.messages[trailingEvent.messages.length - 1]?.role,
      "assistant",
      "session.context must never turn a non-assistant history tail into a trailing assistant turn"
    );

    // Case 2: mid-conversation visible synthetic followed by a real user message -> safely stripped!
    const midEvent = {
      sessionID: sid,
      system: [],
      messages: [
        { role: "user", content: "hi" },
        { role: "assistant", content: "done" },
        { role: "user", content: "[Guardian] notice", metadata: visibleMeta },
        { role: "user", content: "next question" },
      ],
    };
    await contextHook(midEvent);
    assert.equal(midEvent.messages.length, 3, "mid-conversation visible message is safely stripped");
    assert.equal(midEvent.messages[midEvent.messages.length - 1]?.content, "next question");
  });
});

describe("Guardian Slash Commands", () => {
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
    registerGuardianV2Commands_5(ctx, () => dir);
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
    assert.ok(opened.at(-1).message.includes("Blocked tools (preflight): 1"));
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
    registerGuardianV2Commands_5(ctx, () => current);
    const commands = register().commands;
    const status = commands.find((c) => c.id === "opencode-guardian.status");
    await status.run();
    assert.ok(shown.at(-1).message.includes("Blocked tools (preflight): 1"));
    current = b;
    await status.run();
    assert.ok(shown.at(-1).message.includes("Blocked tools (preflight): 0"));
    assert.match(shown.at(-1).message, /Warnings: 1/);
    const reset = commands.find((c) => c.id === "opencode-guardian.reset");
    await reset.run();
    assert.equal(readGuardianStatus(a).blocked, 1);
    assert.equal(readGuardianStatus(b).warnings, 0);
  });

  test("V2 setup owns global commands independent of sidebar and conversation rendering", (t) => {
    const dir = isolated(t);
    const steps = [];
    const slots = [];
    let factory;
    let released = 0;
    const cleanup = GuardianTui.setup({
      location: { directory: dir },
      keymap: { layer(create) { steps.push("keymap"); factory = create; } },
      ui: { slot(input) {
        steps.push("slot");
        slots.push(input.append);
        return () => { released++; };
      } },
    });
    assert.equal(steps[0], "keymap");
    assert.deepEqual(slots.sort(), ["session.composer.top", "sidebar.content"]);
    assert.equal(factory().mode, "global");
    assert.equal(factory().commands.filter((c) => c.palette === true).length, 7);
    assert.equal(typeof cleanup, "function");
    cleanup();
    assert.equal(released, 2);
  });
});

describe("Version Update Notice", () => {
  function options(t, latest = "0.4.3") {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-notice-test-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    let calls = 0;
    return {
      input: {
        installedVersion: "0.4.2", allowDevelopment: true,
        cachePath: path.join(dir, "notice.json"), now: 1_800_000_000_000,
        fetcher: async () => { calls++; return {
          ok: true, json: async () => ({ name: "opencode-guardian", version: latest }),
        }; },
      },
      get calls() { return calls; },
    };
  }
  test("stable semver comparison ignores prereleases and does not downgrade", () => {
    for (const [a, b, expected] of [
      ["0.4.2", "0.4.3", true], ["0.4.2", "0.5.0", true],
      ["0.4.2", "1.0.0", true], ["0.4.2", "0.4.2", false],
      ["1.0.0", "0.99.99", false], ["0.4.2", "0.4.3-beta.1", false],
      ["0.4.2-local", "0.4.3", false],
    ]) assert.equal(newerStableVersion(a, b), expected, a + " / " + b);
  });
  test("24-hour cached update appears without a second registry request", async (t) => {
    const fixture = options(t);
    assert.deepEqual(await checkGuardianUpdate(fixture.input), { current: "0.4.2", latest: "0.4.3" });
    assert.deepEqual(await checkGuardianUpdate({ ...fixture.input, now: fixture.input.now + 23 * 3600_000 }), { current: "0.4.2", latest: "0.4.3" });
    assert.equal(fixture.calls, 1);
    await checkGuardianUpdate({ ...fixture.input, now: fixture.input.now + 25 * 3600_000 });
    assert.equal(fixture.calls, 2);
  });
  test("an up-to-date install stays silent and network failures fail open", async (t) => {
    assert.equal(await checkGuardianUpdate(options(t, "0.4.2").input), undefined);
    const fixture = options(t);
    assert.equal(await checkGuardianUpdate({ ...fixture.input, fetcher: async () => { throw new Error("offline"); } }), undefined);
    let shown = 0;
    await announceGuardianUpdate(() => { shown++; throw new Error("toast unavailable"); }, fixture.input);
    assert.equal(shown, 1);
  });
  test("local development mode skips networking by default", async (t) => {
    const fixture = options(t);
    assert.equal(await checkGuardianUpdate({ ...fixture.input, allowDevelopment: false }), undefined);
    assert.equal(fixture.calls, 0);
  });
  test("invalid registry responses do not create notices", async (t) => {
    const fixture = options(t);
    const fetcher = async () => ({ ok: true, json: async () => ({ name: "other-package", version: "9.0.0" }) });
    assert.equal(await checkGuardianUpdate({ ...fixture.input, fetcher }), undefined);
  });

  test("Dalga 3 (G-25): failed /guardian-reset does not invoke onReset/toast-clear and broken config is flagged distinctly", async (t) => {
    const { registerGuardianV2Commands } = await import("../dist/tui.js");
    const { configureGuardianTelemetry, clearGuardianTelemetryConfig } = await import("../dist/telemetry.js");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-g25-tui-"));
    t.after(() => {
      clearGuardianTelemetryConfig();
      fs.rmSync(dir, { recursive: true, force: true });
    });
    configureGuardianTelemetry(dir, { enabled: false, level: "off" });

    let registeredCommands = [];
    let onResetCalls = 0;
    const alerts = [];
    const ctx = {
      keymap: {
        layer(factory) {
          registeredCommands = factory().commands;
        },
      },
      ui: {
        dialog: {
          async confirm() { return true; },
          async alert(msg) { alerts.push(msg); },
        },
      },
    };
    registerGuardianV2Commands(ctx, () => dir, () => { onResetCalls++; });
    const resetCmd = registeredCommands.find((c) => c.id === "opencode-guardian.reset");
    assert.ok(resetCmd);
    await resetCmd.run();
    assert.equal(onResetCalls, 0, "failed reset must NOT call onReset or clear intervention visibility");
    assert.match(alerts[0]?.message ?? "", /Reset failed/i);
  });
});
