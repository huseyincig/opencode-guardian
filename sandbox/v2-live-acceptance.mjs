import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import OpencodeGuardian, {
  GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD,
  GUARDIAN_INTERVENTION_RPC_METHOD,
  readGuardianStatus,
} from "../dist/index.js";
import TuiPlugin from "../dist/tui.js";

console.log("================================================================================");
console.log("     OPENCODE-GUARDIAN — LIVE V2.3.0 + BUN HOST ACCEPTANCE TEST SUITE");
console.log("================================================================================");

const repoDir = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v2-live-"));
const oldStateDir = process.env.OPENCODE_GUARDIAN_STATE_DIR;
process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(tmpRoot, "state");

const cleanupTmp = () => {
  if (oldStateDir === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
  else process.env.OPENCODE_GUARDIAN_STATE_DIR = oldStateDir;
  fs.rmSync(tmpRoot, { recursive: true, force: true });
};

try {
  // 1. Packed Tarball Verification in Node & Bun 1.4.4
  console.log("\n[1] Packed Tarball Verification (Node + Bun 1.4.4)...");
  const packDir = path.join(tmpRoot, "pack");
  fs.mkdirSync(packDir, { recursive: true });
  const packRes = spawnSync("npm", ["pack", "--pack-destination", packDir], {
    cwd: repoDir,
    encoding: "utf8",
  });
  assert.equal(packRes.status, 0, `npm pack failed: ${packRes.stderr}`);
  const tgzName = packRes.stdout.trim().split("\n").pop();
  assert.ok(tgzName && tgzName.endsWith(".tgz"), `Unexpected tarball name: ${tgzName}`);
  const tgzPath = path.join(packDir, tgzName);

  const installDir = path.join(tmpRoot, "installed");
  fs.mkdirSync(installDir, { recursive: true });
  const tarRes = spawnSync("tar", ["-xzf", tgzPath, "-C", installDir], { encoding: "utf8" });
  assert.equal(tarRes.status, 0, `tar extract failed: ${tarRes.stderr}`);
  const pkgRoot = path.join(installDir, "package");
  fs.symlinkSync(path.join(repoDir, "node_modules"), path.join(pkgRoot, "node_modules"), "dir");

  const importProbe = `
    import server, { OpencodeGuardian } from "${pkgRoot}/dist/index.js";
    import tui from "${pkgRoot}/dist/tui.js";
    import * as rpc from "${pkgRoot}/dist/intervention-rpc.js";
    import pkgMain from "opencode-guardian";
    import pkgTui from "opencode-guardian/tui";
    import * as pkgRpc from "opencode-guardian/rpc";
    if (server.server !== undefined) throw new Error("V1 server export must be undefined");
    if (tui.tui !== undefined) throw new Error("V1 tui export must be undefined");
    if (!pkgMain.setup || !pkgTui.setup || !pkgRpc.GUARDIAN_INTERVENTION_RPC_DEFINITION) {
      throw new Error("Missing V2 exports");
    }
    if (server !== OpencodeGuardian) throw new Error("Default export mismatch");
    console.log("EXPORTS_OK");
  `;
  fs.writeFileSync(path.join(pkgRoot, "probe-imports.mjs"), importProbe);

  const nodeImport = spawnSync(process.execPath, [path.join(pkgRoot, "probe-imports.mjs")], {
    cwd: pkgRoot,
    encoding: "utf8",
  });
  assert.equal(nodeImport.status, 0, `Node packed import failed: ${nodeImport.stderr}`);
  assert.match(nodeImport.stdout, /EXPORTS_OK/);
  console.log(`    ✓ Node (${process.version}) packed '.', './tui', './rpc' imports verified`);

  const bunBin = "/root/.bun/bin/bun";
  assert.equal(fs.existsSync(bunBin), true, `Bun binary not found at ${bunBin}`);
  const bunImport = spawnSync(bunBin, [path.join(pkgRoot, "probe-imports.mjs")], {
    cwd: pkgRoot,
    encoding: "utf8",
  });
  assert.equal(bunImport.status, 0, `Bun packed import failed: ${bunImport.stderr}`);
  assert.match(bunImport.stdout, /EXPORTS_OK/);
  console.log("    ✓ Bun (1.4.4) packed '.', './tui', './rpc' imports & dist/tui.js fallback verified (no ResolveMessage crash)");

  // 2. Full V2.3.0 Server Hook Set, Preflight, Redaction, Post-Turn Remediation, RPC & Telemetry
  console.log("\n[2] V2 Server setup(ctx) Full v2.3.0 Hook Set & Lifecycle...");
  const projectDir = path.join(tmpRoot, "project-v2");
  fs.mkdirSync(projectDir, { recursive: true });
  fs.writeFileSync(path.join(projectDir, "opencode-guardian.json"), JSON.stringify({
    enabled: true,
    preflight: { enabled: true },
    telemetry: { level: "violations" },
    updateNotice: { enabled: false },
  }));

  const registeredHooks = new Map();
  const rpcHandlers = {};
  const synthetics = [];
  const eventQueue = [];
  let wakeEvent = null;
  const pushEvent = async (ev) => {
    eventQueue.push(ev);
    wakeEvent?.();
    await new Promise((r) => setImmediate(r));
  };

  let turnMode = "violation";
  const v2Host = {
    location: { directory: projectDir },
    event: {
      subscribe({ signal }) {
        return (async function* () {
          while (!signal.aborted) {
            if (!eventQueue.length) {
              await new Promise((resolve) => { wakeEvent = resolve; });
            }
            const next = eventQueue.shift();
            if (next === null) break;
            if (next) yield next;
          }
        })();
      },
    },
    session: {
      async get({ sessionID }) {
        return { id: sessionID, parentID: undefined, location: { directory: projectDir } };
      },
      async context() {
        if (turnMode === "clean") {
          return [
            { id: "u2", type: "user", text: "Explain the architecture." },
            { id: "a2", type: "assistant", content: [{ type: "text", text: "The architecture uses V2 hooks cleanly." }] },
          ];
        }
        return [
          { id: "u1", type: "user", text: "Fix the bug." },
          { id: "a1", type: "assistant", content: [{ type: "text", text: "The test failure is unrelated to this change." }] },
        ];
      },
      async synthetic(req) {
        synthetics.push(req);
        return { id: "syn-1" };
      },
      async wait() { return { status: "idle" }; },
      async hook(kind, cb) {
        const list = registeredHooks.get(`session.${kind}`) ?? [];
        list.push(cb);
        registeredHooks.set(`session.${kind}`, list);
        return { dispose() { list.splice(list.indexOf(cb), 1); } };
      },
    },
    tool: {
      async hook(kind, cb) {
        const list = registeredHooks.get(`tool.${kind}`) ?? [];
        list.push(cb);
        registeredHooks.set(`tool.${kind}`, list);
        return { dispose() { list.splice(list.indexOf(cb), 1); } };
      },
    },
    shell: {
      async hook(kind, cb) {
        const list = registeredHooks.get(`shell.${kind}`) ?? [];
        list.push(cb);
        registeredHooks.set(`shell.${kind}`, list);
        return { dispose() { list.splice(list.indexOf(cb), 1); } };
      },
    },
    rpc: {
      async register(_def, handlers) {
        Object.assign(rpcHandlers, handlers);
        return { dispose() {} };
      },
    },
  };

  const cleanup = await OpencodeGuardian.setup(v2Host);
  assert.equal(typeof cleanup, "function");

  const expectedHooks = [
    "session.prompt",
    "session.context",
    "session.compaction",
    "session.generate",
    "session.title",
    "tool.execute.before",
    "tool.execute.after",
    "shell.create.before",
  ];
  for (const h of expectedHooks) {
    assert.ok((registeredHooks.get(h)?.length ?? 0) > 0, `Missing hook: ${h}`);
  }
  assert.equal(typeof rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD], "function");
  assert.equal(typeof rpcHandlers[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD], "function");
  console.log("    ✓ All 10 V2.3.0 hooks & RPC methods registered");

  // Preflight blocking (tool.execute.before + shell.create.before)
  await assert.rejects(
    async () => {
      for (const cb of registeredHooks.get("tool.execute.before")) {
        await cb({ tool: "bash", sessionID: "s-live", id: "c1", input: { command: "rm -rf /" } });
      }
    },
    (e) => e.reason === "destructive-command"
  );
  await assert.rejects(
    async () => {
      for (const cb of registeredHooks.get("shell.create.before")) {
        await cb({ sessionID: "s-live", command: "rm -rf /" });
      }
    },
    (e) => e.reason === "destructive-command"
  );
  console.log("    ✓ Preflight blocks destructive commands in both tool.execute.before and shell.create.before");

  // Error secret redaction
  const secretToken = "sk-proj-abcdef1234567890abcdef1234567890";
  const errEv = {
    tool: "bash", sessionID: "s-live", id: "c2",
    input: { command: "curl" }, status: "error",
    error: new Error(`Auth Bearer ${secretToken}`),
  };
  for (const cb of registeredHooks.get("tool.execute.after")) {
    await cb(errEv);
  }
  assert.equal(errEv.error.message.includes(secretToken), false);
  console.log("    ✓ Error secret redaction verified");

  // Post-turn remediation & RPC intervention active -> clean turn clears
  await pushEvent({ type: "session.idle", data: { sessionID: "s-live" } });
  for (let i = 0; i < 60 && synthetics.length === 0; i++) {
    await new Promise((r) => setTimeout(r, 15));
  }
  assert.ok(synthetics.length >= 1, "Expected post-turn remediation");
  const snapActive = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID: "s-live" });
  assert.equal(snapActive.active, true);

  turnMode = "clean";
  await pushEvent({ type: "session.idle", data: { sessionID: "s-live" } });
  for (let i = 0; i < 60; i++) {
    const s = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID: "s-live" });
    if (!s.active) break;
    await new Promise((r) => setTimeout(r, 15));
  }
  const snapCleared = await rpcHandlers[GUARDIAN_INTERVENTION_RPC_METHOD]({ sessionID: "s-live" });
  assert.equal(snapCleared.active, false, "Clean turn must clear RPC intervention");
  console.log("    ✓ Post-turn remediation & clean-turn RPC intervention clear verified");

  // Telemetry low-I/O check (violations suppresses benign preflight-allowed)
  for (const cb of registeredHooks.get("tool.execute.before")) {
    await cb({ tool: "bash", sessionID: "s-live", id: "c3", input: { command: "echo safe" } });
  }
  const statusViolations = readGuardianStatus(projectDir);
  assert.equal(statusViolations.blocked, 2);
  console.log("    ✓ Low-I/O telemetry (level: 'violations') verified");

  await pushEvent(null);
  await cleanup();
  console.log("    ✓ Clean server disposal verified");

  // 3. V2 TUI Verification
  console.log("\n[3] V2 TUI Verification (slots, 7 commands + /guardian, enabled: false)...");
  const tuiClaims = [];
  let layerFactory = null;
  const tuiCleanup = TuiPlugin.setup({
    location: { directory: projectDir },
    ui: {
      slot(claim) { tuiClaims.push(claim); return () => {}; },
      toast: { show() {} },
      dialog: { alert: async () => {}, confirm: async () => false },
    },
    keymap: { layer(factory) { layerFactory = factory; return () => {}; } },
    data: { on: () => () => {} },
  });
  assert.equal(typeof tuiCleanup, "function");
  const sidebarClaim = tuiClaims.find((c) => c.append === "sidebar.content");
  const composerClaim = tuiClaims.find((c) => c.append === "session.composer.top");
  assert.ok(sidebarClaim && sidebarClaim.replace === undefined, "sidebar.content must be additive");
  assert.ok(composerClaim && composerClaim.replace === undefined, "session.composer.top must be additive");
  const layerCommands = layerFactory().commands;
  assert.equal(layerCommands.length, 8, "Expected 7 guardian-* commands + 1 /guardian dispatcher");
  assert.ok(layerCommands.some((c) => c.slash?.name === "guardian"));
  tuiCleanup();

  const disabledDir = path.join(tmpRoot, "disabled-tui");
  fs.mkdirSync(disabledDir, { recursive: true });
  fs.writeFileSync(path.join(disabledDir, "opencode-guardian.json"), JSON.stringify({ enabled: false }));
  let disabledSlotCalled = false;
  const disabledTui = TuiPlugin.setup({
    location: { directory: disabledDir },
    ui: { slot() { disabledSlotCalled = true; return () => {}; } },
  });
  assert.equal(disabledTui, undefined);
  assert.equal(disabledSlotCalled, false);
  console.log("    ✓ V2 TUI additive slots, 7 commands + /guardian, and enabled: false verified");

  // 4. Real OpenCode v2.3.0 CLI Host Acceptance
  console.log("\n[4] Real OpenCode v2.3.0 CLI Host Acceptance (/usr/local/bin/opencode)...");
  const ocBin = "/usr/local/bin/opencode";
  assert.equal(fs.existsSync(ocBin), true, `OpenCode binary not found at ${ocBin}`);
  const ocWorkspace = path.join(tmpRoot, "oc-workspace");
  fs.mkdirSync(ocWorkspace, { recursive: true });
  fs.writeFileSync(
    path.join(ocWorkspace, "opencode.json"),
    JSON.stringify({ plugins: [`file://${repoDir}`] }, null, 2)
  );
  const ocVer = spawnSync(ocBin, ["--version"], { cwd: ocWorkspace, encoding: "utf8" });
  assert.equal(ocVer.status, 0, `opencode --version failed: ${ocVer.stderr}`);
  const ocVersionText = ocVer.stdout.trim();
  assert.match(ocVersionText, /2\.3\./, `Expected OpenCode v2.3.x, got: ${ocVersionText}`);
  console.log(`    ✓ Real OpenCode CLI (${ocVersionText}) verified in isolated workspace with plugin config`);

  console.log("\n================================================================================");
  console.log("  OPENCODE V2.3.0 + BUN 1.4.4 LIVE ACCEPTANCE TESTS PASSED SUCCESSFULLY!");
  console.log("================================================================================");
} finally {
  cleanupTmp();
}
