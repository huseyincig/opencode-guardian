import test from "node:test";
import assert from "node:assert/strict";
import TuiPlugin, { registerGuardianV2Commands } from "../dist/tui.js";
import RootTui, { default as LocalPathTui } from "../tui.js";
import OpencodeGuardian from "../dist/index.js";
import * as RpcPlugin from "../dist/intervention-rpc.js";

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
