import test from "node:test";
import assert from "node:assert/strict";
import TuiPlugin from "../dist/tui.js";
import RootTui, { default as LocalPathTui } from "../tui.js";

test("V2 TUI registers an additive sidebar slot and returns its disposer", () => {
  let claim;
  const stop = () => {};
  const cleanup = TuiPlugin.setup({
    ui: { slot(input) { claim = input; return stop; } },
  });
  assert.equal(TuiPlugin.id, "opencode-guardian.tui");
  assert.equal(claim.append, "sidebar.content");
  assert.equal(claim.replace, undefined);
  assert.equal(typeof claim.render, "function");
  assert.equal(cleanup, stop);
});

test("root tui.js resolves the same dual-mode sidebar plugin for local path loading", () => {
  assert.equal(RootTui, TuiPlugin);
  assert.equal(LocalPathTui, TuiPlugin);
  assert.equal(RootTui.id, "opencode-guardian.tui");
});


test("V1 TUI registers sidebar_content as an additive slot and renders the Guardian sidebar", async () => {
  let claim;
  let calls = 0;
  const registration = await TuiPlugin.tui({
    state: { path: { directory: process.cwd() } },
    slots: {
      register(input) { calls++; claim = input; return "guardian-v1-slot"; },
    },
  });
  assert.equal(registration, undefined);
  assert.equal(calls, 1);
  assert.equal(claim.order, 600);
  assert.equal(typeof claim.slots.sidebar_content, "function");
  assert.equal(claim.id, undefined, "V1 host assigns slot IDs");
  // Full rendering belongs to the actual TUI host; mock tests verify registration.
  assert.equal(TuiPlugin.server, undefined);
});

test("V1 and V2 sidebar registration APIs coexist in the same package entrypoint", async () => {
  let v1 = false;
  let v2 = false;
  await TuiPlugin.tui({ state: { path: { directory: process.cwd() } }, slots: { register(input) {
    v1 = typeof input.slots.sidebar_content === "function";
    return "guardian-v1-slot";
  } } });
  const dispose = TuiPlugin.setup({ ui: { slot(input) {
    v2 = input.append === "sidebar.content";
    return () => {};
  } } });
  assert.equal(v1, true);
  assert.equal(v2, true);
  assert.equal(typeof dispose, "function");
});

test("V1 TUI honors the same disabled Guardian configuration", async (t) => {
  const fs = await import("node:fs");
  const os = await import("node:os");
  const path = await import("node:path");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-v1-tui-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, "opencode-guardian.json"), '{"enabled":false}');
  let called = false;
  await TuiPlugin.tui({
    state: { path: { directory: dir } },
    slots: { register() { called = true; } },
  });
  assert.equal(called, false);
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
  assert.equal(typeof TuiPlugin.tui, "function");
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

test("dual-mode SDK entrypoints and Node 24 package contract", async () => {
  const { readFileSync } = await import("node:fs");
  const { readFile } = await import("node:fs/promises");
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.engines.node, ">=24.0.0");
  const v1 = readFileSync(new URL(import.meta.resolve("@opencode-ai/plugin/tui")), "utf8");
  const v2 = readFileSync(new URL(import.meta.resolve("@opencode/plugin/tui")), "utf8");
  assert.equal(typeof v1, "string");
  assert.equal(typeof v2, "string");
  assert.equal(typeof TuiPlugin.tui, "function");
  assert.equal(typeof TuiPlugin.setup, "function");
});


test("V2 accent never relies on the possibly transparent action background", async () => {
  const { readFileSync } = await import("node:fs");
  const source = readFileSync(new URL("../src/tui.tsx", import.meta.url), "utf8");
  assert.match(source, /accent: context\.theme\.status\?\.success\?\.base \?\? context\.theme\.text\.base/);
  assert.doesNotMatch(source, /accent: context\.theme\.background\.action\.primary\.base/);
});
