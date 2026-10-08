/**
 * Emit two Solid Universal TUI variants from src/tui.tsx.
 * Runtime shares OpenCode's virtual Solid renderer; standalone supports Node tests.
 * Keep the root ./tui entrypoint and emitted declarations produced by tsc.
 */
import { transformSync } from "@babel/core";
import babelPresetSolid from "babel-preset-solid";
import babelPresetTypescript from "@babel/preset-typescript";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const sourcePath = path.join(root, "src", "tui.tsx");
const dist = path.join(root, "dist");
const source = readFileSync(sourcePath, "utf8");

function compile(moduleName) {
  const result = transformSync(source, {
    filename: sourcePath,
    babelrc: false,
    configFile: false,
    presets: [
      [babelPresetSolid, { moduleName, generate: "universal" }],
      [babelPresetTypescript, { isTSX: true, allExtensions: true }],
    ],
  });
  if (!result?.code) throw new Error("Solid Universal TUI compilation failed");
  return result.code;
}

const runtime = compile("opentui:runtime-module:%40opentui%2Fsolid")
  .replace(/from (["'])solid-js\1/g, 'from "opentui:runtime-module:solid-js"');
const standalone = compile("@opentui/solid");

if (runtime.includes('from "@opentui/solid"') ||
    runtime.includes('from "@opentui/solid/jsx-runtime"') ||
    runtime.includes('from "solid-js"') ||
    runtime.includes('from "@opencode/plugin/tui"')) {
  throw new Error("Guardian host TUI still imports an isolated/bare runtime");
}
if (!runtime.includes("opentui:runtime-module:%40opentui%2Fsolid") ||
    !runtime.includes("opentui:runtime-module:solid-js")) {
  throw new Error("Guardian host TUI does not use OpenCode's shared Solid runtime");
}
if (!standalone.includes('@opentui/solid')) {
  throw new Error("Standalone TUI is missing Solid Universal imports");
}

writeFileSync(path.join(dist, "tui-runtime.js"), runtime + "\n");
writeFileSync(path.join(dist, "tui-standalone.js"), standalone + "\n");
writeFileSync(path.join(dist, "tui.js"), [
  "// Adaptive Guardian TUI entrypoint: host runtime first, standalone Node fallback.",
  "let hostRuntime = false;",
  "try {",
  '  await import("opentui:runtime-module:%40opentui%2Fsolid");',
  "  hostRuntime = true;",
  "} catch (error) {",
  '  if (error?.code !== "ERR_MODULE_NOT_FOUND" && error?.code !== "ERR_UNSUPPORTED_ESM_URL_SCHEME" &&',
  '      error?.code !== "ERR_UNKNOWN_URL_SCHEME") throw error;',
  "}",
  "const implementation = hostRuntime",
  '  ? await import("./tui-runtime.js")',
  '  : await import("./tui-standalone.js");',
  "export default implementation.default;",
  "export const tui = implementation.default.tui;",
  "export const setup = implementation.default.setup;",
  "export const registerGuardianV1Commands = implementation.registerGuardianV1Commands;",
  "export const registerGuardianV2Commands = implementation.registerGuardianV2Commands;",
  "",
].join("\n"));
console.error("[emit-tui] Guardian host, standalone and adaptive TUI emitted");
