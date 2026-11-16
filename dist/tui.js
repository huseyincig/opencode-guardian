// Adaptive Guardian TUI entrypoint: host runtime first, standalone Node fallback.
let hostRuntime = false;
try {
  await import("opentui:runtime-module:%40opentui%2Fsolid");
  hostRuntime = true;
} catch {
  hostRuntime = false;
}
const implementation = hostRuntime
  ? await import("./tui-runtime.js")
  : await import("./tui-standalone.js");
export default implementation.default;
export const setup = implementation.default.setup;
export const registerGuardianV2Commands = implementation.registerGuardianV2Commands;
