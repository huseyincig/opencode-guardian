// Adaptive Guardian TUI entrypoint: host runtime first, standalone Node fallback.
let hostRuntime = false;
try {
  await import("opentui:runtime-module:%40opentui%2Fsolid");
  hostRuntime = true;
} catch (error) {
  if (error?.code !== "ERR_MODULE_NOT_FOUND" && error?.code !== "ERR_UNSUPPORTED_ESM_URL_SCHEME" &&
      error?.code !== "ERR_UNKNOWN_URL_SCHEME") throw error;
}
const implementation = hostRuntime
  ? await import("./tui-runtime.js")
  : await import("./tui-standalone.js");
export default implementation.default;
export const tui = implementation.default.tui;
export const setup = implementation.default.setup;
export const registerGuardianV1Commands = implementation.registerGuardianV1Commands;
export const registerGuardianV2Commands = implementation.registerGuardianV2Commands;
