/** Dedicated TUI entrypoint: OpenCode V2 (setup / sidebar.content & session.composer.top). */
import type { Plugin } from "@opencode/plugin/tui";
type GuardianV2Context = Parameters<Plugin.Definition["setup"]>[0];
/** Register Guardian keymap layer and slash commands; host cleans up setup-created layers on unload. */
export declare function registerGuardianV2Commands(context: GuardianV2Context, directory: () => string, onReset?: (directory: string) => void): void;
declare const guardianTui: Plugin.Definition;
export default guardianTui;
