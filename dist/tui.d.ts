/** Dedicated TUI entrypoint: OpenCode 1 (tui / sidebar_content) and 2 (setup / sidebar.content). */
import type { Plugin } from "@opencode/plugin/tui";
import type { TuiPluginApi, TuiPluginModule } from "@opencode-ai/plugin/tui";
type GuardianV2Context = Parameters<Plugin.Definition["setup"]>[0];
/** Register in a host-owned Solid component: keymap.layer follows that owner's cleanup. */
export declare function registerGuardianV2Commands(context: GuardianV2Context, directory: () => string): void;
/** V1 command.register is optional in the installed V1 1.18.34 contract. */
export declare function registerGuardianV1Commands(api: TuiPluginApi): void;
declare const guardianTui: TuiPluginModule & Plugin.Definition;
export default guardianTui;
