/** Dedicated TUI entrypoint: OpenCode 1 (tui / sidebar_content) and 2 (setup / sidebar.content). */
import type { Plugin } from "@opencode/plugin/tui";
import type { TuiPlugin, TuiPluginApi, TuiPluginModule } from "@opencode-ai/plugin/tui";
import { createSignal, onCleanup, Show } from "solid-js";
import { readFileSync } from "node:fs";
import type { RGBA } from "@opentui/core";
import { readGuardianStatus } from "./telemetry.js";
import { loadConfig } from "./engine.js";
import { announceGuardianUpdate, checkGuardianUpdate } from "./version-notice.js";

const guardianVersion = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;

type SidebarColors = {
  accent: RGBA;
  onAccent: RGBA;
  text: RGBA;
  muted: RGBA;
  success?: RGBA;
  warning?: RGBA;
  error?: RGBA;
};

function StatRow(props: {
  label: string;
  value: string | number;
  valueColor?: RGBA;
  muted: RGBA;
  text: RGBA;
}) {
  return (
    <box width="100%" flexDirection="row" justifyContent="space-between">
      <text fg={props.muted} flexShrink={0}>{props.label}</text>
      <text fg={props.valueColor ?? props.text} flexShrink={1} marginLeft={1}>
        <b>{props.value}</b>
      </text>
    </box>
  );
}

function GuardianSidebar(props: { colors: SidebarColors; directory?: string }) {
  const [open, setOpen] = createSignal(false);
  const [status, setStatus] = createSignal(readGuardianStatus(props.directory));
  const timer = setInterval(() => setStatus(readGuardianStatus(props.directory)), 2500);
  let disposed = false;
  onCleanup(() => {
    clearInterval(timer);
    disposed = true;
  });

  const [hasUpdate, setHasUpdate] = createSignal(false);
  const [latestVersion, setLatestVersion] = createSignal<string | undefined>(undefined);

  checkGuardianUpdate({ allowDevelopment: true })
    .then((info) => {
      if (!disposed && info) {
        setHasUpdate(true);
        setLatestVersion(info.latest);
      }
    })
    .catch(() => {});

  const successColor = () => props.colors.success ?? props.colors.accent;
  const warningColor = () => props.colors.warning ?? props.colors.accent;
  const errorColor = () => props.colors.error ?? props.colors.accent;

  const preflightLabel = () => {
    const pf = status().preflight;
    if (pf === "active") return "● active";
    if (pf === "disabled") return "○ disabled";
    if (pf === "unavailable") return "▲ unavailable";
    return "—";
  };

  const preflightColor = () => {
    const pf = status().preflight;
    if (pf === "active") return successColor();
    if (pf === "unavailable") return warningColor();
    return props.colors.muted;
  };

  const totalBlocked = () => status().blocked + status().remediations;

  const statusLabel = () => {
    if (totalBlocked() > 0) return `● ${totalBlocked()} blocked`;
    if (status().warnings > 0) return `● ${status().warnings} warn`;
    if (status().errors > 0) return `● ${status().errors} err`;
    if (!status().lastEvent && status().preflight === "unknown") return "○ Idle";
    return "● Active";
  };

  const statusColor = () => {
    if (totalBlocked() > 0) return errorColor();
    if (status().warnings > 0) return warningColor();
    if (status().errors > 0) return errorColor();
    if (!status().lastEvent && status().preflight === "unknown") return props.colors.muted;
    return successColor();
  };

  return (
    <box width="100%" flexDirection="column" gap={0}>
      <box
        width="100%"
        flexDirection="row"
        justifyContent="space-between"
        alignItems="center"
        onMouseDown={() => setOpen((value) => !value)}
      >
        <box flexDirection="row" alignItems="center">
          <text fg={props.colors.muted}>{() => open() ? "▼ " : "▶ "}</text>
          <text fg={props.colors.text}><b>Guardian</b></text>
        </box>
        <box flexDirection="row" alignItems="center">
          <text fg={props.colors.muted}>{"v" + guardianVersion}</text>
          <Show when={hasUpdate()}>
            <text fg={successColor()}><b> (↑)</b></text>
          </Show>
        </box>
      </box>
      <Show when={!open()}>
        <StatRow
          label="Status"
          value={statusLabel()}
          valueColor={statusColor()}
          muted={props.colors.muted}
          text={props.colors.text}
        />
        <StatRow
          label="Interventions"
          value={`${status().warnings}w · ${status().remediations}r`}
          muted={props.colors.muted}
          text={props.colors.text}
        />
      </Show>
      <Show when={open()}>
        <StatRow
          label="Preflight"
          value={preflightLabel()}
          valueColor={preflightColor()}
          muted={props.colors.muted}
          text={props.colors.text}
        />
        <StatRow
          label="Inspected"
          value={status().inspected}
          muted={props.colors.muted}
          text={props.colors.text}
        />
        <StatRow
          label="Blocked"
          value={totalBlocked()}
          valueColor={totalBlocked() > 0 ? errorColor() : props.colors.muted}
          muted={props.colors.muted}
          text={props.colors.text}
        />
        <StatRow
          label="Warnings"
          value={status().warnings}
          valueColor={status().warnings > 0 ? warningColor() : props.colors.muted}
          muted={props.colors.muted}
          text={props.colors.text}
        />
        <StatRow
          label="Remediations"
          value={status().remediations}
          valueColor={status().remediations > 0 ? props.colors.accent : props.colors.muted}
          muted={props.colors.muted}
          text={props.colors.text}
        />
        <Show when={hasUpdate() && latestVersion()}>
          <StatRow
            label="Update"
            value={`v${latestVersion()}`}
            valueColor={successColor()}
            muted={props.colors.muted}
            text={props.colors.text}
          />
        </Show>
        <Show when={status().errors > 0}>
          <StatRow
            label="Errors"
            value={status().errors}
            valueColor={errorColor()}
            muted={props.colors.muted}
            text={props.colors.text}
          />
        </Show>
        <Show when={status().truncated}>
          <box width="100%" flexDirection="row" justifyContent="space-between">
            <text fg={props.colors.muted}>Log</text>
            <text fg={props.colors.muted}>recent window</text>
          </box>
        </Show>
      </Show>
    </box>
  );
}

const v2Plugin: Plugin.Definition = {
  id: "opencode-guardian.tui",
  setup(context) {
    const directory = context.location?.directory ?? process.cwd();
    const config = loadConfig(directory);
    if (config.enabled === false) return;
    if (config.updateNotice?.enabled !== false && typeof context.ui.toast?.show === "function") {
      void announceGuardianUpdate((current, latest) => context.ui.toast.show({
        title: "OpenCode Guardian — New version", message: `v${current} → v${latest} (update manually)`, variant: "info", duration: 5000,
      }));
    }
    // Append: never override Magic Context, AFT, or built-in sidebar sections.
    return context.ui.slot({
      append: "sidebar.content",
      render: () => <GuardianSidebar directory={directory} colors={{
        accent: context.theme.status?.success?.base ?? context.theme.text.base,
        onAccent: context.theme.text.action.primary.base,
        text: context.theme.text.base,
        muted: context.theme.text.muted,
        success: context.theme.status?.success?.base,
        warning: context.theme.status?.warning?.base,
        error: context.theme.status?.error?.base,
      }} />,
    });
  },
};

/** Use V1's actual SDK contract; V1 slot IDs are host-managed, not disposers. */
const v1Tui: TuiPlugin = async (api: TuiPluginApi) => {
  const directory = api.state.path.directory;
  const config = loadConfig(directory);
  if (config.enabled === false) return;
  api.slots.register({
    order: 600,
    slots: {
      sidebar_content(_context, _props) {
        return <GuardianSidebar directory={directory} colors={{
          accent: api.theme.current.primary,
          onAccent: api.theme.current.background,
          text: api.theme.current.text,
          muted: api.theme.current.textMuted,
          success: api.theme.current.success,
          warning: api.theme.current.warning,
          error: api.theme.current.error,
        }} />;
      },
    },
  });
};

const guardianTui: TuiPluginModule & Plugin.Definition = {
  ...v2Plugin,
  tui: v1Tui,
};

export default guardianTui;
