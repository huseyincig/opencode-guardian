/** Dedicated TUI entrypoint: OpenCode 1 (tui / sidebar_content) and 2 (setup / sidebar.content). */
import type { Plugin } from "@opencode/plugin/tui";
import type { TuiPlugin, TuiPluginApi, TuiPluginModule } from "@opencode-ai/plugin/tui";
import { createSignal, onCleanup, Show } from "solid-js";
import { readFileSync } from "node:fs";
import type { RGBA } from "@opentui/core";
import { readGuardianStatus } from "./telemetry.js";
import { loadConfig, resolveEffectiveConfig } from "./engine.js";
import { announceGuardianUpdate, checkGuardianUpdate } from "./version-notice.js";
import {
  registerToastClearListener,
  registerToastListener,
  type GuardianToastPayload,
} from "./toast.js";
import {
  GUARDIAN_INTERVENTION_RPC_DEFINITION,
  GUARDIAN_INTERVENTION_RPC_METHOD,
  parseGuardianInterventionSnapshot,
} from "./intervention-rpc.js";
import { GUARDIAN_COMMANDS, guardianCommandReport, guardianResetReport,
  type GuardianCommand, type GuardianReport } from "./commands.js";

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

function GuardianConversationIntervention(props: {
  payload: GuardianToastPayload | undefined;
  colors: SidebarColors;
}) {
  const accent = () =>
    props.payload?.variant === "warning"
      ? props.colors.warning ?? props.colors.accent
      : props.colors.error ?? props.colors.accent;
  const label = () => {
    if (props.payload?.variant === "warning") return "GUARDIAN · WARNING";
    if (props.payload?.title.includes("Blocked")) return "GUARDIAN · BLOCKED";
    return "GUARDIAN · ERROR";
  };

  return (
    <Show when={props.payload}>
      <box
        width="100%"
        flexDirection="column"
        border={["left"]}
        borderColor={accent()}
        paddingLeft={1}
        marginBottom={1}
      >
        <text fg={accent()}><b>{label()}</b></text>
        <text fg={props.colors.text}>{props.payload?.message ?? ""}</text>
      </box>
    </Show>
  );
}

type GuardianV2Context = Parameters<Plugin.Definition["setup"]>[0];

function v2SessionDirectory(
  context: GuardianV2Context,
  sessionID: string,
  fallback: string
): string {
  return context.data.session.get(sessionID)?.location?.directory ??
    context.data.location.default()?.directory ??
    fallback;
}

function v2CommandDirectory(context: GuardianV2Context, fallback: string): string {
  const route = context.ui.router.current();
  if (route.type === "session") {
    return v2SessionDirectory(context, route.sessionID, fallback);
  }
  return context.data.location.default()?.directory ?? fallback;
}

async function v2PerformCommand(
  context: GuardianV2Context, command: GuardianCommand, directory: string
): Promise<void> {
  if (command === "reset") {
    const confirmed = await context.ui.dialog.confirm({
      title: "Guardian: Reset Statistics",
      message: "Reset this project's counters? The audit log is not wiped (normal rotation still applies). Configuration and protection are unchanged.",
      label: { confirm: "Reset counters", cancel: "Cancel" },
    });
    if (confirmed !== true) return;
    const result = guardianResetReport(directory);
    await context.ui.dialog.alert(result);
    return;
  }
  const result = await guardianCommandReport(command, directory, guardianVersion);
  await context.ui.dialog.alert(result);
}

/** Register in a host-owned Solid component: keymap.layer follows that owner's cleanup. */
export function registerGuardianV2Commands(
  context: GuardianV2Context, directory: () => string
): void {
  if (typeof context.keymap?.layer !== "function") return;
  const commands = GUARDIAN_COMMANDS.map((command) => ({
    id: "opencode-guardian." + command.id,
    title: command.title,
    description: command.description,
    group: "Guardian",
    palette: true as const,
    slash: { name: "guardian-" + command.id },
    run: () => v2PerformCommand(context, command.id, directory()),
  }));
  context.keymap.layer(() => ({
    mode: "global",
    commands: [...commands, {
      id: "opencode-guardian.dispatch",
      title: "Guardian: Commands",
      description: "Run /guardian status, activity, doctor, rules, config, version or reset",
      group: "Guardian",
      slash: { name: "guardian", arguments: true as const },
      run: async (raw?: string) => {
        const token = (raw ?? "").trim().toLowerCase()
          .replace(/^\/?guardian(?:\s+|$)/, "").split(/\s+/)[0];
        const requested = GUARDIAN_COMMANDS.find((item) => item.id === token);
        if (!requested) {
          await context.ui.dialog.alert({
            title: "Guardian: Commands",
            message: "Use /guardian status, activity, doctor, rules, config, version or reset.",
          });
          return;
        }
        await v2PerformCommand(context, requested.id, directory());
      },
    }],
  }));
}

function v1ShowReport(api: TuiPluginApi, report: GuardianReport,
  dialog: TuiPluginApi["ui"]["dialog"] = api.ui.dialog): void {
  dialog.setSize("large");
  dialog.replace(() => api.ui.DialogAlert(report));
}

/** V1 command.register is optional in the installed V1 1.18.34 contract. */
export function registerGuardianV1Commands(api: TuiPluginApi): void {
  if (typeof api.command?.register !== "function") return;
  const unregister = api.command.register(() => GUARDIAN_COMMANDS.map((command) => ({
    title: command.title,
    value: "opencode-guardian." + command.id,
    description: command.description,
    category: "Guardian",
    slash: { name: "guardian-" + command.id },
    onSelect: async (selected) => {
      const directory = api.state.path.directory;
      const dialog = selected ?? api.ui.dialog;
      if (command.id === "reset") {
        dialog.setSize("medium");
        dialog.replace(() => api.ui.DialogConfirm({
          title: "Guardian: Reset Statistics",
          message: "Reset this project's counters? The audit log is not wiped (normal rotation still applies). Protection stays active.",
          onConfirm: () => {
            dialog.clear();
            v1ShowReport(api, guardianResetReport(directory), dialog);
          },
          onCancel: () => dialog.clear(),
        }));
        return;
      }
      const report = await guardianCommandReport(command.id, directory, guardianVersion);
      v1ShowReport(api, report, dialog);
    },
  })));
  // The pinned V1 API owns plugin resources via its explicit lifecycle.
  api.lifecycle?.onDispose?.(unregister);
}

function GuardianSidebar(props: {
  colors: SidebarColors;
  directory?: string;
  currentDirectory?: () => string;
  checkUpdates?: boolean;
}) {
  const currentDirectory = () => props.currentDirectory?.() ?? props.directory ?? process.cwd();
  const [open, setOpen] = createSignal(false);
  const [status, setStatus] = createSignal(readGuardianStatus(currentDirectory()));
  const timer = setInterval(() => setStatus(readGuardianStatus(currentDirectory())), 2500);
  const updateController = new AbortController();
  let disposed = false;
  onCleanup(() => {
    clearInterval(timer);
    updateController.abort();
    disposed = true;
  });

  const [hasUpdate, setHasUpdate] = createSignal(false);
  const [latestVersion, setLatestVersion] = createSignal<string | undefined>(undefined);

  if (props.checkUpdates !== false) {
    checkGuardianUpdate({
      allowDevelopment: true,
      signal: updateController.signal,
    })
      .then((info) => {
        if (!disposed && info) {
          setHasUpdate(true);
          setLatestVersion(info.latest);
        }
      })
      .catch(() => {});
  }

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

  const statusLabel = () => {
    // Historical counters must not masquerade as the latest event.
    switch (status().lastKind) {
      case "inspection-error": return "▲ inspection error";
      case "preflight-blocked": return "● preflight blocked";
      case "post-remediation": return "● remediation sent";
      case "remediation-verified": return "● remediation verified";
      case "remediation-failed": return "▲ remediation failed";
      case "remediation-unverified": return "▲ remediation unverified";
      case "statistics-reset": return "○ statistics reset";
      case "verification-unavailable": return "▲ verification unavailable";
      case "post-warning": return "▲ warning";
      case "preflight-allowed": return "● allowed";
      case "runtime-started": return "● Active";
      default: return "○ Idle";
    }
  };

  const statusColor = () => {
    switch (status().lastKind) {
      case "inspection-error":
      case "preflight-blocked":
      case "remediation-failed": return errorColor();
      case "post-warning":
      case "remediation-unverified":
      case "verification-unavailable": return warningColor();
      case "post-remediation": return props.colors.accent;
      case "remediation-verified":
      case "preflight-allowed":
      case "runtime-started": return successColor();
      default: return props.colors.muted;
    }
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
      <Show when={hasUpdate() && latestVersion()}>
        <StatRow
          label="Update available"
          value={`v${latestVersion()}`}
          valueColor={successColor()}
          muted={props.colors.muted}
          text={props.colors.text}
        />
      </Show>
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
          label="Mode"
          value="Autonomous"
          valueColor={props.colors.accent}
          muted={props.colors.muted}
          text={props.colors.text}
        />
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
          value={status().blocked}
          valueColor={status().blocked > 0 ? errorColor() : props.colors.muted}
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
    const config = resolveEffectiveConfig(loadConfig(directory), context.options);
    if (config.enabled === false) return;
    const updateNoticeController = new AbortController();
    // The pinned V2 host owns setup-created layers and removes them on unload.
    registerGuardianV2Commands(context, () => v2CommandDirectory(context, directory));
    if (config.updateNotice?.enabled !== false && typeof context.ui.toast?.show === "function") {
      void announceGuardianUpdate((current, latest) => context.ui.toast.show({
        title: "OpenCode Guardian — New version", message: `v${current} → v${latest} (update manually)`, variant: "info", duration: 5000,
      }), { signal: updateNoticeController.signal });
    }
    const colors = (): SidebarColors => ({
      accent: context.theme.status?.success?.base ?? context.theme.text.base,
      onAccent: context.theme.text.action.primary.base,
      text: context.theme.text.base,
      muted: context.theme.text.muted,
      success: context.theme.status?.success?.base,
      warning: context.theme.status?.warning?.base,
      error: context.theme.status?.error?.base,
    });

    const [interventions, setInterventions] = createSignal<Record<string, GuardianToastPayload>>({});
    const rpcInFlight = new Set<string>();
    let rpcGeneration = 0;
    let disposed = false;

    const storeIntervention = (
      sessionID: string,
      payload: GuardianToastPayload | undefined
    ): void => {
      setInterventions((current) => {
        const next = { ...current };
        if (payload) next[sessionID] = payload;
        else delete next[sessionID];

        while (Object.keys(next).length > 32) {
          const oldest = Object.keys(next)[0];
          if (!oldest) break;
          delete next[oldest];
        }
        return next;
      });
    };

    const interventionRpc =
      typeof context.client?.rpc === "function"
        ? context.client.rpc(GUARDIAN_INTERVENTION_RPC_DEFINITION)
        : undefined;

    const refreshIntervention = async (sessionID: string): Promise<void> => {
      if (!interventionRpc || disposed || rpcInFlight.has(sessionID)) return;
      rpcInFlight.add(sessionID);
      const generation = rpcGeneration;
      const sessionLocation =
        context.data.session.get(sessionID)?.location ?? context.location;
      const requestedDirectory = sessionLocation?.directory;
      try {
        const raw = await interventionRpc[GUARDIAN_INTERVENTION_RPC_METHOD](
          { sessionID },
          sessionLocation ? { location: sessionLocation } : undefined
        );
        if (disposed || generation !== rpcGeneration) return;
        const currentDirectory =
          context.data.session.get(sessionID)?.location?.directory ??
          context.location?.directory;
        if (currentDirectory !== requestedDirectory) return;
        const snapshot = parseGuardianInterventionSnapshot(raw);
        if (!snapshot) return;
        storeIntervention(
          sessionID,
          snapshot.active
            ? {
                title: snapshot.title,
                message: snapshot.message,
                variant: snapshot.variant,
                duration: snapshot.duration,
              }
            : undefined
        );
      } catch {
        // Same-process toast bridge remains available when RPC is unavailable.
      } finally {
        rpcInFlight.delete(sessionID);
      }
    };

    let rpcPoll: ReturnType<typeof setInterval> | undefined;
    if (interventionRpc) {
      const refreshCurrentSession = () => {
        const route = context.ui.router.current();
        if (route.type === "session") {
          void refreshIntervention(route.sessionID);
        }
      };
      refreshCurrentSession();
      rpcPoll = setInterval(refreshCurrentSession, 500);
    }

    const ownsInterventionScope = (scope: {
      directory?: string | undefined;
      sessionID?: string | undefined;
    }): boolean => {
      if (!scope.sessionID) {
        return scope.directory === undefined || scope.directory === directory;
      }
      const session = context.data.session.get(scope.sessionID);
      if (!session) return false;
      const sessionDirectory = session.location?.directory ?? directory;
      return scope.directory === undefined || scope.directory === sessionDirectory;
    };

    const unregisterToast = registerToastListener((toast, scope) => {
      if (!ownsInterventionScope(scope)) return;
      if (scope.sessionID) {
        storeIntervention(scope.sessionID, toast);
      }
      const toastDirectory =
        scope.sessionID
          ? v2SessionDirectory(context, scope.sessionID, directory)
          : scope.directory ?? directory;
      const toastConfig = resolveEffectiveConfig(
        loadConfig(toastDirectory),
        context.options
      );
      if (
        toastConfig.notifications?.enabled !== false &&
        typeof context.ui.toast?.show === "function"
      ) {
        try {
          context.ui.toast.show({
            title: toast.title,
            message: toast.message,
            variant: toast.variant,
            duration: toast.duration,
            ...(scope.sessionID ? { sessionID: scope.sessionID } : {}),
          });
        } catch {}
      }
    });
    const unregisterToastClear = registerToastClearListener((scope) => {
      if (!ownsInterventionScope(scope)) return;
      if (scope.sessionID) {
        storeIntervention(scope.sessionID, undefined);
      }
    });

    // Main conversation column: visible Guardian interventions belong next to
    // the active chat, not only in the sidebar/toast layer.
    const conversationSlotDisposer = context.ui.slot({
      append: "session.composer.top",
      render: ({ sessionID }) => (
        <GuardianConversationIntervention
          payload={interventions()[sessionID]}
          colors={colors()}
        />
      ),
    });

    // Append: never override Magic Context, AFT, or built-in sidebar sections.
    const sidebarSlotDisposer = context.ui.slot({
      append: "sidebar.content",
      render: ({ sessionID }) => {
        const sessionDirectory = () =>
          v2SessionDirectory(context, sessionID, directory);
        const sessionConfig = () =>
          resolveEffectiveConfig(loadConfig(sessionDirectory()), context.options);
        return <GuardianSidebar directory={directory}
          currentDirectory={sessionDirectory}
          checkUpdates={sessionConfig().updateNotice?.enabled !== false}
          colors={colors()} />;
      },
    });

    return () => {
      disposed = true;
      rpcGeneration += 1;
      rpcInFlight.clear();
      updateNoticeController.abort();
      if (rpcPoll) clearInterval(rpcPoll);
      try { unregisterToast?.(); } catch {}
      try { unregisterToastClear?.(); } catch {}
      try { conversationSlotDisposer?.(); } catch {}
      try { sidebarSlotDisposer?.(); } catch {}
    };
  },
};

/** Use V1's actual SDK contract; V1 slot IDs are host-managed, not disposers. */
const v1Tui: TuiPlugin = async (api: TuiPluginApi, pluginOptions) => {
  const directory = api.state.path.directory;
  const config = resolveEffectiveConfig(loadConfig(directory), pluginOptions);
  if (config.enabled === false) return;
  registerGuardianV1Commands(api);
  if (config.notifications?.enabled !== false && typeof api.ui?.toast === "function") {
    const unregisterToast = registerToastListener((toast) => {
      try {
        api.ui.toast({
          title: toast.title,
          message: toast.message,
          variant: toast.variant,
          duration: toast.duration,
        });
      } catch {}
    }, { directory });
    api.lifecycle?.onDispose?.(unregisterToast);
  }
  api.slots.register({
    order: 600,
    slots: {
      sidebar_content(_context, _props) {
        return <GuardianSidebar directory={directory}
          currentDirectory={() => api.state.path.directory}
          checkUpdates={config.updateNotice?.enabled !== false} colors={{
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
