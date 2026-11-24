/** Dedicated TUI entrypoint: OpenCode V2 (setup / sidebar.content & session.composer.top). */
import type { Plugin } from "@opencode/plugin/tui";
import { createEffect, createSignal, onCleanup, Show } from "solid-js";
import { readFileSync } from "node:fs";
import type { RGBA } from "@opentui/core";
import { readGuardianStatus } from "./telemetry.js";
import { loadConfig, resolveEffectiveConfig } from "./engine.js";
import { announceGuardianUpdate, checkGuardianUpdate } from "./version-notice.js";
import {
  dispatchGuardianToastClear,
  registerToastClearListener,
  registerToastListener,
  type GuardianToastPayload,
} from "./toast.js";
import {
  GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD,
  GUARDIAN_INTERVENTION_RPC_DEFINITION,
  GUARDIAN_INTERVENTION_RPC_METHOD,
  parseGuardianInterventionSnapshot,
} from "./intervention-rpc.js";
import { GUARDIAN_COMMANDS, guardianCommandReport, guardianResetReport,
  type GuardianCommand } from "./commands.js";

const guardianVersion = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;

type SidebarColor = string | RGBA;

type SidebarColors = {
  accent: SidebarColor;
  onAccent: SidebarColor;
  background: SidebarColor;
  text: SidebarColor;
  muted: SidebarColor;
  success?: SidebarColor;
  warning?: SidebarColor;
  error?: SidebarColor;
};

function StatRow(props: {
  label: string;
  value: string | number;
  valueColor?: SidebarColor;
  muted: SidebarColor;
  text: SidebarColor;
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
  onDismiss?: () => void;
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
        onMouseDown={() => props.onDismiss?.()}
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
  sessionID: string | undefined,
  fallback: string
): string {
  return (sessionID ? context.data?.session?.get?.(sessionID)?.location?.directory : undefined) ??
    context.data?.location?.default?.()?.directory ??
    fallback;
}

function v2CommandDirectory(context: GuardianV2Context, fallback: string): string {
  const route = context.ui?.router?.current?.();
  if (route?.type === "session") {
    return v2SessionDirectory(context, route.sessionID, fallback);
  }
  return context.data?.location?.default?.()?.directory ?? fallback;
}

/** A broken project config must not reject the host's UI render callback. */
function v2UiConfig(directory: string, options: unknown) {
  try { return resolveEffectiveConfig(loadConfig(directory), options); } catch {
    return { enabled: false, notifications: { enabled: false }, updateNotice: { enabled: false } };
  }
}

async function v2PerformCommand(
  context: GuardianV2Context, command: GuardianCommand, directory: string,
  onReset?: (directory: string) => void
): Promise<void> {
  if (command === "reset") {
    const confirmed = await context.ui.dialog.confirm({
      title: "Guardian: Reset Statistics",
      message: "Reset this project's counters? The audit log is not wiped (normal rotation still applies). Configuration and protection are unchanged.",
      label: { confirm: "Reset counters", cancel: "Cancel" },
    });
    if (confirmed !== true) return;
    const result = guardianResetReport(directory);
    if (onReset) {
      onReset(directory);
    } else {
      dispatchGuardianToastClear({ directory });
    }
    await context.ui.dialog.alert(result);
    return;
  }
  const result = await guardianCommandReport(command, directory, guardianVersion, context.options);
  await context.ui.dialog.alert(result);
}

/** Register Guardian keymap layer and slash commands; host cleans up setup-created layers on unload. */
export function registerGuardianV2Commands(
  context: GuardianV2Context, directory: () => string,
  onReset?: (directory: string) => void
): void {
  if (typeof context.keymap?.layer !== "function") return;
  const commands = GUARDIAN_COMMANDS.map((command) => ({
    id: "opencode-guardian." + command.id,
    title: command.title,
    description: command.description,
    group: "Guardian",
    palette: true as const,
    slash: { name: "guardian-" + command.id },
    run: () => v2PerformCommand(context, command.id, directory(), onReset),
  }));
  try {
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
          await v2PerformCommand(context, requested.id, directory(), onReset);
        },
      }],
    }));
  } catch {
    // Host keymap layer validation failure must not crash TUI setup.
  }
}

function guardianStatusEqual(
  a: ReturnType<typeof readGuardianStatus>,
  b: ReturnType<typeof readGuardianStatus>
): boolean {
  return (
    a.preflight === b.preflight &&
    a.inspected === b.inspected &&
    a.blocked === b.blocked &&
    a.warnings === b.warnings &&
    a.remediations === b.remediations &&
    a.errors === b.errors &&
    a.verified === b.verified &&
    a.failed === b.failed &&
    a.unverified === b.unverified &&
    a.streamStops === b.streamStops &&
    a.streamVerified === b.streamVerified &&
    a.streamIneffective === b.streamIneffective &&
    a.redacted === b.redacted &&
    a.telemetryLevel === b.telemetryLevel &&
    a.truncated === b.truncated &&
    a.lastEvent === b.lastEvent &&
    a.lastKind === b.lastKind
  );
}

function GuardianSidebar(props: {
  colors: SidebarColors;
  directory?: string;
  currentDirectory?: () => string;
  refreshVersion?: () => number;
  checkUpdates?: boolean;
}) {
  const currentDirectory = () => props.currentDirectory?.() ?? props.directory ?? process.cwd();
  const [open, setOpen] = createSignal(false);
  const [status, setStatus] = createSignal(readGuardianStatus(currentDirectory()));
  const syncStatus = (dir: string) => {
    const next = readGuardianStatus(dir);
    setStatus((prev) => (guardianStatusEqual(prev, next) ? prev : next));
  };
  createEffect(() => {
    const dir = currentDirectory();
    props.refreshVersion?.();
    syncStatus(dir);
  });
  const timer = setInterval(() => syncStatus(currentDirectory()), 5000);
  (timer as { unref?: () => void }).unref?.();
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
    if (pf === "unavailable") return "! unavailable";
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
      case "stream-interrupt-requested": return "! stream stop";
      case "stream-interrupt-verified": return "✓ stream stopped";
      case "stream-interrupt-ineffective": return "✕ stream not stopped";
      case "inspection-error": return "✕ inspection error";
      case "preflight-blocked": return "⊘ preflight blocked";
      case "post-remediation": return "↻ remediation sent";
      case "remediation-verified": return "✓ verified";
      case "remediation-failed": return "✕ remediation failed";
      case "remediation-unverified": return "! unverified";
      case "statistics-reset": return "○ reset";
      case "verification-unavailable": return "! verification off";
      case "post-warning": return "! warning";
      case "preflight-allowed": return "● allowed";
      case "post-inspected": return "● inspected";
      case "runtime-started": return "● Active";
      default: return "○ Idle";
    }
  };

  const statusColor = () => {
    switch (status().lastKind) {
      case "inspection-error":
      case "preflight-blocked":
      case "stream-interrupt-ineffective":
      case "remediation-failed": return errorColor();
      case "stream-interrupt-requested":
      case "post-warning":
      case "remediation-unverified":
      case "verification-unavailable": return warningColor();
      case "post-remediation": return props.colors.accent;
      case "remediation-verified":
      case "stream-interrupt-verified":
      case "preflight-allowed":
      case "post-inspected":
      case "runtime-started": return successColor();
      default: return props.colors.muted;
    }
  };

  return (
    <box width="100%" flexDirection="column" gap={0}>
      <box
        width="100%"
        flexDirection="row"
        onMouseDown={() => setOpen((value) => !value)}
      >
        <text fg={props.colors.muted}>{() => open() ? "▼ " : "▶ "}</text>
        <box backgroundColor={props.colors.accent} paddingLeft={1} paddingRight={1}>
          <text fg={props.colors.background}>guardian</text>
        </box>
        <text fg={props.colors.muted}>{" v" + guardianVersion}</text>
        <text fg={statusColor()} flexShrink={1} truncate wrapMode="none">
          {` · ${statusLabel()}`}
        </text>
        <Show when={hasUpdate()}>
          <text fg={successColor()} flexShrink={0} wrapMode="none">
            {latestVersion() ? ` (↑${latestVersion()})` : " (↑)"}
          </text>
        </Show>
      </box>
      <Show when={hasUpdate() && latestVersion()}>
        <box width="100%" flexDirection="column" paddingLeft={1}>
          <StatRow
            label="Update available"
            value={`v${latestVersion()}`}
            valueColor={successColor()}
            muted={props.colors.muted}
            text={props.colors.text}
          />
        </box>
      </Show>
      <Show when={!open()}>
        <box width="100%" flexDirection="column" paddingLeft={1}>
          <StatRow
            label="Status"
            value={statusLabel()}
            valueColor={statusColor()}
            muted={props.colors.muted}
            text={props.colors.text}
          />
          <StatRow
            label="Interventions"
            value={`${status().warnings}w · ${status().remediations}r${status().streamStops > 0 ? ` · ${status().streamStops}s` : ""}`}
            muted={props.colors.muted}
            text={props.colors.text}
          />
        </box>
      </Show>
      <Show when={open()}>
        <box width="100%" flexDirection="column" paddingLeft={1}>
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
            label="Tool Blocks"
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
          <Show when={status().streamStops > 0}>
            <StatRow
              label="Stream Stops"
              value={`${status().streamStops} (${status().streamVerified}✓ ${status().streamIneffective}✗)`}
              valueColor={status().streamIneffective > 0 ? errorColor() : warningColor()}
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
        </box>
      </Show>
    </box>
  );
}

const v2Plugin: Plugin.Definition = {
  id: "opencode-guardian.tui",
  setup(context) {
    const directory = context.location?.directory ?? process.cwd();
    let config: ReturnType<typeof resolveEffectiveConfig>;
    try {
      config = resolveEffectiveConfig(loadConfig(directory), context.options);
    } catch {
      config = { enabled: true, notifications: { enabled: false }, updateNotice: { enabled: false } } as ReturnType<typeof resolveEffectiveConfig>;
    }
    if (config.enabled === false) return;
    const updateNoticeController = new AbortController();
    // The pinned V2 host owns setup-created layers and removes them on unload.
    let clearOnReset: ((targetDirectory: string) => void) | undefined;
    registerGuardianV2Commands(context, () => v2CommandDirectory(context, directory), (dir) => clearOnReset?.(dir));
    if (config.updateNotice?.enabled !== false && typeof context.ui.toast?.show === "function") {
      void announceGuardianUpdate((current, latest) => context.ui.toast.show({
        title: "OpenCode Guardian — New version", message: `v${current} → v${latest} (update manually)`, variant: "info", duration: 5000,
      }), { signal: updateNoticeController.signal });
    }
    const colors = (): SidebarColors => ({
      accent: context.theme?.status?.success?.base ?? context.theme?.text?.base ?? "green",
      onAccent: context.theme?.text?.action?.primary?.base ?? context.theme?.text?.base ?? "white",
      background:
        (context.theme as { background?: { base?: SidebarColor; panel?: SidebarColor } } | undefined)
          ?.background?.base ??
        (context.theme as { background?: { base?: SidebarColor; panel?: SidebarColor } } | undefined)
          ?.background?.panel ??
        "black",
      text: context.theme?.text?.base ?? "white",
      muted: context.theme?.text?.muted ?? context.theme?.text?.base ?? "gray",
      success: context.theme?.status?.success?.base,
      warning: context.theme?.status?.warning?.base,
      error: context.theme?.status?.error?.base,
    });

    const [interventions, setInterventions] = createSignal<Record<string, GuardianToastPayload>>({});
    const [sidebarVersion, setSidebarVersion] = createSignal(0);
    const rpcInFlight = new Set<string>();
    const interventionTimers = new Map<string, ReturnType<typeof setTimeout>>();
    const dismissedInterventionSignatures = new Map<string, string>();
    let rpcGeneration = 0;
    let disposed = false;

    const payloadSignature = (payload: GuardianToastPayload): string =>
      `${payload.variant}\0${payload.title}\0${payload.message}`;

    const rememberDismissedSignature = (sessionID: string, sig: string): void => {
      dismissedInterventionSignatures.delete(sessionID);
      dismissedInterventionSignatures.set(sessionID, sig);
      while (dismissedInterventionSignatures.size > 64) {
        const oldest = dismissedInterventionSignatures.keys().next().value;
        if (!oldest) break;
        dismissedInterventionSignatures.delete(oldest);
      }
    };

    const clearInterventionTimer = (sessionID: string): void => {
      const existing = interventionTimers.get(sessionID);
      if (existing !== undefined) {
        clearTimeout(existing);
        interventionTimers.delete(sessionID);
      }
    };

    const storeIntervention = (
      sessionID: string,
      payload: GuardianToastPayload | undefined,
      options?: { fromPoll?: boolean; markDismissed?: boolean }
    ): void => {
      const existingPayload = interventions()[sessionID];
      if (payload) {
        const sig = payloadSignature(payload);
        if (options?.fromPoll && dismissedInterventionSignatures.get(sessionID) === sig) {
          return;
        }
        if (!options?.fromPoll && dismissedInterventionSignatures.get(sessionID) === sig) {
          dismissedInterventionSignatures.delete(sessionID);
        }
        if (
          options?.fromPoll &&
          existingPayload &&
          payloadSignature(existingPayload) === sig &&
          interventionTimers.has(sessionID)
        ) {
          return;
        }
      } else {
        if (options?.markDismissed && existingPayload) {
          rememberDismissedSignature(sessionID, payloadSignature(existingPayload));
        }
        if (!existingPayload) {
          clearInterventionTimer(sessionID);
          return;
        }
      }

      clearInterventionTimer(sessionID);
      if (payload && !disposed) {
        const ttlMs = payload.duration > 0 ? payload.duration : 5000;
        const sig = payloadSignature(payload);
        const timer = setTimeout(() => {
          interventionTimers.delete(sessionID);
          rememberDismissedSignature(sessionID, sig);
          storeIntervention(sessionID, undefined);
        }, ttlMs);
        (timer as { unref?: () => void }).unref?.();
        interventionTimers.set(sessionID, timer);
      }
      setInterventions((current) => {
        const next = { ...current };
        if (payload) next[sessionID] = payload;
        else delete next[sessionID];

        while (Object.keys(next).length > 32) {
          const oldest = Object.keys(next)[0];
          if (!oldest) break;
          clearInterventionTimer(oldest);
          delete next[oldest];
        }
        return next;
      });
      if (payload) {
        setSidebarVersion((v) => v + 1);
      }
    };

    const interventionRpc =
      typeof context.client?.rpc === "function"
        ? context.client.rpc(GUARDIAN_INTERVENTION_RPC_DEFINITION)
        : undefined;
    const INTERVENTION_RPC_TIMEOUT_MS = 1500;

    const refreshIntervention = async (sessionID: string): Promise<void> => {
      if (!interventionRpc || disposed || rpcInFlight.has(sessionID)) return;
      rpcInFlight.add(sessionID);
      const generation = rpcGeneration;
      const sessionLocation =
        context.data?.session?.get?.(sessionID)?.location ?? context.location;
      const requestedDirectory = sessionLocation?.directory;
      let timeoutTimer: ReturnType<typeof setTimeout> | undefined;
      try {
        const rpcCall = Promise.resolve().then(() =>
          interventionRpc[GUARDIAN_INTERVENTION_RPC_METHOD](
            { sessionID },
            sessionLocation ? { location: sessionLocation } : undefined
          )
        );
        rpcCall.catch(() => {});
        const raw = await Promise.race([
          rpcCall,
          new Promise<undefined>((resolve) => {
            timeoutTimer = setTimeout(() => resolve(undefined), INTERVENTION_RPC_TIMEOUT_MS);
            (timeoutTimer as { unref?: () => void }).unref?.();
          }),
        ]);
        if (raw === undefined || disposed || generation !== rpcGeneration) return;
        const currentSession = context.data?.session?.get?.(sessionID);
        if (!currentSession) return;
        const currentDirectory =
          currentSession.location?.directory ??
          context.location?.directory;
        if (currentDirectory !== requestedDirectory) return;
        const snapshot = parseGuardianInterventionSnapshot(raw);
        if (!snapshot) return;
        if (!snapshot.active) {
          dismissedInterventionSignatures.delete(sessionID);
        }
        storeIntervention(
          sessionID,
          snapshot.active
            ? {
                title: snapshot.title,
                message: snapshot.message,
                variant: snapshot.variant,
                duration: snapshot.duration,
              }
            : undefined,
          { fromPoll: true }
        );
      } catch {
        // Same-process toast bridge remains available when RPC is unavailable.
      } finally {
        if (timeoutTimer !== undefined) clearTimeout(timeoutTimer);
        rpcInFlight.delete(sessionID);
      }
    };

    clearOnReset = (targetDirectory: string): void => {
      rpcGeneration += 1;
      setSidebarVersion((v) => v + 1);
      const route = context.ui?.router?.current?.();
      if (route?.type === "session") {
        storeIntervention(route.sessionID, undefined, { markDismissed: true });
        dispatchGuardianToastClear({ directory: targetDirectory, sessionID: route.sessionID });
      }
      for (const sessionID of Object.keys(interventions())) {
        if (v2SessionDirectory(context, sessionID, directory) === targetDirectory) {
          storeIntervention(sessionID, undefined, { markDismissed: true });
        }
      }
      dispatchGuardianToastClear({ directory: targetDirectory });
      if (interventionRpc && typeof interventionRpc[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD] === "function") {
        void interventionRpc[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD](
          { directory: targetDirectory },
          { location: { directory: targetDirectory } }
        ).catch(() => {});
      }
    };
    const ACTIVE_RPC_POLL_MS = 500;
    const IDLE_RPC_POLL_MS = 5000;
    let rpcPollTimer: ReturnType<typeof setTimeout> | undefined;
    const nextRpcPollMs = (): number => {
      const route = context.ui?.router?.current?.();
      if (route?.type !== "session") return IDLE_RPC_POLL_MS;
      if (interventions()[route.sessionID]) return ACTIVE_RPC_POLL_MS;
      const statusFn = context.data?.session?.status;
      if (typeof statusFn === "function") {
        try {
          if (statusFn(route.sessionID) === "idle") return IDLE_RPC_POLL_MS;
        } catch {}
      }
      return ACTIVE_RPC_POLL_MS;
    };
    const refreshCurrentSession = () => {
      const route = context.ui?.router?.current?.();
      if (route?.type === "session") {
        void refreshIntervention(route.sessionID);
      }
    };
    const scheduleRpcPoll = () => {
      if (!interventionRpc || disposed) return;
      if (rpcPollTimer !== undefined) {
        clearTimeout(rpcPollTimer);
        rpcPollTimer = undefined;
      }
      rpcPollTimer = setTimeout(() => {
        rpcPollTimer = undefined;
        if (disposed) return;
        refreshCurrentSession();
        scheduleRpcPoll();
      }, nextRpcPollMs());
      (rpcPollTimer as { unref?: () => void }).unref?.();
    };
    if (interventionRpc) {
      refreshCurrentSession();
      scheduleRpcPoll();
    }

    const ownsInterventionScope = (scope: {
      directory?: string | undefined;
      sessionID?: string | undefined;
    }): boolean => {
      if (!scope.sessionID) {
        return true;
      }
      const session = context.data?.session?.get?.(scope.sessionID);
      if (!session) {
        return scope.directory !== undefined && scope.directory === directory;
      }
      const sessionDirectory = session.location?.directory ?? directory;
      return scope.directory === undefined || scope.directory === sessionDirectory;
    };

    const unregisterToast = registerToastListener((toast, scope) => {
      if (!ownsInterventionScope(scope)) return;
      rpcGeneration += 1;
      if (scope.sessionID) {
        storeIntervention(scope.sessionID, toast);
      }
      const toastDirectory =
        scope.sessionID
          ? v2SessionDirectory(context, scope.sessionID, directory)
          : scope.directory ?? directory;
      const toastConfig = v2UiConfig(toastDirectory, context.options);
      if (
        toastConfig.enabled !== false && toastConfig.notifications?.enabled !== false &&
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
      rpcGeneration += 1;
      setSidebarVersion((v) => v + 1);
      if (scope.sessionID) {
        storeIntervention(scope.sessionID, undefined, { markDismissed: true });
      } else {
        const targetDir = scope.directory ?? directory;
        for (const sessionID of Object.keys(interventions())) {
          if (v2SessionDirectory(context, sessionID, directory) === targetDir) {
            storeIntervention(sessionID, undefined, { markDismissed: true });
          }
        }
      }
    });
    const extractTuiEventSessionID = (event: unknown): string | undefined => {
      const ev = event as {
        sessionID?: string;
        data?: { sessionID?: string; id?: string; info?: { id?: string } };
        properties?: { sessionID?: string; id?: string; info?: { id?: string } };
      } | undefined;
      return (
        ev?.data?.sessionID ??
        ev?.data?.info?.id ??
        ev?.data?.id ??
        ev?.properties?.sessionID ??
        ev?.properties?.info?.id ??
        ev?.properties?.id ??
        ev?.sessionID
      );
    };
    const unregisterSessionDelete = typeof context.data?.on === "function"
      ? context.data.on("session.deleted", (event) => {
          const sid = extractTuiEventSessionID(event);
          rpcGeneration += 1;
          if (sid) {
            dismissedInterventionSignatures.delete(sid);
            storeIntervention(sid, undefined);
            rpcInFlight.delete(sid);
          }
        })
      : undefined;
    const unregisterSessionMoved = typeof context.data?.on === "function"
      ? context.data.on("session.moved", (event) => {
          const sid = extractTuiEventSessionID(event);
          rpcGeneration += 1;
          if (sid) {
            dismissedInterventionSignatures.delete(sid);
            storeIntervention(sid, undefined);
            rpcInFlight.delete(sid);
          }
          setSidebarVersion((v) => v + 1);
        })
      : undefined;
    const handleHostRefresh = (): void => {
      rpcGeneration += 1;
      rpcInFlight.clear();
      setSidebarVersion((v) => v + 1);
      const route = context.ui?.router?.current?.();
      if (route?.type === "session") {
        void refreshIntervention(route.sessionID);
      }
    };
    const handleSessionActivity = (event: unknown): void => {
      const sid = extractTuiEventSessionID(event);
      const route = context.ui?.router?.current?.();
      setSidebarVersion((v) => v + 1);
      if (route?.type === "session" && (!sid || sid === route.sessionID)) {
        void refreshIntervention(route.sessionID);
      }
      scheduleRpcPoll();
    };
    let unregisterSessionStatus: (() => void) | undefined;
    let unregisterSessionIdle: (() => void) | undefined;
    let unregisterPluginUpdated: (() => void) | undefined;
    let unregisterConfigUpdated: (() => void) | undefined;
    if (typeof context.data?.on === "function") {
      try {
        unregisterSessionStatus = context.data.on("session.status", handleSessionActivity);
      } catch {
        // Optional reactive session status event for adaptive polling.
      }
      try {
        unregisterSessionIdle = context.data.on("session.idle", handleSessionActivity);
      } catch {
        // Optional reactive session idle event for adaptive polling.
      }
      try {
        unregisterPluginUpdated = context.data.on("plugin.updated", handleHostRefresh);
      } catch {
        // Optional v2.4.x non-blocking startup / hot-reload refresh event.
      }
      try {
        unregisterConfigUpdated = context.data.on("config.updated", handleHostRefresh);
      } catch {
        // Optional config reload refresh event.
      }
    }

    // Main conversation column: visible Guardian interventions belong next to
    // the active chat, not only in the sidebar/toast layer.
    const conversationSlotDisposer = context.ui.slot({
      append: "session.composer.top",
      render: (props) => (
        <GuardianConversationIntervention
          payload={props.sessionID && context.data?.session?.get?.(props.sessionID) ? interventions()[props.sessionID] : undefined}
          colors={colors()}
          onDismiss={() => {
            if (!props.sessionID) return;
            rpcGeneration += 1;
            const sessionDir = v2SessionDirectory(context, props.sessionID, directory);
            storeIntervention(props.sessionID, undefined, { markDismissed: true });
            dispatchGuardianToastClear({ directory: sessionDir, sessionID: props.sessionID });
            if (interventionRpc && typeof interventionRpc[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD] === "function") {
              const sessionLocation = context.data?.session?.get?.(props.sessionID)?.location ?? context.location;
              void interventionRpc[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD](
                { sessionID: props.sessionID },
                sessionLocation ? { location: sessionLocation } : undefined
              ).catch(() => {});
            }
          }}
        />
      ),
    });

    // Append: never override Magic Context, AFT, or built-in sidebar sections.
    const sidebarSlotDisposer = context.ui.slot({
      append: "sidebar.content",
      render: (props) => {
        const sessionDirectory = () =>
          v2SessionDirectory(context, props.sessionID, directory);
        const sessionConfig = () =>
          v2UiConfig(sessionDirectory(), context.options);
        return <GuardianSidebar directory={directory}
          currentDirectory={sessionDirectory}
          refreshVersion={sidebarVersion}
          checkUpdates={sessionConfig().updateNotice?.enabled !== false}
          colors={colors()} />;
      },
    });

    return () => {
      disposed = true;
      rpcGeneration += 1;
      rpcInFlight.clear();
      dismissedInterventionSignatures.clear();
      for (const timer of interventionTimers.values()) {
        clearTimeout(timer);
      }
      interventionTimers.clear();
      updateNoticeController.abort();
      if (rpcPollTimer !== undefined) clearTimeout(rpcPollTimer);
      try { unregisterToast?.(); } catch {}
      try { unregisterToastClear?.(); } catch {}
      try { unregisterSessionDelete?.(); } catch {}
      try { unregisterSessionMoved?.(); } catch {}
      try { unregisterSessionStatus?.(); } catch {}
      try { unregisterSessionIdle?.(); } catch {}
      try { unregisterPluginUpdated?.(); } catch {}
      try { unregisterConfigUpdated?.(); } catch {}
      try { conversationSlotDisposer?.(); } catch {}
      try { sidebarSlotDisposer?.(); } catch {}
    };
  },
};

const guardianTui: Plugin.Definition = v2Plugin;

export default guardianTui;
