import { memo as _$memo } from "@opentui/solid";
import { createComponent as _$createComponent } from "@opentui/solid";
import { createTextNode as _$createTextNode } from "@opentui/solid";
import { effect as _$effect } from "@opentui/solid";
import { insertNode as _$insertNode } from "@opentui/solid";
import { insert as _$insert } from "@opentui/solid";
import { setProp as _$setProp } from "@opentui/solid";
import { createElement as _$createElement } from "@opentui/solid";
/** Dedicated TUI entrypoint: OpenCode V2 (setup / sidebar.content & session.composer.top). */

import { createEffect, createSignal, onCleanup, Show } from "solid-js";
import { readFileSync } from "node:fs";
import { readGuardianStatus } from "./telemetry.js";
import { loadConfig, resolveEffectiveConfig } from "./engine.js";
import { announceGuardianUpdate, checkGuardianUpdate } from "./version-notice.js";
import { dispatchGuardianToastClear, registerToastClearListener, registerToastListener } from "./toast.js";
import { GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD, GUARDIAN_INTERVENTION_RPC_DEFINITION, GUARDIAN_INTERVENTION_RPC_METHOD, GUARDIAN_RESET_RPC_METHOD, GUARDIAN_STATUS_RPC_METHOD, parseGuardianInterventionSnapshot } from "./intervention-rpc.js";
import { GUARDIAN_COMMANDS, guardianCommandReport, guardianResetReport } from "./commands.js";
const guardianVersion = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
function StatRow(props) {
  return (() => {
    var _el$ = _$createElement("box"),
      _el$2 = _$createElement("text"),
      _el$3 = _$createElement("text"),
      _el$4 = _$createElement("b");
    _$insertNode(_el$, _el$2);
    _$insertNode(_el$, _el$3);
    _$setProp(_el$, "width", "100%");
    _$setProp(_el$, "flexDirection", "row");
    _$setProp(_el$, "justifyContent", "space-between");
    _$setProp(_el$2, "flexShrink", 0);
    _$insert(_el$2, () => props.label);
    _$insertNode(_el$3, _el$4);
    _$setProp(_el$3, "flexShrink", 1);
    _$setProp(_el$3, "marginLeft", 1);
    _$insert(_el$4, () => props.value);
    _$effect(_p$ => {
      var _v$ = props.muted,
        _v$2 = props.valueColor ?? props.text;
      _v$ !== _p$.e && (_p$.e = _$setProp(_el$2, "fg", _v$, _p$.e));
      _v$2 !== _p$.t && (_p$.t = _$setProp(_el$3, "fg", _v$2, _p$.t));
      return _p$;
    }, {
      e: undefined,
      t: undefined
    });
    return _el$;
  })();
}
function GuardianConversationIntervention(props) {
  const kindMeta = () => {
    const title = props.payload?.title ?? "";
    if (title.includes("Blocked")) {
      return {
        badge: "⊘ BLOCKED",
        subtitle: "Preflight safety block",
        color: props.colors.error ?? props.colors.accent
      };
    }
    if (title.includes("Remediation")) {
      return {
        badge: "↻ REMEDIATION",
        subtitle: "Correction requested",
        color: props.colors.error ?? props.colors.accent
      };
    }
    if (title.includes("Repetition")) {
      return {
        badge: "⏹ STREAM STOP",
        subtitle: "Repetition detected",
        color: props.colors.warning ?? props.colors.accent
      };
    }
    if (props.payload?.variant === "warning" || title.includes("Warning")) {
      return {
        badge: "▲ WARNING",
        subtitle: "Advisory finding",
        color: props.colors.warning ?? props.colors.accent
      };
    }
    if (props.payload?.variant === "info") {
      return {
        badge: "● NOTICE",
        subtitle: "Guardian notice",
        color: props.colors.accent
      };
    }
    return {
      badge: "✕ ERROR",
      subtitle: "Policy intervention",
      color: props.colors.error ?? props.colors.accent
    };
  };
  const messageLines = () => (props.payload?.message ?? "").split("\n").map(line => line.trimEnd()).filter(line => line.length > 0);
  return _$createComponent(Show, {
    get when() {
      return props.payload;
    },
    get children() {
      var _el$5 = _$createElement("box"),
        _el$6 = _$createElement("box"),
        _el$7 = _$createElement("box"),
        _el$8 = _$createElement("box"),
        _el$9 = _$createElement("text"),
        _el$0 = _$createElement("b"),
        _el$1 = _$createElement("text"),
        _el$10 = _$createElement("b"),
        _el$12 = _$createElement("text"),
        _el$13 = _$createElement("text");
      _$insertNode(_el$5, _el$6);
      _$setProp(_el$5, "width", "100%");
      _$setProp(_el$5, "flexDirection", "column");
      _$setProp(_el$5, "border", ["left"]);
      _$setProp(_el$5, "paddingLeft", 1);
      _$setProp(_el$5, "marginBottom", 1);
      _$setProp(_el$5, "onMouseDown", () => props.onDismiss?.());
      _$insertNode(_el$6, _el$7);
      _$insertNode(_el$6, _el$13);
      _$setProp(_el$6, "width", "100%");
      _$setProp(_el$6, "flexDirection", "row");
      _$setProp(_el$6, "justifyContent", "space-between");
      _$setProp(_el$6, "alignItems", "center");
      _$insertNode(_el$7, _el$8);
      _$insertNode(_el$7, _el$1);
      _$insertNode(_el$7, _el$12);
      _$setProp(_el$7, "flexDirection", "row");
      _$setProp(_el$7, "alignItems", "center");
      _$insertNode(_el$8, _el$9);
      _$setProp(_el$8, "paddingLeft", 1);
      _$setProp(_el$8, "paddingRight", 1);
      _$insertNode(_el$9, _el$0);
      _$insert(_el$0, () => kindMeta().badge);
      _$insertNode(_el$1, _el$10);
      _$insertNode(_el$10, _$createTextNode(` GUARDIAN`));
      _$insert(_el$12, () => ` · ${kindMeta().subtitle}`);
      _$insertNode(_el$13, _$createTextNode(`[dismiss]`));
      _$insert(_el$5, () => messageLines().map(line => (() => {
        var _el$15 = _$createElement("text");
        _$insert(_el$15, line);
        _$effect(_$p => _$setProp(_el$15, "fg", line.startsWith("Action:") ? props.colors.muted : props.colors.text, _$p));
        return _el$15;
      })()), null);
      _$effect(_p$ => {
        var _v$3 = kindMeta().color,
          _v$4 = kindMeta().color,
          _v$5 = props.colors.background,
          _v$6 = kindMeta().color,
          _v$7 = props.colors.muted,
          _v$8 = props.colors.muted;
        _v$3 !== _p$.e && (_p$.e = _$setProp(_el$5, "borderColor", _v$3, _p$.e));
        _v$4 !== _p$.t && (_p$.t = _$setProp(_el$8, "backgroundColor", _v$4, _p$.t));
        _v$5 !== _p$.a && (_p$.a = _$setProp(_el$9, "fg", _v$5, _p$.a));
        _v$6 !== _p$.o && (_p$.o = _$setProp(_el$1, "fg", _v$6, _p$.o));
        _v$7 !== _p$.i && (_p$.i = _$setProp(_el$12, "fg", _v$7, _p$.i));
        _v$8 !== _p$.n && (_p$.n = _$setProp(_el$13, "fg", _v$8, _p$.n));
        return _p$;
      }, {
        e: undefined,
        t: undefined,
        a: undefined,
        o: undefined,
        i: undefined,
        n: undefined
      });
      return _el$5;
    }
  });
}
function v2SessionDirectory(context, sessionID, fallback) {
  return (sessionID ? context.data?.session?.get?.(sessionID)?.location?.directory : undefined) ?? context.data?.location?.default?.()?.directory ?? fallback;
}
function v2CommandDirectory(context, fallback) {
  const route = context.ui?.router?.current?.();
  if (route?.type === "session") {
    return v2SessionDirectory(context, route.sessionID, fallback);
  }
  return context.data?.location?.default?.()?.directory ?? fallback;
}

/** A broken project config must not reject the host's UI render callback, but must remain distinguishable from intentional disablement. */
function v2UiConfig(directory, options) {
  try {
    return {
      ...resolveEffectiveConfig(loadConfig(directory), options),
      configInvalid: false
    };
  } catch {
    return {
      enabled: false,
      notifications: {
        enabled: false
      },
      updateNotice: {
        enabled: false
      },
      configInvalid: true
    };
  }
}
async function withRpcTimeout(promise, timeoutMs = 1500) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("RPC timeout")), timeoutMs);
      timer.unref?.();
    })]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
async function fetchServerStatusViaRpc(context, directory) {
  if (typeof context.client?.rpc !== "function") return undefined;
  try {
    const rpcClient = context.client.rpc(GUARDIAN_INTERVENTION_RPC_DEFINITION);
    const rpcStatus = rpcClient?.[GUARDIAN_STATUS_RPC_METHOD];
    if (typeof rpcStatus !== "function") return undefined;
    const res = await withRpcTimeout(rpcStatus({
      directory
    }, {
      location: {
        directory
      }
    }));
    return res?.ok === true && res.status && typeof res.status === "object" ? res.status : undefined;
  } catch {
    return undefined;
  }
}
async function v2PerformCommand(context, command, directory, onReset) {
  if (command === "reset") {
    const confirmed = await context.ui.dialog.confirm({
      title: "Guardian: Reset Statistics",
      message: "Reset this project's counters? The audit log is not wiped (normal rotation still applies). Configuration and protection are unchanged.",
      label: {
        confirm: "Reset counters",
        cancel: "Cancel"
      }
    });
    if (confirmed !== true) return;
    let result;
    if (typeof context.client?.rpc === "function") {
      try {
        const rpcClient = context.client.rpc(GUARDIAN_INTERVENTION_RPC_DEFINITION);
        const rpcReset = rpcClient?.[GUARDIAN_RESET_RPC_METHOD];
        if (typeof rpcReset === "function") {
          const remote = await withRpcTimeout(rpcReset({
            directory
          }, {
            location: {
              directory
            }
          }));
          if (remote && typeof remote.title === "string" && typeof remote.message === "string") {
            result = {
              title: remote.title,
              message: remote.message
            };
          }
        }
      } catch {
        // Fall back to local reset when RPC host is unavailable (e.g. standalone/unit tests).
      }
    }
    if (!result) {
      result = guardianResetReport(directory);
    }
    const resetSucceeded = !result.message.startsWith("Reset failed");
    if (resetSucceeded) {
      if (onReset) {
        onReset(directory);
      } else {
        dispatchGuardianToastClear({
          directory
        });
      }
    }
    await context.ui.dialog.alert(result);
    return;
  }
  const remoteStatus = command === "status" ? await fetchServerStatusViaRpc(context, directory) : undefined;
  const result = await guardianCommandReport(command, directory, guardianVersion, context.options, remoteStatus);
  await context.ui.dialog.alert(result);
}

/** Register Guardian keymap layer and slash commands; host cleans up setup-created layers on unload. */
export function registerGuardianV2Commands(context, directory, onReset) {
  if (typeof context.keymap?.layer !== "function") return;
  const commands = GUARDIAN_COMMANDS.map(command => ({
    id: "opencode-guardian." + command.id,
    title: command.title,
    description: command.description,
    group: "Guardian",
    palette: true,
    slash: {
      name: "guardian-" + command.id
    },
    run: () => v2PerformCommand(context, command.id, directory(), onReset)
  }));
  try {
    context.keymap.layer(() => ({
      mode: "global",
      commands: [...commands, {
        id: "opencode-guardian.dispatch",
        title: "Guardian: Commands",
        description: "Run /guardian status, activity, doctor, rules, config, version or reset",
        group: "Guardian",
        slash: {
          name: "guardian",
          arguments: true
        },
        run: async raw => {
          const token = (raw ?? "").trim().toLowerCase().replace(/^\/?guardian(?:\s+|$)/, "").split(/\s+/)[0];
          const requested = GUARDIAN_COMMANDS.find(item => item.id === token);
          if (!requested) {
            await context.ui.dialog.alert({
              title: "Guardian: Commands",
              message: "Use /guardian status, activity, doctor, rules, config, version or reset."
            });
            return;
          }
          await v2PerformCommand(context, requested.id, directory(), onReset);
        }
      }]
    }));
  } catch {
    // Host keymap layer validation failure must not crash TUI setup.
  }
}
function guardianStatusEqual(a, b) {
  return a.preflight === b.preflight && a.inspected === b.inspected && a.blocked === b.blocked && a.warnings === b.warnings && a.remediations === b.remediations && a.errors === b.errors && a.verified === b.verified && a.failed === b.failed && a.unverified === b.unverified && a.streamStops === b.streamStops && a.streamVerified === b.streamVerified && a.streamIneffective === b.streamIneffective && a.redacted === b.redacted && a.telemetryLevel === b.telemetryLevel && a.truncated === b.truncated && a.lastEvent === b.lastEvent && a.lastKind === b.lastKind;
}
function GuardianSidebar(props) {
  const currentDirectory = () => props.currentDirectory?.() ?? props.directory ?? process.cwd();
  const [open, setOpen] = createSignal(false);
  const [status, setStatus] = createSignal(readGuardianStatus(currentDirectory()));
  let statusSeq = 0;
  let remoteSucceededForDir;
  const syncStatus = (dir, forceDiskFallback = false) => {
    const seq = ++statusSeq;
    const hasRemote = Boolean(props.fetchRemoteStatus);
    if (!hasRemote || forceDiskFallback || remoteSucceededForDir !== dir) {
      const next = readGuardianStatus(dir);
      setStatus(prev => guardianStatusEqual(prev, next) ? prev : next);
    }
    if (props.fetchRemoteStatus) {
      void props.fetchRemoteStatus(dir).then(remote => {
        if (disposed || seq !== statusSeq || currentDirectory() !== dir) return;
        if (remote) {
          remoteSucceededForDir = dir;
          setStatus(prev => guardianStatusEqual(prev, remote) ? prev : remote);
        } else {
          remoteSucceededForDir = undefined;
          const fallback = readGuardianStatus(dir);
          setStatus(prev => guardianStatusEqual(prev, fallback) ? prev : fallback);
        }
      }).catch(() => {
        if (disposed || seq !== statusSeq || currentDirectory() !== dir) return;
        remoteSucceededForDir = undefined;
        const fallback = readGuardianStatus(dir);
        setStatus(prev => guardianStatusEqual(prev, fallback) ? prev : fallback);
      });
    }
  };
  createEffect(() => {
    const dir = currentDirectory();
    props.refreshVersion?.();
    syncStatus(dir);
  });
  const timer = setInterval(() => syncStatus(currentDirectory()), 5000);
  timer.unref?.();
  const updateController = new AbortController();
  let disposed = false;
  onCleanup(() => {
    clearInterval(timer);
    updateController.abort();
    disposed = true;
  });
  const [hasUpdate, setHasUpdate] = createSignal(false);
  const [latestVersion, setLatestVersion] = createSignal(undefined);
  if (props.checkUpdates !== false) {
    checkGuardianUpdate({
      allowDevelopment: true,
      signal: updateController.signal
    }).then(info => {
      if (!disposed && info) {
        setHasUpdate(true);
        setLatestVersion(info.latest);
      }
    }).catch(() => {});
  }
  const successColor = () => props.colors.success ?? props.colors.accent;
  const warningColor = () => props.colors.warning ?? props.colors.accent;
  const errorColor = () => props.colors.error ?? props.colors.accent;
  const preflightLabel = () => {
    if (props.configInvalid?.()) return "! invalid config";
    if (props.configEnabled?.() === false || props.configPreflight?.() === false) return "○ disabled";
    const pf = status().preflight;
    if (pf === "active") return "● active";
    if (pf === "disabled") return "○ disabled";
    if (pf === "unavailable") return "! unavailable";
    return "—";
  };
  const preflightColor = () => {
    if (props.configInvalid?.()) return errorColor();
    if (props.configEnabled?.() === false || props.configPreflight?.() === false) return props.colors.muted;
    const pf = status().preflight;
    if (pf === "active") return successColor();
    if (pf === "unavailable") return warningColor();
    return props.colors.muted;
  };
  const statusLabel = () => {
    if (props.configInvalid?.()) return "✕ invalid config";
    if (props.configEnabled?.() === false) return "○ disabled";
    // Historical counters must not masquerade as the latest event.
    switch (status().lastKind) {
      case "stream-interrupt-requested":
        return "! stream stop";
      case "stream-interrupt-verified":
        return "✓ stream stopped";
      case "stream-interrupt-ineffective":
        return "✕ stream not stopped";
      case "inspection-error":
        return "✕ inspection error";
      case "preflight-blocked":
        return "⊘ preflight blocked";
      case "post-remediation":
        return "↻ remediation sent";
      case "remediation-verified":
        return "✓ verified";
      case "remediation-failed":
        return "✕ remediation failed";
      case "remediation-unverified":
        return "! unverified";
      case "statistics-reset":
        return "○ reset";
      case "verification-unavailable":
        return "! verification off";
      case "post-warning":
        return "! warning";
      case "preflight-allowed":
        return "● allowed";
      case "post-inspected":
        return "● inspected";
      case "runtime-started":
        return "● Active";
      default:
        return "○ Idle";
    }
  };
  const statusColor = () => {
    if (props.configInvalid?.()) return errorColor();
    if (props.configEnabled?.() === false) return props.colors.muted;
    switch (status().lastKind) {
      case "inspection-error":
      case "preflight-blocked":
      case "stream-interrupt-ineffective":
      case "remediation-failed":
        return errorColor();
      case "stream-interrupt-requested":
      case "post-warning":
      case "remediation-unverified":
      case "verification-unavailable":
        return warningColor();
      case "post-remediation":
        return props.colors.accent;
      case "remediation-verified":
      case "stream-interrupt-verified":
      case "preflight-allowed":
      case "post-inspected":
      case "runtime-started":
        return successColor();
      default:
        return props.colors.muted;
    }
  };
  return (() => {
    var _el$16 = _$createElement("box"),
      _el$17 = _$createElement("box"),
      _el$18 = _$createElement("box"),
      _el$19 = _$createElement("text"),
      _el$20 = _$createElement("box"),
      _el$21 = _$createElement("text"),
      _el$23 = _$createElement("box"),
      _el$24 = _$createElement("text");
    _$insertNode(_el$16, _el$17);
    _$setProp(_el$16, "width", "100%");
    _$setProp(_el$16, "flexDirection", "column");
    _$setProp(_el$16, "gap", 0);
    _$insertNode(_el$17, _el$18);
    _$insertNode(_el$17, _el$23);
    _$setProp(_el$17, "width", "100%");
    _$setProp(_el$17, "flexDirection", "row");
    _$setProp(_el$17, "justifyContent", "space-between");
    _$setProp(_el$17, "alignItems", "center");
    _$setProp(_el$17, "onMouseDown", () => setOpen(value => !value));
    _$insertNode(_el$18, _el$19);
    _$insertNode(_el$18, _el$20);
    _$setProp(_el$18, "flexDirection", "row");
    _$setProp(_el$18, "alignItems", "center");
    _$insert(_el$19, () => open() ? "▼ " : "▶ ");
    _$insertNode(_el$20, _el$21);
    _$setProp(_el$20, "paddingLeft", 1);
    _$setProp(_el$20, "paddingRight", 1);
    _$insertNode(_el$21, _$createTextNode(`guardian`));
    _$insertNode(_el$23, _el$24);
    _$setProp(_el$23, "flexDirection", "row");
    _$setProp(_el$23, "alignItems", "center");
    _$insert(_el$24, "v" + guardianVersion);
    _$insert(_el$23, _$createComponent(Show, {
      get when() {
        return hasUpdate();
      },
      get children() {
        var _el$25 = _$createElement("text"),
          _el$26 = _$createElement("b");
        _$insertNode(_el$25, _el$26);
        _$insertNode(_el$26, _$createTextNode(` (↑)`));
        _$effect(_$p => _$setProp(_el$25, "fg", successColor(), _$p));
        return _el$25;
      }
    }), null);
    _$insert(_el$16, _$createComponent(Show, {
      get when() {
        return _$memo(() => !!hasUpdate())() && latestVersion();
      },
      get children() {
        var _el$28 = _$createElement("box");
        _$setProp(_el$28, "width", "100%");
        _$setProp(_el$28, "flexDirection", "column");
        _$setProp(_el$28, "paddingLeft", 1);
        _$insert(_el$28, _$createComponent(StatRow, {
          label: "Update available",
          get value() {
            return `v${latestVersion()}`;
          },
          get valueColor() {
            return successColor();
          },
          get muted() {
            return props.colors.muted;
          },
          get text() {
            return props.colors.text;
          }
        }));
        return _el$28;
      }
    }), null);
    _$insert(_el$16, _$createComponent(Show, {
      get when() {
        return !open();
      },
      get children() {
        var _el$29 = _$createElement("box");
        _$setProp(_el$29, "width", "100%");
        _$setProp(_el$29, "flexDirection", "column");
        _$setProp(_el$29, "paddingLeft", 1);
        _$insert(_el$29, _$createComponent(StatRow, {
          label: "Status",
          get value() {
            return statusLabel();
          },
          get valueColor() {
            return statusColor();
          },
          get muted() {
            return props.colors.muted;
          },
          get text() {
            return props.colors.text;
          }
        }), null);
        _$insert(_el$29, _$createComponent(StatRow, {
          label: "Interventions",
          get value() {
            return `${status().warnings}w · ${status().remediations}r${status().streamStops > 0 ? ` · ${status().streamStops}s` : ""}`;
          },
          get muted() {
            return props.colors.muted;
          },
          get text() {
            return props.colors.text;
          }
        }), null);
        return _el$29;
      }
    }), null);
    _$insert(_el$16, _$createComponent(Show, {
      get when() {
        return open();
      },
      get children() {
        var _el$30 = _$createElement("box");
        _$setProp(_el$30, "width", "100%");
        _$setProp(_el$30, "flexDirection", "column");
        _$setProp(_el$30, "paddingLeft", 1);
        _$insert(_el$30, _$createComponent(StatRow, {
          label: "Mode",
          value: "Autonomous",
          get valueColor() {
            return props.colors.accent;
          },
          get muted() {
            return props.colors.muted;
          },
          get text() {
            return props.colors.text;
          }
        }), null);
        _$insert(_el$30, _$createComponent(StatRow, {
          label: "Preflight",
          get value() {
            return preflightLabel();
          },
          get valueColor() {
            return preflightColor();
          },
          get muted() {
            return props.colors.muted;
          },
          get text() {
            return props.colors.text;
          }
        }), null);
        _$insert(_el$30, _$createComponent(StatRow, {
          label: "Inspected",
          get value() {
            return status().inspected;
          },
          get muted() {
            return props.colors.muted;
          },
          get text() {
            return props.colors.text;
          }
        }), null);
        _$insert(_el$30, _$createComponent(StatRow, {
          label: "Tool Blocks",
          get value() {
            return status().blocked;
          },
          get valueColor() {
            return _$memo(() => status().blocked > 0)() ? errorColor() : props.colors.muted;
          },
          get muted() {
            return props.colors.muted;
          },
          get text() {
            return props.colors.text;
          }
        }), null);
        _$insert(_el$30, _$createComponent(StatRow, {
          label: "Warnings",
          get value() {
            return status().warnings;
          },
          get valueColor() {
            return _$memo(() => status().warnings > 0)() ? warningColor() : props.colors.muted;
          },
          get muted() {
            return props.colors.muted;
          },
          get text() {
            return props.colors.text;
          }
        }), null);
        _$insert(_el$30, _$createComponent(StatRow, {
          label: "Remediations",
          get value() {
            return status().remediations;
          },
          get valueColor() {
            return _$memo(() => status().remediations > 0)() ? props.colors.accent : props.colors.muted;
          },
          get muted() {
            return props.colors.muted;
          },
          get text() {
            return props.colors.text;
          }
        }), null);
        _$insert(_el$30, _$createComponent(Show, {
          get when() {
            return status().streamStops > 0;
          },
          get children() {
            return _$createComponent(StatRow, {
              label: "Stream Stops",
              get value() {
                return `${status().streamStops} (${status().streamVerified}✓ ${status().streamIneffective}✗)`;
              },
              get valueColor() {
                return _$memo(() => status().streamIneffective > 0)() ? errorColor() : warningColor();
              },
              get muted() {
                return props.colors.muted;
              },
              get text() {
                return props.colors.text;
              }
            });
          }
        }), null);
        _$insert(_el$30, _$createComponent(Show, {
          get when() {
            return status().errors > 0;
          },
          get children() {
            return _$createComponent(StatRow, {
              label: "Errors",
              get value() {
                return status().errors;
              },
              get valueColor() {
                return errorColor();
              },
              get muted() {
                return props.colors.muted;
              },
              get text() {
                return props.colors.text;
              }
            });
          }
        }), null);
        _$insert(_el$30, _$createComponent(Show, {
          get when() {
            return status().truncated;
          },
          get children() {
            var _el$31 = _$createElement("box"),
              _el$32 = _$createElement("text"),
              _el$34 = _$createElement("text");
            _$insertNode(_el$31, _el$32);
            _$insertNode(_el$31, _el$34);
            _$setProp(_el$31, "width", "100%");
            _$setProp(_el$31, "flexDirection", "row");
            _$setProp(_el$31, "justifyContent", "space-between");
            _$insertNode(_el$32, _$createTextNode(`Log`));
            _$insertNode(_el$34, _$createTextNode(`recent window`));
            _$effect(_p$ => {
              var _v$9 = props.colors.muted,
                _v$0 = props.colors.muted;
              _v$9 !== _p$.e && (_p$.e = _$setProp(_el$32, "fg", _v$9, _p$.e));
              _v$0 !== _p$.t && (_p$.t = _$setProp(_el$34, "fg", _v$0, _p$.t));
              return _p$;
            }, {
              e: undefined,
              t: undefined
            });
            return _el$31;
          }
        }), null);
        return _el$30;
      }
    }), null);
    _$effect(_p$ => {
      var _v$1 = props.colors.muted,
        _v$10 = props.colors.accent,
        _v$11 = props.colors.background,
        _v$12 = props.colors.muted;
      _v$1 !== _p$.e && (_p$.e = _$setProp(_el$19, "fg", _v$1, _p$.e));
      _v$10 !== _p$.t && (_p$.t = _$setProp(_el$20, "backgroundColor", _v$10, _p$.t));
      _v$11 !== _p$.a && (_p$.a = _$setProp(_el$21, "fg", _v$11, _p$.a));
      _v$12 !== _p$.o && (_p$.o = _$setProp(_el$24, "fg", _v$12, _p$.o));
      return _p$;
    }, {
      e: undefined,
      t: undefined,
      a: undefined,
      o: undefined
    });
    return _el$16;
  })();
}
const v2Plugin = {
  id: "opencode-guardian.tui",
  setup(context) {
    const directory = context.location?.directory ?? process.cwd();
    let config;
    try {
      config = resolveEffectiveConfig(loadConfig(directory), context.options);
    } catch {
      config = {
        enabled: true,
        notifications: {
          enabled: false
        },
        updateNotice: {
          enabled: false
        }
      };
    }
    if (config.enabled === false) return;
    const updateNoticeController = new AbortController();
    // The pinned V2 host owns setup-created layers and removes them on unload.
    let clearOnReset;
    registerGuardianV2Commands(context, () => v2CommandDirectory(context, directory), dir => clearOnReset?.(dir));
    if (config.updateNotice?.enabled !== false && typeof context.ui.toast?.show === "function") {
      void announceGuardianUpdate((current, latest) => context.ui.toast.show({
        title: "OpenCode Guardian — New version",
        message: `v${current} → v${latest} (update manually)`,
        variant: "info",
        duration: 5000
      }), {
        signal: updateNoticeController.signal
      });
    }
    const colors = () => ({
      accent: context.theme?.status?.success?.base ?? context.theme?.text?.base ?? "green",
      onAccent: context.theme?.text?.action?.primary?.base ?? context.theme?.text?.base ?? "white",
      background: context.theme?.background?.base ?? context.theme?.background?.panel ?? "black",
      text: context.theme?.text?.base ?? "white",
      muted: context.theme?.text?.muted ?? context.theme?.text?.base ?? "gray",
      success: context.theme?.status?.success?.base,
      warning: context.theme?.status?.warning?.base,
      error: context.theme?.status?.error?.base
    });
    const [interventions, setInterventions] = createSignal({});
    const [sidebarVersion, setSidebarVersion] = createSignal(0);
    const rpcInFlight = new Map();
    let rpcRequestSeq = 0;
    const interventionTimers = new Map();
    const dismissedInterventionSignatures = new Map();
    let rpcGeneration = 0;
    let disposed = false;
    const payloadSignature = payload => `${payload.variant}\0${payload.title}\0${payload.message}`;
    const rememberDismissedSignature = (sessionID, sig) => {
      dismissedInterventionSignatures.delete(sessionID);
      dismissedInterventionSignatures.set(sessionID, sig);
      while (dismissedInterventionSignatures.size > 64) {
        const oldest = dismissedInterventionSignatures.keys().next().value;
        if (!oldest) break;
        dismissedInterventionSignatures.delete(oldest);
      }
    };
    const clearInterventionTimer = sessionID => {
      const existing = interventionTimers.get(sessionID);
      if (existing !== undefined) {
        clearTimeout(existing);
        interventionTimers.delete(sessionID);
      }
    };
    const storeIntervention = (sessionID, payload, options) => {
      const existingPayload = interventions()[sessionID];
      if (payload) {
        const sig = payloadSignature(payload);
        if (options?.fromPoll && dismissedInterventionSignatures.get(sessionID) === sig) {
          return;
        }
        if (!options?.fromPoll && dismissedInterventionSignatures.get(sessionID) === sig) {
          dismissedInterventionSignatures.delete(sessionID);
        }
        if (options?.fromPoll && existingPayload && payloadSignature(existingPayload) === sig && interventionTimers.has(sessionID)) {
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
        timer.unref?.();
        interventionTimers.set(sessionID, timer);
      }
      setInterventions(current => {
        const next = {
          ...current
        };
        if (payload) next[sessionID] = payload;else delete next[sessionID];
        while (Object.keys(next).length > 32) {
          const oldest = Object.keys(next)[0];
          if (!oldest) break;
          clearInterventionTimer(oldest);
          delete next[oldest];
        }
        return next;
      });
      if (payload) {
        setSidebarVersion(v => v + 1);
      }
    };
    const interventionRpc = typeof context.client?.rpc === "function" ? context.client.rpc(GUARDIAN_INTERVENTION_RPC_DEFINITION) : undefined;
    const INTERVENTION_RPC_TIMEOUT_MS = 1500;
    const refreshIntervention = async sessionID => {
      if (!interventionRpc || disposed || rpcInFlight.has(sessionID)) return;
      const reqToken = ++rpcRequestSeq;
      rpcInFlight.set(sessionID, reqToken);
      const generation = rpcGeneration;
      const sessionLocation = context.data?.session?.get?.(sessionID)?.location ?? context.location;
      const requestedDirectory = sessionLocation?.directory;
      let timeoutTimer;
      try {
        const rpcCall = Promise.resolve().then(() => interventionRpc[GUARDIAN_INTERVENTION_RPC_METHOD]({
          sessionID
        }, sessionLocation ? {
          location: sessionLocation
        } : undefined));
        rpcCall.catch(() => {});
        const raw = await Promise.race([rpcCall, new Promise(resolve => {
          timeoutTimer = setTimeout(() => resolve(undefined), INTERVENTION_RPC_TIMEOUT_MS);
          timeoutTimer.unref?.();
        })]);
        if (raw === undefined || disposed || generation !== rpcGeneration) return;
        const currentSession = context.data?.session?.get?.(sessionID);
        if (!currentSession) return;
        const currentDirectory = currentSession.location?.directory ?? context.location?.directory;
        if (currentDirectory !== requestedDirectory) return;
        const snapshot = parseGuardianInterventionSnapshot(raw);
        if (!snapshot) return;
        if (!snapshot.active) {
          dismissedInterventionSignatures.delete(sessionID);
        }
        storeIntervention(sessionID, snapshot.active ? {
          title: snapshot.title,
          message: snapshot.message,
          variant: snapshot.variant,
          duration: snapshot.duration
        } : undefined, {
          fromPoll: true
        });
      } catch {
        // Same-process toast bridge remains available when RPC is unavailable.
      } finally {
        if (timeoutTimer !== undefined) clearTimeout(timeoutTimer);
        if (rpcInFlight.get(sessionID) === reqToken) {
          rpcInFlight.delete(sessionID);
        }
      }
    };
    clearOnReset = targetDirectory => {
      rpcGeneration += 1;
      setSidebarVersion(v => v + 1);
      const route = context.ui?.router?.current?.();
      if (route?.type === "session") {
        storeIntervention(route.sessionID, undefined, {
          markDismissed: true
        });
        dispatchGuardianToastClear({
          directory: targetDirectory,
          sessionID: route.sessionID
        });
      }
      for (const sessionID of Object.keys(interventions())) {
        if (v2SessionDirectory(context, sessionID, directory) === targetDirectory) {
          storeIntervention(sessionID, undefined, {
            markDismissed: true
          });
        }
      }
      dispatchGuardianToastClear({
        directory: targetDirectory
      });
      if (interventionRpc && typeof interventionRpc[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD] === "function") {
        void interventionRpc[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD]({
          directory: targetDirectory
        }, {
          location: {
            directory: targetDirectory
          }
        }).catch(() => {});
      }
    };
    const ACTIVE_RPC_POLL_MS = 500;
    const IDLE_RPC_POLL_MS = 5000;
    let rpcPollTimer;
    const nextRpcPollMs = () => {
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
      rpcPollTimer.unref?.();
    };
    if (interventionRpc) {
      refreshCurrentSession();
      scheduleRpcPoll();
    }
    const ownsInterventionScope = scope => {
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
      const toastDirectory = scope.sessionID ? v2SessionDirectory(context, scope.sessionID, directory) : scope.directory ?? directory;
      const toastConfig = v2UiConfig(toastDirectory, context.options);
      if (toastConfig.enabled !== false && toastConfig.notifications?.enabled !== false && typeof context.ui.toast?.show === "function") {
        try {
          const toastLines = toast.message.split("\n").filter(line => line.trim().length > 0);
          const compactMessage = toastLines.length > 2 ? `${toastLines[0]}\n${toastLines[toastLines.length - 1]}` : toast.message;
          context.ui.toast.show({
            title: toast.title,
            message: compactMessage,
            variant: toast.variant,
            duration: Math.min(toast.duration, 5000),
            ...(scope.sessionID ? {
              sessionID: scope.sessionID
            } : {})
          });
        } catch {}
      }
    });
    const unregisterToastClear = registerToastClearListener(scope => {
      if (!ownsInterventionScope(scope)) return;
      rpcGeneration += 1;
      setSidebarVersion(v => v + 1);
      if (scope.sessionID) {
        storeIntervention(scope.sessionID, undefined, {
          markDismissed: true
        });
      } else {
        const targetDir = scope.directory ?? directory;
        for (const sessionID of Object.keys(interventions())) {
          if (v2SessionDirectory(context, sessionID, directory) === targetDir) {
            storeIntervention(sessionID, undefined, {
              markDismissed: true
            });
          }
        }
      }
    });
    const extractTuiEventSessionID = event => {
      const ev = event;
      return ev?.data?.sessionID ?? ev?.data?.info?.id ?? ev?.data?.id ?? ev?.properties?.sessionID ?? ev?.properties?.info?.id ?? ev?.properties?.id ?? ev?.sessionID;
    };
    const unregisterSessionDelete = typeof context.data?.on === "function" ? context.data.on("session.deleted", event => {
      const sid = extractTuiEventSessionID(event);
      rpcGeneration += 1;
      if (sid) {
        dismissedInterventionSignatures.delete(sid);
        storeIntervention(sid, undefined);
        rpcInFlight.delete(sid);
      }
    }) : undefined;
    const unregisterSessionMoved = typeof context.data?.on === "function" ? context.data.on("session.moved", event => {
      const sid = extractTuiEventSessionID(event);
      rpcGeneration += 1;
      if (sid) {
        dismissedInterventionSignatures.delete(sid);
        storeIntervention(sid, undefined);
        rpcInFlight.delete(sid);
      }
      setSidebarVersion(v => v + 1);
    }) : undefined;
    const handleHostRefresh = () => {
      rpcGeneration += 1;
      rpcInFlight.clear();
      setSidebarVersion(v => v + 1);
      const route = context.ui?.router?.current?.();
      if (route?.type === "session") {
        void refreshIntervention(route.sessionID);
      }
    };
    const handleSessionActivity = event => {
      const sid = extractTuiEventSessionID(event);
      const route = context.ui?.router?.current?.();
      setSidebarVersion(v => v + 1);
      if (route?.type === "session" && (!sid || sid === route.sessionID)) {
        void refreshIntervention(route.sessionID);
      }
      scheduleRpcPoll();
    };
    const sessionActivityUnregisters = [];
    let unregisterPluginUpdated;
    let unregisterConfigUpdated;
    if (typeof context.data?.on === "function") {
      for (const evType of ["session.status", "session.idle", "session.execution.started", "session.execution.succeeded", "session.execution.failed", "session.execution.interrupted"]) {
        try {
          const unreg = context.data.on(evType, handleSessionActivity);
          if (typeof unreg === "function") {
            sessionActivityUnregisters.push(unreg);
          }
        } catch {
          // Optional reactive session lifecycle event for adaptive polling.
        }
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
      render: props => _$createComponent(GuardianConversationIntervention, {
        get payload() {
          return _$memo(() => !!(props.sessionID && context.data?.session?.get?.(props.sessionID)))() ? interventions()[props.sessionID] : undefined;
        },
        get colors() {
          return colors();
        },
        onDismiss: () => {
          if (!props.sessionID) return;
          rpcGeneration += 1;
          const sessionDir = v2SessionDirectory(context, props.sessionID, directory);
          storeIntervention(props.sessionID, undefined, {
            markDismissed: true
          });
          dispatchGuardianToastClear({
            directory: sessionDir,
            sessionID: props.sessionID
          });
          if (interventionRpc && typeof interventionRpc[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD] === "function") {
            const sessionLocation = context.data?.session?.get?.(props.sessionID)?.location ?? context.location;
            void interventionRpc[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD]({
              sessionID: props.sessionID
            }, sessionLocation ? {
              location: sessionLocation
            } : undefined).catch(() => {});
          }
        }
      })
    });

    // Append: never override Magic Context, AFT, or built-in sidebar sections.
    const sidebarSlotDisposer = context.ui.slot({
      append: "sidebar.content",
      render: props => {
        const sessionDirectory = () => v2SessionDirectory(context, props.sessionID, directory);
        const sessionConfig = () => v2UiConfig(sessionDirectory(), context.options);
        return _$createComponent(GuardianSidebar, {
          directory: directory,
          currentDirectory: sessionDirectory,
          refreshVersion: sidebarVersion,
          get checkUpdates() {
            return sessionConfig().updateNotice?.enabled !== false;
          },
          configInvalid: () => sessionConfig().configInvalid,
          configEnabled: () => sessionConfig().enabled !== false,
          configPreflight: () => sessionConfig().preflight?.enabled === true,
          get fetchRemoteStatus() {
            return interventionRpc && typeof interventionRpc[GUARDIAN_STATUS_RPC_METHOD] === "function" ? async dir => {
              const res = await withRpcTimeout(interventionRpc[GUARDIAN_STATUS_RPC_METHOD]({
                directory: dir
              }, {
                location: {
                  directory: dir
                }
              }));
              return res?.ok === true && res.status && typeof res.status === "object" ? res.status : undefined;
            } : undefined;
          },
          get colors() {
            return colors();
          }
        });
      }
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
      try {
        unregisterToast?.();
      } catch {}
      try {
        unregisterToastClear?.();
      } catch {}
      try {
        unregisterSessionDelete?.();
      } catch {}
      try {
        unregisterSessionMoved?.();
      } catch {}
      for (const unreg of sessionActivityUnregisters.splice(0)) {
        try {
          unreg();
        } catch {}
      }
      try {
        unregisterPluginUpdated?.();
      } catch {}
      try {
        unregisterConfigUpdated?.();
      } catch {}
      try {
        conversationSlotDisposer?.();
      } catch {}
      try {
        sidebarSlotDisposer?.();
      } catch {}
    };
  }
};
const guardianTui = v2Plugin;
export default guardianTui;
