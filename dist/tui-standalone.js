import { memo as _$memo } from "@opentui/solid";
import { createComponent as _$createComponent } from "@opentui/solid";
import { createTextNode as _$createTextNode } from "@opentui/solid";
import { effect as _$effect } from "@opentui/solid";
import { insertNode as _$insertNode } from "@opentui/solid";
import { insert as _$insert } from "@opentui/solid";
import { setProp as _$setProp } from "@opentui/solid";
import { createElement as _$createElement } from "@opentui/solid";
/** Dedicated TUI entrypoint: OpenCode 1 (tui / sidebar_content) and 2 (setup / sidebar.content). */

import { createSignal, onCleanup, Show } from "solid-js";
import { readFileSync } from "node:fs";
import { readGuardianStatus } from "./telemetry.js";
import { loadConfig } from "./engine.js";
import { announceGuardianUpdate, checkGuardianUpdate } from "./version-notice.js";
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
function v2CommandDirectory(context, fallback) {
  return context.data?.location?.default?.()?.directory ?? fallback;
}
async function v2PerformCommand(context, command, directory) {
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
    const result = guardianResetReport(directory);
    await context.ui.dialog.alert(result);
    return;
  }
  const result = await guardianCommandReport(command, directory, guardianVersion);
  await context.ui.dialog.alert(result);
}

/** Register in a host-owned Solid component: keymap.layer follows that owner's cleanup. */
export function registerGuardianV2Commands(context, directory) {
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
    run: () => v2PerformCommand(context, command.id, directory())
  }));
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
        await v2PerformCommand(context, requested.id, directory());
      }
    }]
  }));
}
function v1ShowReport(api, report, dialog = api.ui.dialog) {
  dialog.setSize("large");
  dialog.replace(() => api.ui.DialogAlert(report));
}

/** V1 command.register is optional in the installed V1 1.18.34 contract. */
export function registerGuardianV1Commands(api) {
  if (typeof api.command?.register !== "function") return;
  const unregister = api.command.register(() => GUARDIAN_COMMANDS.map(command => ({
    title: command.title,
    value: "opencode-guardian." + command.id,
    description: command.description,
    category: "Guardian",
    slash: {
      name: "guardian-" + command.id
    },
    onSelect: async selected => {
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
          onCancel: () => dialog.clear()
        }));
        return;
      }
      const report = await guardianCommandReport(command.id, directory, guardianVersion);
      v1ShowReport(api, report, dialog);
    }
  })));
  // The pinned V1 API owns plugin resources via its explicit lifecycle.
  api.lifecycle?.onDispose?.(unregister);
}
function GuardianSidebar(props) {
  const currentDirectory = () => props.currentDirectory?.() ?? props.directory ?? process.cwd();
  const [open, setOpen] = createSignal(false);
  const [status, setStatus] = createSignal(readGuardianStatus(currentDirectory()));
  const timer = setInterval(() => setStatus(readGuardianStatus(currentDirectory())), 2500);
  let disposed = false;
  onCleanup(() => {
    clearInterval(timer);
    disposed = true;
  });
  const [hasUpdate, setHasUpdate] = createSignal(false);
  const [latestVersion, setLatestVersion] = createSignal(undefined);
  if (props.checkUpdates !== false) {
    checkGuardianUpdate({
      allowDevelopment: true
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
      case "inspection-error":
        return "▲ inspection error";
      case "preflight-blocked":
        return "● preflight blocked";
      case "post-remediation":
        return "● remediation sent";
      case "remediation-verified":
        return "● remediation verified";
      case "remediation-failed":
        return "▲ remediation failed";
      case "remediation-unverified":
        return "▲ remediation unverified";
      case "statistics-reset":
        return "○ statistics reset";
      case "verification-unavailable":
        return "▲ verification unavailable";
      case "post-warning":
        return "▲ warning";
      case "preflight-allowed":
        return "● allowed";
      case "runtime-started":
        return "● Active";
      default:
        return "○ Idle";
    }
  };
  const statusColor = () => {
    switch (status().lastKind) {
      case "inspection-error":
      case "preflight-blocked":
      case "remediation-failed":
        return errorColor();
      case "post-warning":
      case "remediation-unverified":
      case "verification-unavailable":
        return warningColor();
      case "post-remediation":
        return props.colors.accent;
      case "remediation-verified":
      case "preflight-allowed":
      case "runtime-started":
        return successColor();
      default:
        return props.colors.muted;
    }
  };
  return (() => {
    var _el$5 = _$createElement("box"),
      _el$6 = _$createElement("box"),
      _el$7 = _$createElement("box"),
      _el$8 = _$createElement("text"),
      _el$9 = _$createElement("text"),
      _el$0 = _$createElement("b"),
      _el$10 = _$createElement("box"),
      _el$11 = _$createElement("text");
    _$insertNode(_el$5, _el$6);
    _$setProp(_el$5, "width", "100%");
    _$setProp(_el$5, "flexDirection", "column");
    _$setProp(_el$5, "gap", 0);
    _$insertNode(_el$6, _el$7);
    _$insertNode(_el$6, _el$10);
    _$setProp(_el$6, "width", "100%");
    _$setProp(_el$6, "flexDirection", "row");
    _$setProp(_el$6, "justifyContent", "space-between");
    _$setProp(_el$6, "alignItems", "center");
    _$setProp(_el$6, "onMouseDown", () => setOpen(value => !value));
    _$insertNode(_el$7, _el$8);
    _$insertNode(_el$7, _el$9);
    _$setProp(_el$7, "flexDirection", "row");
    _$setProp(_el$7, "alignItems", "center");
    _$insert(_el$8, () => open() ? "▼ " : "▶ ");
    _$insertNode(_el$9, _el$0);
    _$insertNode(_el$0, _$createTextNode(`Guardian`));
    _$insertNode(_el$10, _el$11);
    _$setProp(_el$10, "flexDirection", "row");
    _$setProp(_el$10, "alignItems", "center");
    _$insert(_el$11, "v" + guardianVersion);
    _$insert(_el$10, _$createComponent(Show, {
      get when() {
        return hasUpdate();
      },
      get children() {
        var _el$12 = _$createElement("text"),
          _el$13 = _$createElement("b");
        _$insertNode(_el$12, _el$13);
        _$insertNode(_el$13, _$createTextNode(` (↑)`));
        _$effect(_$p => _$setProp(_el$12, "fg", successColor(), _$p));
        return _el$12;
      }
    }), null);
    _$insert(_el$5, _$createComponent(Show, {
      get when() {
        return _$memo(() => !!hasUpdate())() && latestVersion();
      },
      get children() {
        return _$createComponent(StatRow, {
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
        });
      }
    }), null);
    _$insert(_el$5, _$createComponent(Show, {
      get when() {
        return !open();
      },
      get children() {
        return [_$createComponent(StatRow, {
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
        }), _$createComponent(StatRow, {
          label: "Interventions",
          get value() {
            return `${status().warnings}w · ${status().remediations}r`;
          },
          get muted() {
            return props.colors.muted;
          },
          get text() {
            return props.colors.text;
          }
        })];
      }
    }), null);
    _$insert(_el$5, _$createComponent(Show, {
      get when() {
        return open();
      },
      get children() {
        return [_$createComponent(StatRow, {
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
        }), _$createComponent(StatRow, {
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
        }), _$createComponent(StatRow, {
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
        }), _$createComponent(StatRow, {
          label: "Blocked",
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
        }), _$createComponent(StatRow, {
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
        }), _$createComponent(StatRow, {
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
        }), _$createComponent(Show, {
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
        }), _$createComponent(Show, {
          get when() {
            return status().truncated;
          },
          get children() {
            var _el$15 = _$createElement("box"),
              _el$16 = _$createElement("text"),
              _el$18 = _$createElement("text");
            _$insertNode(_el$15, _el$16);
            _$insertNode(_el$15, _el$18);
            _$setProp(_el$15, "width", "100%");
            _$setProp(_el$15, "flexDirection", "row");
            _$setProp(_el$15, "justifyContent", "space-between");
            _$insertNode(_el$16, _$createTextNode(`Log`));
            _$insertNode(_el$18, _$createTextNode(`recent window`));
            _$effect(_p$ => {
              var _v$3 = props.colors.muted,
                _v$4 = props.colors.muted;
              _v$3 !== _p$.e && (_p$.e = _$setProp(_el$16, "fg", _v$3, _p$.e));
              _v$4 !== _p$.t && (_p$.t = _$setProp(_el$18, "fg", _v$4, _p$.t));
              return _p$;
            }, {
              e: undefined,
              t: undefined
            });
            return _el$15;
          }
        })];
      }
    }), null);
    _$effect(_p$ => {
      var _v$5 = props.colors.muted,
        _v$6 = props.colors.text,
        _v$7 = props.colors.muted;
      _v$5 !== _p$.e && (_p$.e = _$setProp(_el$8, "fg", _v$5, _p$.e));
      _v$6 !== _p$.t && (_p$.t = _$setProp(_el$9, "fg", _v$6, _p$.t));
      _v$7 !== _p$.a && (_p$.a = _$setProp(_el$11, "fg", _v$7, _p$.a));
      return _p$;
    }, {
      e: undefined,
      t: undefined,
      a: undefined
    });
    return _el$5;
  })();
}
const v2Plugin = {
  id: "opencode-guardian.tui",
  setup(context) {
    const directory = context.location?.directory ?? process.cwd();
    const config = loadConfig(directory);
    if (config.enabled === false) return;
    // The pinned V2 host owns setup-created layers and removes them on unload.
    registerGuardianV2Commands(context, () => v2CommandDirectory(context, directory));
    if (config.updateNotice?.enabled !== false && typeof context.ui.toast?.show === "function") {
      void announceGuardianUpdate((current, latest) => context.ui.toast.show({
        title: "OpenCode Guardian — New version",
        message: `v${current} → v${latest} (update manually)`,
        variant: "info",
        duration: 5000
      }));
    }
    // Append: never override Magic Context, AFT, or built-in sidebar sections.
    return context.ui.slot({
      append: "sidebar.content",
      render: () => _$createComponent(GuardianSidebar, {
        directory: directory,
        currentDirectory: () => v2CommandDirectory(context, directory),
        get checkUpdates() {
          return config.updateNotice?.enabled !== false;
        },
        get colors() {
          return {
            accent: context.theme.status?.success?.base ?? context.theme.text.base,
            onAccent: context.theme.text.action.primary.base,
            text: context.theme.text.base,
            muted: context.theme.text.muted,
            success: context.theme.status?.success?.base,
            warning: context.theme.status?.warning?.base,
            error: context.theme.status?.error?.base
          };
        }
      })
    });
  }
};

/** Use V1's actual SDK contract; V1 slot IDs are host-managed, not disposers. */
const v1Tui = async api => {
  const directory = api.state.path.directory;
  const config = loadConfig(directory);
  if (config.enabled === false) return;
  registerGuardianV1Commands(api);
  api.slots.register({
    order: 600,
    slots: {
      sidebar_content(_context, _props) {
        return _$createComponent(GuardianSidebar, {
          directory: directory,
          currentDirectory: () => api.state.path.directory,
          get checkUpdates() {
            return config.updateNotice?.enabled !== false;
          },
          get colors() {
            return {
              accent: api.theme.current.primary,
              onAccent: api.theme.current.background,
              text: api.theme.current.text,
              muted: api.theme.current.textMuted,
              success: api.theme.current.success,
              warning: api.theme.current.warning,
              error: api.theme.current.error
            };
          }
        });
      }
    }
  });
};
const guardianTui = {
  ...v2Plugin,
  tui: v1Tui
};
export default guardianTui;
