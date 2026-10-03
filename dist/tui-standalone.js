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
function GuardianSidebar(props) {
  const [open, setOpen] = createSignal(false);
  const [status, setStatus] = createSignal(readGuardianStatus(props.directory));
  const timer = setInterval(() => setStatus(readGuardianStatus(props.directory)), 2500);
  let disposed = false;
  onCleanup(() => {
    clearInterval(timer);
    disposed = true;
  });
  const [hasUpdate, setHasUpdate] = createSignal(false);
  const [latestVersion, setLatestVersion] = createSignal(undefined);
  checkGuardianUpdate({
    allowDevelopment: true
  }).then(info => {
    if (!disposed && info) {
      setHasUpdate(true);
      setLatestVersion(info.latest);
    }
  }).catch(() => {});
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
            return totalBlocked();
          },
          get valueColor() {
            return _$memo(() => totalBlocked() > 0)() ? errorColor() : props.colors.muted;
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
            return _$memo(() => !!hasUpdate())() && latestVersion();
          },
          get children() {
            return _$createComponent(StatRow, {
              label: "Update",
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
  api.slots.register({
    order: 600,
    slots: {
      sidebar_content(_context, _props) {
        return _$createComponent(GuardianSidebar, {
          directory: directory,
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
