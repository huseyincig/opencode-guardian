/**
 * Safe user-facing toast notifications for Guardian interventions.
 *
 * Dispatches visually distinct notifications (by variant/color and title)
 * at the exact moments Guardian intervenes:
 * - PREFLIGHT BLOCK (red / error): Dangerous tool / shell command blocked
 * - POST REMEDIATION (red / error): Remediation prompt sent to agent
 * - POST WARNING (yellow / warning): Advisory finding recorded
 *
 * Privacy requirement:
 * Raw snippets, source code, command strings, and secrets MUST NOT leak to toasts.
 * Only safe rule IDs, severity, and action taken are included.
 */

export type GuardianToastVariant = "error" | "warning" | "info";

export type GuardianInterventionKind =
  | "preflight-blocked"
  | "remediation"
  | "warning";

export interface GuardianToastPayload {
  title: string;
  message: string;
  variant: GuardianToastVariant;
  duration: number;
}

export interface GuardianInterventionInput {
  kind: GuardianInterventionKind;
  ruleIds?: readonly string[] | undefined;
  ruleId?: string | undefined;
  tool?: string | undefined;
}

export type GuardianToastListener = (payload: GuardianToastPayload) => void | Promise<unknown>;

export interface GuardianToastNotifierOptions {
  client?: unknown;
  context?: unknown;
  directory?: string | undefined;
  enabled?: boolean | undefined;
}

export interface GuardianToastNotifier {
  notify(input: GuardianInterventionInput): void;
}

const activeListeners = new Set<GuardianToastListener>();
const recentDispatches = new Map<string, number>();
const DEDUPE_WINDOW_MS = 600;

import { SAFE_RULE_IDS } from "./audit.js";

export function sanitizeToastRuleId(raw: unknown): string {
  if (typeof raw !== "string") return "guardian/policy";
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 40) return "guardian/policy";
  if (SAFE_RULE_IDS.has(trimmed) || trimmed === "preflight") {
    return trimmed;
  }
  // Standard two-segment rule format: "category/rule-name"
  if (/^[a-z0-9_-]+\/[a-z0-9_-]+$/i.test(trimmed)) {
    return trimmed;
  }
  return "guardian/policy";
}

export function formatGuardianToast(input: GuardianInterventionInput): GuardianToastPayload {
  switch (input.kind) {
    case "preflight-blocked": {
      const safeRule = sanitizeToastRuleId(input.ruleId ?? input.ruleIds?.[0] ?? "preflight");
      const safeTool =
        typeof input.tool === "string" && /^[a-z0-9_.-]+$/i.test(input.tool.trim())
          ? input.tool.trim()
          : undefined;
      const message = safeTool
        ? `[${safeRule}] Execution of "${safeTool}" was blocked for safety.`
        : `[${safeRule}] Command execution was blocked for safety.`;
      return {
        title: "Guardian — Blocked",
        message,
        variant: "error",
        duration: 5000,
      };
    }
    case "remediation": {
      const rawRules =
        Array.isArray(input.ruleIds) && input.ruleIds.length
          ? input.ruleIds
          : input.ruleId
            ? [input.ruleId]
            : ["quality/policy"];
      const uniqueRules = Array.from(new Set(rawRules.map(sanitizeToastRuleId)));
      const sliced = uniqueRules.slice(0, 3);
      const remaining = uniqueRules.length - 3;
      const ruleText =
        remaining > 0 ? `${sliced.join(", ")} (+${remaining} more)` : sliced.join(", ");
      return {
        title: "Guardian — Remediation",
        message: `Blocked: ${ruleText}\nAgent was asked to correct the issue.`,
        variant: "error",
        duration: 5000,
      };
    }
    case "warning": {
      const rawRules =
        Array.isArray(input.ruleIds) && input.ruleIds.length
          ? input.ruleIds
          : input.ruleId
            ? [input.ruleId]
            : ["quality/advisory"];
      const uniqueRules = Array.from(new Set(rawRules.map(sanitizeToastRuleId)));
      const sliced = uniqueRules.slice(0, 3);
      const remaining = uniqueRules.length - 3;
      const ruleText =
        remaining > 0 ? `${sliced.join(", ")} (+${remaining} more)` : sliced.join(", ");
      return {
        title: "Guardian — Warning",
        message: `Advisory finding: ${ruleText}.`,
        variant: "warning",
        duration: 4000,
      };
    }
  }
}

export function registerToastListener(listener: GuardianToastListener): () => void {
  activeListeners.add(listener);
  return () => {
    activeListeners.delete(listener);
  };
}

export function clearToastListeners(): void {
  activeListeners.clear();
  recentDispatches.clear();
}

export function dispatchGuardianToast(
  payload: GuardianToastPayload,
  options?: GuardianToastNotifierOptions
): void {
  if (options?.enabled === false) return;

  const dedupeKey = `${payload.variant}:${payload.title}:${payload.message}`;
  const now = Date.now();
  const lastTime = recentDispatches.get(dedupeKey);
  if (lastTime && now - lastTime < DEDUPE_WINDOW_MS) {
    return;
  }
  recentDispatches.set(dedupeKey, now);

  if (recentDispatches.size > 50) {
    for (const [key, timestamp] of recentDispatches.entries()) {
      if (now - timestamp > DEDUPE_WINDOW_MS * 2) {
        recentDispatches.delete(key);
      }
    }
  }

  // 1. Notify in-memory listeners (e.g. active TUI instance)
  for (const listener of activeListeners) {
    try {
      void Promise.resolve(listener(payload)).catch(() => {});
    } catch {
      // Listener errors must never break execution
    }
  }

  // 2. V1 Host Client (client.tui.showToast)
  const client = options?.client as
    | {
        tui?: {
          showToast?: (opts: {
            body: {
              title: string;
              message: string;
              variant: "info" | "success" | "warning" | "error";
              duration: number;
            };
            query?: { directory?: string };
          }) => Promise<unknown>;
        };
      }
    | undefined;

  if (typeof client?.tui?.showToast === "function") {
    try {
      const showToast = client.tui.showToast;
      void showToast({
        body: {
          title: payload.title,
          message: payload.message,
          variant: payload.variant,
          duration: payload.duration,
        },
        ...(options?.directory ? { query: { directory: options.directory } } : {}),
      }).catch(() => {});
    } catch {
      // V1 toast dispatch failure is tolerated
    }
  }

  // 3. V2 Context (context.ui.toast.show or context.client.tui.showToast)
  const context = options?.context as
    | {
        ui?: {
          toast?: {
            show?: (opts: {
              title: string;
              message: string;
              variant: "info" | "success" | "warning" | "error";
              duration: number;
            }) => void;
          };
        };
        client?: {
          tui?: {
            showToast?: (opts: {
              body: {
                title: string;
                message: string;
                variant: "info" | "success" | "warning" | "error";
                duration: number;
              };
              query?: { directory?: string };
            }) => Promise<unknown>;
          };
        };
      }
    | undefined;

  if (typeof context?.ui?.toast?.show === "function") {
    try {
      context.ui.toast.show({
        title: payload.title,
        message: payload.message,
        variant: payload.variant,
        duration: payload.duration,
      });
    } catch {
      // V2 UI toast dispatch failure is tolerated
    }
  }

  if (typeof context?.client?.tui?.showToast === "function") {
    try {
      const showToast = context.client.tui.showToast;
      void showToast({
        body: {
          title: payload.title,
          message: payload.message,
          variant: payload.variant,
          duration: payload.duration,
        },
        ...(options?.directory ? { query: { directory: options.directory } } : {}),
      }).catch(() => {});
    } catch {
      // V2 client toast dispatch failure is tolerated
    }
  }
}

export function createGuardianToastNotifier(
  options?: GuardianToastNotifierOptions
): GuardianToastNotifier {
  return {
    notify(input: GuardianInterventionInput): void {
      try {
        const payload = formatGuardianToast(input);
        dispatchGuardianToast(payload, options);
      } catch {
        // Notification failures must fail softly without interrupting policy execution
      }
    },
  };
}
