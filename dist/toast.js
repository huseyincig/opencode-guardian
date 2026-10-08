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
const activeListeners = new Set();
const recentDispatches = new Map();
const DEDUPE_WINDOW_MS = 600;
import { SAFE_RULE_IDS } from "./audit.js";
export function sanitizeToastRuleId(raw) {
    if (typeof raw !== "string")
        return "guardian/policy";
    const trimmed = raw.trim();
    if (!trimmed || trimmed.length > 40)
        return "guardian/policy";
    if (SAFE_RULE_IDS.has(trimmed) || trimmed === "preflight") {
        return trimmed;
    }
    // Standard two-segment rule format: "category/rule-name"
    if (/^[a-z0-9_-]+\/[a-z0-9_-]+$/i.test(trimmed)) {
        return trimmed;
    }
    return "guardian/policy";
}
export function formatGuardianToast(input) {
    switch (input.kind) {
        case "preflight-blocked": {
            const safeRule = sanitizeToastRuleId(input.ruleId ?? input.ruleIds?.[0] ?? "preflight");
            const safeTool = typeof input.tool === "string" && /^[a-z0-9_.-]+$/i.test(input.tool.trim())
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
            const rawRules = Array.isArray(input.ruleIds) && input.ruleIds.length
                ? input.ruleIds
                : input.ruleId
                    ? [input.ruleId]
                    : ["quality/policy"];
            const uniqueRules = Array.from(new Set(rawRules.map(sanitizeToastRuleId)));
            const sliced = uniqueRules.slice(0, 3);
            const remaining = uniqueRules.length - 3;
            const ruleText = remaining > 0 ? `${sliced.join(", ")} (+${remaining} more)` : sliced.join(", ");
            return {
                title: "Guardian — Remediation",
                message: `Blocked: ${ruleText}\nAgent was asked to correct the issue.`,
                variant: "error",
                duration: 5000,
            };
        }
        case "warning": {
            const rawRules = Array.isArray(input.ruleIds) && input.ruleIds.length
                ? input.ruleIds
                : input.ruleId
                    ? [input.ruleId]
                    : ["quality/advisory"];
            const uniqueRules = Array.from(new Set(rawRules.map(sanitizeToastRuleId)));
            const sliced = uniqueRules.slice(0, 3);
            const remaining = uniqueRules.length - 3;
            const ruleText = remaining > 0 ? `${sliced.join(", ")} (+${remaining} more)` : sliced.join(", ");
            return {
                title: "Guardian — Warning",
                message: `Advisory finding: ${ruleText}.`,
                variant: "warning",
                duration: 4000,
            };
        }
    }
}
export function registerToastListener(listener, scope = {}) {
    const registration = { listener, scope };
    activeListeners.add(registration);
    return () => {
        activeListeners.delete(registration);
    };
}
export function clearToastListeners() {
    activeListeners.clear();
    recentDispatches.clear();
}
export function dispatchGuardianToast(payload, options) {
    if (options?.enabled === false)
        return;
    const dedupeKey = [
        options?.directory ?? "",
        options?.sessionID ?? "",
        payload.variant,
        payload.title,
        payload.message,
    ].join(":");
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
    // 1. Notify only listeners in the same project/session scope.
    const dispatchScope = {
        ...(options?.directory ? { directory: options.directory } : {}),
        ...(options?.sessionID ? { sessionID: options.sessionID } : {}),
    };
    for (const registration of activeListeners) {
        if (registration.scope.directory !== undefined &&
            registration.scope.directory !== options?.directory) {
            continue;
        }
        if (registration.scope.sessionID !== undefined &&
            registration.scope.sessionID !== options?.sessionID) {
            continue;
        }
        try {
            void Promise.resolve(registration.listener(payload, dispatchScope)).catch(() => { });
        }
        catch {
            // Listener errors must never break execution
        }
    }
    // 2. V1 Host Client (client.tui.showToast)
    const client = options?.client;
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
            }).catch(() => { });
        }
        catch {
            // V1 toast dispatch failure is tolerated
        }
    }
    // 3. V2 Context (context.ui.toast.show or context.client.tui.showToast)
    const context = options?.context;
    if (typeof context?.ui?.toast?.show === "function") {
        try {
            context.ui.toast.show({
                title: payload.title,
                message: payload.message,
                variant: payload.variant,
                duration: payload.duration,
                ...(options?.sessionID ? { sessionID: options.sessionID } : {}),
            });
        }
        catch {
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
            }).catch(() => { });
        }
        catch {
            // V2 client toast dispatch failure is tolerated
        }
    }
}
export function createGuardianToastNotifier(options) {
    return {
        notify(input) {
            try {
                const payload = formatGuardianToast(input);
                dispatchGuardianToast(payload, {
                    ...options,
                    ...(input.sessionID ? { sessionID: input.sessionID } : {}),
                });
            }
            catch {
                // Notification failures must fail softly without interrupting policy execution
            }
        },
    };
}
