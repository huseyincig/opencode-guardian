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
const activeClearListeners = new Set();
const recentDispatches = new Map();
const DEDUPE_WINDOW_MS = 600;
import { SAFE_RULE_IDS } from "./audit.js";
import { sanitizeString } from "./secrets/sanitizer.js";
const DEFAULT_TRANSCRIPT_SANITIZER = {
    replacement: "[REDACTED]",
};
function cleanTranscriptField(raw, maxLen, sanitizer) {
    if (typeof raw !== "string")
        return undefined;
    const collapsed = raw.replace(/[\r\n\t]+/g, " ").replace(/\s{2,}/g, " ").trim();
    if (!collapsed)
        return undefined;
    const activeSanitizer = sanitizer ?? DEFAULT_TRANSCRIPT_SANITIZER;
    const redacted = sanitizeString(collapsed, activeSanitizer).sanitized;
    return redacted.length > maxLen ? `${redacted.slice(0, maxLen - 1)}…` : redacted;
}
/**
 * Formats a detailed, secret-safe, model-invisible chat transcript notice
 * for `notifications.transcript: true`.
 */
export function formatGuardianTranscriptNotice(input, sanitizer) {
    const headerByKind = {
        "preflight-blocked": {
            header: "[Guardian] ⊘ BLOCKED — Preflight safety block",
            action: "Execution was prevented before running.",
        },
        remediation: {
            header: "[Guardian] ↻ REMEDIATION — Correction requested",
            action: "Agent was asked to correct the issue.",
        },
        "stream-interrupt-requested": {
            header: "[Guardian] ⏹ STREAM STOP — Repetition detected",
            action: "A stream interruption was requested.",
        },
        warning: {
            header: "[Guardian] ▲ WARNING — Advisory finding",
            action: "Advisory notice recorded (execution allowed).",
        },
    };
    const { header, action } = headerByKind[input.kind];
    const lines = [header];
    if (input.kind === "stream-interrupt-requested") {
        lines.push("- runtime/circuit-breaker: Repetitive generation detected in output stream.");
    }
    else if (input.kind === "preflight-blocked") {
        const safeRule = sanitizeToastRuleId(input.ruleId ?? input.ruleIds?.[0] ?? "preflight");
        const safeTool = typeof input.tool === "string" && /^[a-z0-9_.-]+$/i.test(input.tool.trim())
            ? input.tool.trim()
            : undefined;
        const toolSuffix = safeTool ? ` (tool: ${safeTool})` : "";
        lines.push(`- preflight / ${safeRule}${toolSuffix}: Dangerous operation blocked by preflight policy.`);
    }
    else if (Array.isArray(input.details) && input.details.length > 0) {
        const seen = new Set();
        const bullets = [];
        for (const detail of input.details) {
            const ruleId = sanitizeToastRuleId(detail.ruleId);
            const pattern = cleanTranscriptField(detail.pattern, 80, sanitizer);
            const description = cleanTranscriptField(detail.description, 180, sanitizer);
            const filePath = cleanTranscriptField(detail.filePath, 120, sanitizer);
            const key = `${ruleId}|${pattern ?? ""}|${description ?? ""}|${filePath ?? ""}`;
            if (seen.has(key))
                continue;
            seen.add(key);
            let entry = `- ${ruleId}`;
            if (pattern)
                entry += ` (${pattern})`;
            if (filePath)
                entry += ` [${filePath}]`;
            if (description)
                entry += `: ${description}`;
            bullets.push(entry);
        }
        const MAX_BULLETS = 6;
        lines.push(...bullets.slice(0, MAX_BULLETS));
        if (bullets.length > MAX_BULLETS) {
            lines.push(`- ... (+${bullets.length - MAX_BULLETS} more findings)`);
        }
    }
    else {
        const rawRules = Array.isArray(input.ruleIds) && input.ruleIds.length
            ? input.ruleIds
            : input.ruleId
                ? [input.ruleId]
                : ["quality/policy"];
        const uniqueRules = Array.from(new Set(rawRules.map(sanitizeToastRuleId)));
        for (const ruleId of uniqueRules.slice(0, 6)) {
            lines.push(`- ${ruleId}`);
        }
        if (uniqueRules.length > 6) {
            lines.push(`- ... (+${uniqueRules.length - 6} more rules)`);
        }
    }
    lines.push(`Action: ${action}`);
    return lines.join("\n");
}
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
function resolveToastDuration(defaultMs) {
    const envVal = Number(process.env.OPENCODE_GUARDIAN_INTERVENTION_TTL_MS);
    return Number.isFinite(envVal) && envVal > 0 ? Math.floor(envVal) : defaultMs;
}
export function formatGuardianToast(input) {
    switch (input.kind) {
        case "stream-interrupt-requested": return {
            title: "Guardian — Repetition detected",
            message: "Repetitive generation detected. A stream interruption was requested.",
            variant: "warning",
            duration: resolveToastDuration(5000),
        };
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
                duration: resolveToastDuration(5000),
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
                duration: resolveToastDuration(5000),
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
                duration: resolveToastDuration(4000),
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
export function registerToastClearListener(listener, scope = {}) {
    const registration = { listener, scope };
    activeClearListeners.add(registration);
    return () => {
        activeClearListeners.delete(registration);
    };
}
export function dispatchGuardianToastClear(scope) {
    for (const registration of activeClearListeners) {
        if (registration.scope.directory !== undefined &&
            registration.scope.directory !== scope.directory) {
            continue;
        }
        if (registration.scope.sessionID !== undefined &&
            registration.scope.sessionID !== scope.sessionID) {
            continue;
        }
        try {
            void Promise.resolve(registration.listener(scope)).catch(() => { });
        }
        catch {
            // Listener errors must never break execution.
        }
    }
}
export function clearToastListeners() {
    activeListeners.clear();
    activeClearListeners.clear();
    recentDispatches.clear();
}
export function dispatchGuardianToast(payload, options) {
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
    // Listener delivery also carries the same-process composer fallback state.
    // Disabling toast notifications must not disable that separate UI channel.
    if (options?.enabled === false)
        return;
    // 2. V2 Context (context.ui.toast.show or context.client.tui.showToast)
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
        clear(sessionID) {
            try {
                dispatchGuardianToastClear({
                    ...(options?.directory ? { directory: options.directory } : {}),
                    sessionID,
                });
            }
            catch {
                // Clearing notification state must never interrupt policy execution.
            }
        },
    };
}
