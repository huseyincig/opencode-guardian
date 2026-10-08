import { formatGuardianToast, } from "./toast.js";
export const GUARDIAN_VISIBLE_INTERVENTION_KEY = "opencode-guardian-visible";
export function formatGuardianTranscriptMessage(input) {
    const payload = formatGuardianToast(input);
    const level = payload.variant === "warning" ? "WARNING" : "ERROR";
    const marker = payload.variant === "warning" ? "🟡" : "🔴";
    return `${marker} GUARDIAN · ${level}\n${payload.message}`;
}
export function isGuardianVisibleInterventionMetadata(metadata) {
    return Boolean(metadata &&
        typeof metadata === "object" &&
        !Array.isArray(metadata) &&
        metadata[GUARDIAN_VISIBLE_INTERVENTION_KEY] === true);
}
