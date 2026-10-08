import {
  formatGuardianToast,
  type GuardianInterventionInput,
} from "./toast.js";

export const GUARDIAN_VISIBLE_INTERVENTION_KEY = "opencode-guardian-visible";

export function formatGuardianTranscriptMessage(
  input: GuardianInterventionInput
): string {
  const payload = formatGuardianToast(input);
  const level = payload.variant === "warning" ? "WARNING" : "ERROR";
  const marker = payload.variant === "warning" ? "🟡" : "🔴";
  return `${marker} GUARDIAN · ${level}\n${payload.message}`;
}

export function isGuardianVisibleInterventionMetadata(
  metadata: unknown
): boolean {
  return Boolean(
    metadata &&
    typeof metadata === "object" &&
    !Array.isArray(metadata) &&
    (metadata as Record<string, unknown>)[GUARDIAN_VISIBLE_INTERVENTION_KEY] === true
  );
}
