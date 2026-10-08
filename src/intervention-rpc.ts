import type { GuardianToastPayload } from "./toast.js";

export const GUARDIAN_INTERVENTION_RPC_ID = "opencode-guardian.intervention";
export const GUARDIAN_INTERVENTION_RPC_METHOD = "latest";

export const GUARDIAN_INTERVENTION_RPC_DEFINITION = {
  id: GUARDIAN_INTERVENTION_RPC_ID,
  methods: {
    [GUARDIAN_INTERVENTION_RPC_METHOD]: {
      input: {
        type: "object",
        properties: {
          sessionID: { type: "string", minLength: 1 },
        },
        required: ["sessionID"],
        additionalProperties: false,
      },
      output: {
        type: "object",
        properties: {
          active: { type: "boolean" },
          title: { type: "string" },
          message: { type: "string" },
          variant: { type: "string", enum: ["error", "warning", "info"] },
          duration: { type: "number" },
        },
        required: ["active", "title", "message", "variant", "duration"],
        additionalProperties: false,
      },
    },
  },
  events: {},
} as const;

export interface GuardianInterventionSnapshot extends GuardianToastPayload {
  active: boolean;
}

export function inactiveGuardianIntervention(): GuardianInterventionSnapshot {
  return {
    active: false,
    title: "",
    message: "",
    variant: "info",
    duration: 0,
  };
}

export function activeGuardianIntervention(
  payload: GuardianToastPayload
): GuardianInterventionSnapshot {
  return {
    active: true,
    title: payload.title,
    message: payload.message,
    variant: payload.variant,
    duration: payload.duration,
  };
}

export function parseGuardianInterventionSnapshot(
  value: unknown
): GuardianInterventionSnapshot | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const snapshot = value as Record<string, unknown>;
  const variant = snapshot.variant;
  if (
    typeof snapshot.active !== "boolean" ||
    typeof snapshot.title !== "string" ||
    typeof snapshot.message !== "string" ||
    (variant !== "error" && variant !== "warning" && variant !== "info") ||
    typeof snapshot.duration !== "number" ||
    !Number.isFinite(snapshot.duration)
  ) {
    return undefined;
  }
  return {
    active: snapshot.active,
    title: snapshot.title,
    message: snapshot.message,
    variant,
    duration: snapshot.duration,
  };
}

export function readGuardianInterventionSessionID(
  input: unknown
): string | undefined {
  if (!input || typeof input !== "object" || Array.isArray(input)) return undefined;
  const sessionID = (input as Record<string, unknown>).sessionID;
  return typeof sessionID === "string" && sessionID.length > 0
    ? sessionID
    : undefined;
}
