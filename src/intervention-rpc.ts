import type { Rpc } from "@opencode/plugin/rpc";
import type { GuardianToastPayload } from "./toast.js";

export const GUARDIAN_INTERVENTION_RPC_ID = "opencode-guardian.intervention";
export const GUARDIAN_INTERVENTION_RPC_METHOD = "latest";
export const GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD = "clear";
export const GUARDIAN_STATUS_RPC_METHOD = "status";
export const GUARDIAN_RESET_RPC_METHOD = "reset";

const defineRpc = <T extends Rpc.Definition>(definition: T): T => definition;

export const GUARDIAN_INTERVENTION_RPC_DEFINITION = defineRpc({
  id: GUARDIAN_INTERVENTION_RPC_ID,
  methods: {
    [GUARDIAN_INTERVENTION_RPC_METHOD]: {
      input: {
        type: "object",
        properties: {
          sessionID: { type: "string", minLength: 1, maxLength: 256 },
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
    [GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD]: {
      input: {
        type: "object",
        properties: {
          sessionID: { type: "string", minLength: 1, maxLength: 256 },
          directory: { type: "string", minLength: 1, maxLength: 4096 },
        },
        additionalProperties: false,
      },
      output: {
        type: "object",
        properties: {
          cleared: { type: "boolean" },
        },
        required: ["cleared"],
        additionalProperties: false,
      },
    },
    [GUARDIAN_STATUS_RPC_METHOD]: {
      input: {
        type: "object",
        properties: {
          directory: { type: "string", minLength: 1, maxLength: 4096 },
        },
        additionalProperties: false,
      },
      output: {
        type: "object",
        properties: {
          ok: { type: "boolean" },
          status: { type: "object" },
        },
        required: ["ok"],
        additionalProperties: false,
      },
    },
    [GUARDIAN_RESET_RPC_METHOD]: {
      input: {
        type: "object",
        properties: {
          directory: { type: "string", minLength: 1, maxLength: 4096 },
        },
        additionalProperties: false,
      },
      output: {
        type: "object",
        properties: {
          ok: { type: "boolean" },
          title: { type: "string" },
          message: { type: "string" },
        },
        required: ["ok", "title", "message"],
        additionalProperties: false,
      },
    },
  },
  events: {},
} as const satisfies Rpc.Definition);

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
  return typeof sessionID === "string" && sessionID.length > 0 && sessionID.length <= 256
    ? sessionID
    : undefined;
}

export function readGuardianInterventionDirectory(
  input: unknown
): string | undefined {
  if (!input || typeof input !== "object" || Array.isArray(input)) return undefined;
  const dir = (input as Record<string, unknown>).directory;
  return typeof dir === "string" && dir.trim().length > 0 && dir.length <= 4096
    ? dir
    : undefined;
}
