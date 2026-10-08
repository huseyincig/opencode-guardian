import { randomUUID } from "node:crypto";

export type GuardianMessageKind = "remediation" | "visible";

const TOKEN_KEY = "opencode-guardian-provenance";
const KIND_KEY = "opencode-guardian-kind";
const MAX_SESSION_TOKENS = 64;

const sessionTokens = new Map<string, Map<string, GuardianMessageKind>>();

export function createGuardianMessageMetadata(
  sessionID: string,
  kind: GuardianMessageKind,
  base: Record<string, unknown> = {}
): Record<string, any> {
  const token = randomUUID();
  let tokens = sessionTokens.get(sessionID);
  if (!tokens) {
    tokens = new Map();
    sessionTokens.set(sessionID, tokens);
  }
  tokens.set(token, kind);
  while (tokens.size > MAX_SESSION_TOKENS) {
    const oldest = tokens.keys().next().value;
    if (typeof oldest !== "string") break;
    tokens.delete(oldest);
  }
  return {
    ...base,
    "opencode-guardian": true,
    [TOKEN_KEY]: token,
    [KIND_KEY]: kind,
  };
}

export function isTrustedGuardianMetadata(
  sessionID: string | undefined,
  metadata: unknown,
  kind?: GuardianMessageKind
): boolean {
  if (!sessionID || !metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    return false;
  }
  const record = metadata as Record<string, unknown>;
  const token = record[TOKEN_KEY];
  const claimedKind = record[KIND_KEY];
  if (typeof token !== "string" || typeof claimedKind !== "string") return false;
  const registered = sessionTokens.get(sessionID)?.get(token);
  return registered !== undefined &&
    registered === claimedKind &&
    (kind === undefined || registered === kind);
}

export function forgetGuardianProvenance(sessionID: string): void {
  sessionTokens.delete(sessionID);
}

export function clearGuardianProvenance(): void {
  sessionTokens.clear();
}
