import { randomUUID } from "node:crypto";
const TOKEN_KEY = "opencode-guardian-provenance";
const KIND_KEY = "opencode-guardian-kind";
const MAX_SESSION_TOKENS = 64;
const sessionTokens = new Map();
export function createGuardianMessageMetadata(sessionID, kind, base = {}) {
    const token = randomUUID();
    let tokens = sessionTokens.get(sessionID);
    if (!tokens) {
        tokens = new Map();
        sessionTokens.set(sessionID, tokens);
    }
    tokens.set(token, kind);
    while (tokens.size > MAX_SESSION_TOKENS) {
        const oldest = tokens.keys().next().value;
        if (typeof oldest !== "string")
            break;
        tokens.delete(oldest);
    }
    return {
        ...base,
        "opencode-guardian": true,
        [TOKEN_KEY]: token,
        [KIND_KEY]: kind,
    };
}
export function isTrustedGuardianMetadata(sessionID, metadata, kind) {
    if (!sessionID || !metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
        return false;
    }
    const record = metadata;
    const token = record[TOKEN_KEY];
    const claimedKind = record[KIND_KEY];
    if (typeof token !== "string" || typeof claimedKind !== "string")
        return false;
    const registered = sessionTokens.get(sessionID)?.get(token);
    return registered !== undefined &&
        registered === claimedKind &&
        (kind === undefined || registered === kind);
}
export function forgetGuardianProvenance(sessionID) {
    sessionTokens.delete(sessionID);
}
export function clearGuardianProvenance() {
    sessionTokens.clear();
}
