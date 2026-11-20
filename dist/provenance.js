import { forgetMeshSession, resetMeshStateForTests, stampMeshMetadata, verifyMeshMetadata, } from "./bridge.js";
export function createGuardianMessageMetadata(sessionID, kind, base = {}) {
    return stampMeshMetadata(sessionID, {
        owner: "opencode-guardian",
        kind,
        legacyGuardian: true,
        protected: true,
    }, base);
}
export function isTrustedGuardianMetadata(sessionID, metadata, kind) {
    return verifyMeshMetadata(sessionID, metadata, kind, "opencode-guardian");
}
export function forgetGuardianProvenance(sessionID) {
    forgetMeshSession(sessionID);
}
export function clearGuardianProvenance() {
    resetMeshStateForTests();
}
