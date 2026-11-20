import {
  forgetMeshSession,
  resetMeshStateForTests,
  stampMeshMetadata,
  verifyMeshMetadata,
} from "./bridge.js";

export type GuardianMessageKind = "remediation" | "visible";

export function createGuardianMessageMetadata(
  sessionID: string,
  kind: GuardianMessageKind,
  base: Record<string, unknown> = {}
): Record<string, any> {
  return stampMeshMetadata(
    sessionID,
    {
      owner: "opencode-guardian",
      kind,
      legacyGuardian: true,
      protected: true,
    },
    base
  );
}

export function isTrustedGuardianMetadata(
  sessionID: string | undefined,
  metadata: unknown,
  kind?: GuardianMessageKind
): boolean {
  return verifyMeshMetadata(sessionID, metadata, kind, "opencode-guardian");
}

export function forgetGuardianProvenance(sessionID: string): void {
  forgetMeshSession(sessionID);
}

export function clearGuardianProvenance(): void {
  resetMeshStateForTests();
}
