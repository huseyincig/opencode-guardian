interface SessionState {
  turnKey: string;
  remediationCount: number;
  fingerprints: Set<string>;
  continuationCount: number;
  continuationKeys: Set<string>;
}

export class SessionStateStore {
  private readonly sessions = new Map<string, SessionState>();

  beginTurn(sessionID: string, turnKey: string): SessionState {
    const existing = this.sessions.get(sessionID);
    if (!existing || existing.turnKey !== turnKey) {
      const next: SessionState = {
        turnKey,
        remediationCount: 0,
        fingerprints: new Set<string>(),
        continuationCount: 0,
        continuationKeys: new Set<string>(),
      };
      this.sessions.set(sessionID, next);
      return next;
    }
    return existing;
  }

  canRemediate(
    sessionID: string,
    turnKey: string,
    fingerprint: string,
    budget: number
  ): boolean {
    const state = this.beginTurn(sessionID, turnKey);
    if (state.remediationCount >= budget) return false;
    if (state.fingerprints.has(fingerprint)) return false;
    return true;
  }

  recordRemediation(
    sessionID: string,
    turnKey: string,
    fingerprint: string
  ): void {
    const state = this.beginTurn(sessionID, turnKey);
    state.remediationCount += 1;
    state.fingerprints.add(fingerprint);
  }

  rollbackRemediation(
    sessionID: string,
    turnKey: string,
    fingerprint: string
  ): void {
    const state = this.sessions.get(sessionID);
    if (state && state.turnKey === turnKey) {
      state.remediationCount = Math.max(0, state.remediationCount - 1);
      state.fingerprints.delete(fingerprint);
    }
  }

  canContinue(
    sessionID: string,
    turnKey: string,
    progressKey: string,
    budget: number
  ): boolean {
    const state = this.beginTurn(sessionID, turnKey);
    return (
      state.continuationCount < budget &&
      !state.continuationKeys.has(progressKey)
    );
  }

  recordContinuation(
    sessionID: string,
    turnKey: string,
    progressKey: string
  ): void {
    const state = this.beginTurn(sessionID, turnKey);
    state.continuationCount += 1;
    state.continuationKeys.add(progressKey);
  }

  rollbackContinuation(
    sessionID: string,
    turnKey: string,
    progressKey: string
  ): void {
    const state = this.sessions.get(sessionID);
    if (state && state.turnKey === turnKey) {
      state.continuationCount = Math.max(0, state.continuationCount - 1);
      state.continuationKeys.delete(progressKey);
    }
  }

  forget(sessionID: string): void {
    this.sessions.delete(sessionID);
  }
}
