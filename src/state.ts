export interface HandoffTrackingState {
  handoffId: string;
  kind: "clarification" | "choice" | "approval";
  autoSelect: "allowed" | "forbidden";
  status: "handed_off" | "question_presented" | "resolved";
}

interface SessionState {
  turnKey: string;
  remediationCount: number;
  fingerprints: Set<string>;
  fingerprintCounts?: Map<string, number>;
  ruleRemediationCounts?: Map<string, number>;
  continuationCount: number;
  continuationKeys: Set<string>;
  pendingRemediationRules?: string[];
  pendingRemediationFiles?: string[];
  activeHandoff?: HandoffTrackingState;
  handoffSequence: number;
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
        fingerprintCounts: new Map<string, number>(),
        ruleRemediationCounts: new Map<string, number>(),
        continuationCount: 0,
        continuationKeys: new Set<string>(),
        handoffSequence: 0,
        ...(existing?.activeHandoff ? { activeHandoff: existing.activeHandoff } : {}),
      };
      this.sessions.set(sessionID, next);
      return next;
    }
    return existing;
  }

  getTurnRemediationCount(sessionID: string, turnKey: string): number {
    const state = this.sessions.get(sessionID);
    if (!state || state.turnKey !== turnKey) return 0;
    return state.remediationCount;
  }

  getRuleRemediationCount(sessionID: string, turnKey: string, ruleId: string): number {
    const state = this.sessions.get(sessionID);
    if (!state || state.turnKey !== turnKey) return 0;
    return state.ruleRemediationCounts?.get(ruleId) ?? 0;
  }

  canRemediate(
    sessionID: string,
    turnKey: string,
    fingerprint: string,
    rules: string[],
    budget: number,
    maxTurnBudget?: number
  ): boolean {
    if (budget <= 0) return false;
    const state = this.beginTurn(sessionID, turnKey);
    const turnCeiling = maxTurnBudget ?? Math.max(3, budget * 2);
    if (state.remediationCount >= turnCeiling) return false;
    if (rules.length > 0 && rules.every((rule) => (state.ruleRemediationCounts?.get(rule) ?? 0) >= budget)) {
      return false;
    }
    const count = state.fingerprintCounts?.get(fingerprint) ?? 0;
    if (count >= budget) return false;
    return true;
  }

  hasExhaustedRule(
    sessionID: string,
    turnKey: string,
    rules: string[],
    budget: number
  ): boolean {
    if (budget <= 0) return true;
    const state = this.sessions.get(sessionID);
    if (!state || state.turnKey !== turnKey) return false;
    if (!state.ruleRemediationCounts) return false;
    return rules.some((rule) => (state.ruleRemediationCounts?.get(rule) ?? 0) >= budget);
  }

  recordRemediation(
    sessionID: string,
    turnKey: string,
    fingerprint: string,
    rules: string[] = []
  ): void {
    const state = this.beginTurn(sessionID, turnKey);
    state.remediationCount += 1;
    state.fingerprints.add(fingerprint);
    if (!state.fingerprintCounts) state.fingerprintCounts = new Map();
    state.fingerprintCounts.set(fingerprint, (state.fingerprintCounts.get(fingerprint) ?? 0) + 1);
    if (!state.ruleRemediationCounts) state.ruleRemediationCounts = new Map();
    for (const rule of rules) {
      state.ruleRemediationCounts.set(rule, (state.ruleRemediationCounts.get(rule) ?? 0) + 1);
    }
  }

  rollbackRemediation(
    sessionID: string,
    turnKey: string,
    fingerprint: string,
    rules: string[] = []
  ): void {
    const state = this.sessions.get(sessionID);
    if (state && state.turnKey === turnKey) {
      state.remediationCount = Math.max(0, state.remediationCount - 1);
      state.fingerprints.delete(fingerprint);
      const fCount = state.fingerprintCounts?.get(fingerprint) ?? 1;
      if (fCount <= 1) {
        state.fingerprintCounts?.delete(fingerprint);
      } else {
        state.fingerprintCounts?.set(fingerprint, fCount - 1);
      }
      for (const rule of rules) {
        const rCount = state.ruleRemediationCounts?.get(rule) ?? 1;
        if (rCount <= 1) {
          state.ruleRemediationCounts?.delete(rule);
        } else {
          state.ruleRemediationCounts?.set(rule, rCount - 1);
        }
      }
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

  setPendingRemediation(
    sessionID: string,
    turnKey: string,
    rules: string[],
    files: string[] = []
  ): void {
    const state = this.beginTurn(sessionID, turnKey);
    state.pendingRemediationRules = [...rules];
    state.pendingRemediationFiles = [...files];
  }

  getPendingRemediation(
    sessionID: string,
    turnKey?: string
  ): string[] | undefined {
    const state = this.sessions.get(sessionID);
    if (!state) return undefined;
    if (turnKey !== undefined && state.turnKey !== turnKey) return undefined;
    return state.pendingRemediationRules;
  }

  getPendingRemediationFiles(sessionID: string, turnKey: string): string[] {
    const state = this.sessions.get(sessionID);
    return state?.turnKey === turnKey ? [...(state.pendingRemediationFiles ?? [])] : [];
  }

  clearPendingRemediation(sessionID: string): void {
    const state = this.sessions.get(sessionID);
    if (state) {
      delete state.pendingRemediationRules;
      delete state.pendingRemediationFiles;
    }
  }

  setActiveHandoff(sessionID: string, handoff: HandoffTrackingState): void {
    const state = this.sessions.get(sessionID);
    if (state) {
      state.activeHandoff = handoff;
    }
  }

  getActiveHandoff(sessionID: string): HandoffTrackingState | undefined {
    return this.sessions.get(sessionID)?.activeHandoff;
  }

  clearActiveHandoff(sessionID: string): void {
    const state = this.sessions.get(sessionID);
    if (state) {
      delete state.activeHandoff;
    }
  }

  nextHandoffSequence(sessionID: string, turnKey: string): number {
    const state = this.beginTurn(sessionID, turnKey);
    state.handoffSequence = (state.handoffSequence ?? 0) + 1;
    return state.handoffSequence;
  }

  forget(sessionID: string): void {
    this.sessions.delete(sessionID);
  }
}
