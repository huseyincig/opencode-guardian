export interface HandoffTrackingState {
  handoffId: string;
  turnKey: string;
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
  pendingRemediationFindings?: string[];
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
    fingerprint: string | readonly string[],
    _rules: string[],
    budget: number,
    maxTurnBudget?: number
  ): boolean {
    if (budget <= 0) return false;
    const state = this.beginTurn(sessionID, turnKey);
    const turnCeiling = maxTurnBudget ?? Math.max(3, budget * 2);
    if (state.remediationCount >= turnCeiling) return false;

    const fingerprints =
      typeof fingerprint === "string" ? [fingerprint] : fingerprint;
    if (fingerprints.length === 0) return false;

    return fingerprints.some(
      (key) => (state.fingerprintCounts?.get(key) ?? 0) < budget
    );
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
    fingerprint: string | readonly string[],
    rules: string[] = []
  ): void {
    const state = this.beginTurn(sessionID, turnKey);
    state.remediationCount += 1;
    const fingerprints =
      typeof fingerprint === "string" ? [fingerprint] : fingerprint;
    if (!state.fingerprintCounts) state.fingerprintCounts = new Map();
    for (const key of fingerprints) {
      state.fingerprints.add(key);
      state.fingerprintCounts.set(
        key,
        (state.fingerprintCounts.get(key) ?? 0) + 1
      );
    }
    if (!state.ruleRemediationCounts) state.ruleRemediationCounts = new Map();
    for (const rule of rules) {
      state.ruleRemediationCounts.set(rule, (state.ruleRemediationCounts.get(rule) ?? 0) + 1);
    }
  }

  rollbackRemediation(
    sessionID: string,
    turnKey: string,
    fingerprint: string | readonly string[],
    rules: string[] = []
  ): void {
    const state = this.sessions.get(sessionID);
    if (state && state.turnKey === turnKey) {
      state.remediationCount = Math.max(0, state.remediationCount - 1);
      const fingerprints =
        typeof fingerprint === "string" ? [fingerprint] : fingerprint;
      for (const key of fingerprints) {
        const fCount = state.fingerprintCounts?.get(key) ?? 1;
        if (fCount <= 1) {
          state.fingerprintCounts?.delete(key);
          state.fingerprints.delete(key);
        } else {
          state.fingerprintCounts?.set(key, fCount - 1);
        }
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
    if (state.continuationKeys.has(progressKey)) return;
    state.continuationCount += 1;
    state.continuationKeys.add(progressKey);
  }

  rollbackContinuation(
    sessionID: string,
    turnKey: string,
    progressKey: string
  ): void {
    const state = this.sessions.get(sessionID);
    if (state && state.turnKey === turnKey && state.continuationKeys.delete(progressKey)) {
      state.continuationCount = Math.max(0, state.continuationCount - 1);
    }
  }

  setPendingRemediation(
    sessionID: string,
    turnKey: string,
    rules: string[],
    files: string[] = [],
    findings: string[] = []
  ): void {
    const state = this.beginTurn(sessionID, turnKey);
    state.pendingRemediationRules = [...rules];
    state.pendingRemediationFiles = [...files];
    state.pendingRemediationFindings = [...findings];
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

  getPendingRemediationFindings(sessionID: string, turnKey: string): string[] {
    const state = this.sessions.get(sessionID);
    return state?.turnKey === turnKey
      ? [...(state.pendingRemediationFindings ?? [])]
      : [];
  }

  clearPendingRemediation(sessionID: string): void {
    const state = this.sessions.get(sessionID);
    if (state) {
      delete state.pendingRemediationRules;
      delete state.pendingRemediationFiles;
      delete state.pendingRemediationFindings;
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
