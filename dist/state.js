export class SessionStateStore {
    sessions = new Map();
    beginTurn(sessionID, turnKey) {
        const existing = this.sessions.get(sessionID);
        if (!existing || existing.turnKey !== turnKey) {
            const next = {
                turnKey,
                remediationCount: 0,
                fingerprints: new Set(),
                fingerprintCounts: new Map(),
                ruleRemediationCounts: new Map(),
                continuationCount: 0,
                continuationKeys: new Set(),
                handoffSequence: 0,
                ...(existing?.activeHandoff ? { activeHandoff: existing.activeHandoff } : {}),
            };
            this.sessions.set(sessionID, next);
            return next;
        }
        return existing;
    }
    getTurnRemediationCount(sessionID, turnKey) {
        const state = this.sessions.get(sessionID);
        if (!state || state.turnKey !== turnKey)
            return 0;
        return state.remediationCount;
    }
    getRuleRemediationCount(sessionID, turnKey, ruleId) {
        const state = this.sessions.get(sessionID);
        if (!state || state.turnKey !== turnKey)
            return 0;
        return state.ruleRemediationCounts?.get(ruleId) ?? 0;
    }
    canRemediate(sessionID, turnKey, fingerprint, rules, budget, maxTurnBudget) {
        if (budget <= 0)
            return false;
        const state = this.beginTurn(sessionID, turnKey);
        const turnCeiling = maxTurnBudget ?? Math.max(3, budget * 2);
        if (state.remediationCount >= turnCeiling)
            return false;
        if (rules.length > 0 && rules.every((rule) => (state.ruleRemediationCounts?.get(rule) ?? 0) >= budget)) {
            return false;
        }
        const count = state.fingerprintCounts?.get(fingerprint) ?? 0;
        if (count >= budget)
            return false;
        if (state.fingerprints.has(fingerprint))
            return false;
        return true;
    }
    hasExhaustedRule(sessionID, turnKey, rules, budget) {
        if (budget <= 0)
            return true;
        const state = this.sessions.get(sessionID);
        if (!state || state.turnKey !== turnKey)
            return false;
        if (!state.ruleRemediationCounts)
            return false;
        return rules.some((rule) => (state.ruleRemediationCounts?.get(rule) ?? 0) >= budget);
    }
    recordRemediation(sessionID, turnKey, fingerprint, rules = []) {
        const state = this.beginTurn(sessionID, turnKey);
        state.remediationCount += 1;
        state.fingerprints.add(fingerprint);
        if (!state.fingerprintCounts)
            state.fingerprintCounts = new Map();
        state.fingerprintCounts.set(fingerprint, (state.fingerprintCounts.get(fingerprint) ?? 0) + 1);
        if (!state.ruleRemediationCounts)
            state.ruleRemediationCounts = new Map();
        for (const rule of rules) {
            state.ruleRemediationCounts.set(rule, (state.ruleRemediationCounts.get(rule) ?? 0) + 1);
        }
    }
    rollbackRemediation(sessionID, turnKey, fingerprint, rules = []) {
        const state = this.sessions.get(sessionID);
        if (state && state.turnKey === turnKey) {
            state.remediationCount = Math.max(0, state.remediationCount - 1);
            state.fingerprints.delete(fingerprint);
            const fCount = state.fingerprintCounts?.get(fingerprint) ?? 1;
            if (fCount <= 1) {
                state.fingerprintCounts?.delete(fingerprint);
            }
            else {
                state.fingerprintCounts?.set(fingerprint, fCount - 1);
            }
            for (const rule of rules) {
                const rCount = state.ruleRemediationCounts?.get(rule) ?? 1;
                if (rCount <= 1) {
                    state.ruleRemediationCounts?.delete(rule);
                }
                else {
                    state.ruleRemediationCounts?.set(rule, rCount - 1);
                }
            }
        }
    }
    canContinue(sessionID, turnKey, progressKey, budget) {
        const state = this.beginTurn(sessionID, turnKey);
        return (state.continuationCount < budget &&
            !state.continuationKeys.has(progressKey));
    }
    recordContinuation(sessionID, turnKey, progressKey) {
        const state = this.beginTurn(sessionID, turnKey);
        state.continuationCount += 1;
        state.continuationKeys.add(progressKey);
    }
    rollbackContinuation(sessionID, turnKey, progressKey) {
        const state = this.sessions.get(sessionID);
        if (state && state.turnKey === turnKey) {
            state.continuationCount = Math.max(0, state.continuationCount - 1);
            state.continuationKeys.delete(progressKey);
        }
    }
    setPendingRemediation(sessionID, turnKey, rules, files = []) {
        const state = this.beginTurn(sessionID, turnKey);
        state.pendingRemediationRules = [...rules];
        state.pendingRemediationFiles = [...files];
    }
    getPendingRemediation(sessionID, turnKey) {
        const state = this.sessions.get(sessionID);
        if (!state)
            return undefined;
        if (turnKey !== undefined && state.turnKey !== turnKey)
            return undefined;
        return state.pendingRemediationRules;
    }
    getPendingRemediationFiles(sessionID, turnKey) {
        const state = this.sessions.get(sessionID);
        return state?.turnKey === turnKey ? [...(state.pendingRemediationFiles ?? [])] : [];
    }
    clearPendingRemediation(sessionID) {
        const state = this.sessions.get(sessionID);
        if (state) {
            delete state.pendingRemediationRules;
            delete state.pendingRemediationFiles;
        }
    }
    setActiveHandoff(sessionID, handoff) {
        const state = this.sessions.get(sessionID);
        if (state) {
            state.activeHandoff = handoff;
        }
    }
    getActiveHandoff(sessionID) {
        return this.sessions.get(sessionID)?.activeHandoff;
    }
    clearActiveHandoff(sessionID) {
        const state = this.sessions.get(sessionID);
        if (state) {
            delete state.activeHandoff;
        }
    }
    nextHandoffSequence(sessionID, turnKey) {
        const state = this.beginTurn(sessionID, turnKey);
        state.handoffSequence = (state.handoffSequence ?? 0) + 1;
        return state.handoffSequence;
    }
    forget(sessionID) {
        this.sessions.delete(sessionID);
    }
}
