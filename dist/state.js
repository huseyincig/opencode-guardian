export class SessionStateStore {
    sessions = new Map();
    beginTurn(sessionID, turnKey) {
        const existing = this.sessions.get(sessionID);
        if (!existing || existing.turnKey !== turnKey) {
            const next = {
                turnKey,
                remediationCount: 0,
                fingerprints: new Set(),
                continuationCount: 0,
                continuationKeys: new Set(),
            };
            this.sessions.set(sessionID, next);
            return next;
        }
        return existing;
    }
    canRemediate(sessionID, turnKey, fingerprint, budget) {
        const state = this.beginTurn(sessionID, turnKey);
        if (state.remediationCount >= budget)
            return false;
        if (state.fingerprints.has(fingerprint))
            return false;
        return true;
    }
    recordRemediation(sessionID, turnKey, fingerprint) {
        const state = this.beginTurn(sessionID, turnKey);
        state.remediationCount += 1;
        state.fingerprints.add(fingerprint);
    }
    rollbackRemediation(sessionID, turnKey, fingerprint) {
        const state = this.sessions.get(sessionID);
        if (state && state.turnKey === turnKey) {
            state.remediationCount = Math.max(0, state.remediationCount - 1);
            state.fingerprints.delete(fingerprint);
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
    forget(sessionID) {
        this.sessions.delete(sessionID);
    }
}
