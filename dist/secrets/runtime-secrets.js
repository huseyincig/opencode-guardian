import { isSensitiveKey } from './patterns.js';
const COMMON_SAFE_VALUES = new Set([
    'development',
    'production',
    'staging',
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    'postgres',
    'mongodb',
    'redis',
    'undefined',
    'true',
    'false',
    'null',
]);
export class RuntimeSecretRegistry {
    envSecrets = new Set();
    manualSecrets = new Set();
    cleared = false;
    lastRefreshAt = 0;
    static AUTO_REFRESH_INTERVAL_MS = 2_000;
    constructor() {
        this.refreshEnv();
    }
    normalizeSecret(val) {
        if (!val || typeof val !== 'string')
            return undefined;
        const trimmed = val.trim();
        if (trimmed.length < 6)
            return undefined;
        if (COMMON_SAFE_VALUES.has(trimmed.toLowerCase()))
            return undefined;
        return trimmed;
    }
    /**
     * Replaces environment-derived secrets with a fresh scan of `env`, evicting
     * rotated or removed environment values while preserving manually added secrets.
     */
    refreshEnv(env = process.env) {
        this.cleared = false;
        this.lastRefreshAt = Date.now();
        this.envSecrets.clear();
        let added = 0;
        for (const [key, val] of Object.entries(env)) {
            if (!val || typeof val !== 'string')
                continue;
            if (isSensitiveKey(key)) {
                const normalized = this.normalizeSecret(val);
                if (normalized && !this.envSecrets.has(normalized)) {
                    this.envSecrets.add(normalized);
                    added++;
                }
            }
        }
        return added;
    }
    /**
     * Scans an environment object (defaults to process.env) and registers sensitive values.
     */
    scanEnv(env = process.env) {
        this.cleared = false;
        let added = 0;
        for (const [key, val] of Object.entries(env)) {
            if (!val || typeof val !== 'string')
                continue;
            if (isSensitiveKey(key)) {
                const normalized = this.normalizeSecret(val);
                if (normalized && !this.envSecrets.has(normalized)) {
                    this.envSecrets.add(normalized);
                    added++;
                }
            }
        }
        return added;
    }
    /**
     * Registers a single secret value if it satisfies safety constraints.
     */
    addSecret(val) {
        const normalized = this.normalizeSecret(val);
        if (!normalized)
            return false;
        this.manualSecrets.add(normalized);
        return true;
    }
    /**
     * Returns registered secrets sorted by length descending to prevent partial replacement.
     */
    getSecrets() {
        if (!this.cleared && Date.now() - this.lastRefreshAt >= RuntimeSecretRegistry.AUTO_REFRESH_INTERVAL_MS) {
            this.refreshEnv(process.env);
        }
        const combined = new Set([...this.envSecrets, ...this.manualSecrets]);
        return Array.from(combined).sort((a, b) => b.length - a.length);
    }
    /**
     * Clears all registered secrets (useful in tests).
     */
    clear() {
        this.envSecrets.clear();
        this.manualSecrets.clear();
        this.cleared = true;
    }
    /**
     * Diagnostic summary: never leaks values or lengths directly.
     */
    count() {
        return new Set([...this.envSecrets, ...this.manualSecrets]).size;
    }
}
export const defaultRuntimeSecrets = new RuntimeSecretRegistry();
