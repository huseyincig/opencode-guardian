export declare class RuntimeSecretRegistry {
    private secrets;
    constructor();
    /**
     * Scans an environment object (defaults to process.env) and registers sensitive values.
     */
    scanEnv(env?: Record<string, string | undefined>): number;
    /**
     * Registers a single secret value if it satisfies safety constraints.
     */
    addSecret(val: string): boolean;
    /**
     * Returns registered secrets sorted by length descending to prevent partial replacement.
     */
    getSecrets(): string[];
    /**
     * Clears all registered secrets (useful in tests).
     */
    clear(): void;
    /**
     * Diagnostic summary: never leaks values or lengths directly.
     */
    count(): number;
}
export declare const defaultRuntimeSecrets: RuntimeSecretRegistry;
