export type PreflightFinding = "destructive-command" | "opaque-shell-execution" | "uninspectable-shell-input" | "hardcoded-secret-in-file-write" | "uninspectable-file-input" | "lazy-commit-message" | "hallucinated-or-malformed-package";
export declare function isShellExecutionTool(tool: string, additionalTools?: readonly string[]): boolean;
export declare function isFileMutationTool(tool: string): boolean;
/** A process launcher requires inspection of both the executable and argv. */
export declare function isProcessStartTool(tool: string): boolean;
export declare function evaluateFileMutationPreflight(tool: string, input: unknown): PreflightFinding | undefined;
export declare function extractGitCommitMessage(command: string): string | undefined;
export declare function isLazyCommitMessage(command: string): boolean;
export declare function isHallucinatedOrMalformedPackageInstall(command: string): boolean;
export declare function evaluatePreflight(tool: string, input: unknown, additionalTools?: readonly string[]): PreflightFinding | undefined;
export declare class GuardianPreflightError extends Error {
    readonly reason: PreflightFinding;
    constructor(reason: PreflightFinding);
}
/**
 * Opt-in strict guard: reject recognized risks before a host executes a tool.
 * This does not parse arbitrary shell syntax or replace OS/host permissions.
 */
export declare function enforcePreflight(tool: string, input: unknown, additionalTools?: readonly string[]): void;
