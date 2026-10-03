export type PreflightFinding = "destructive-command" | "opaque-shell-execution" | "uninspectable-shell-input";
export declare function isShellExecutionTool(tool: string, additionalTools?: readonly string[]): boolean;
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
