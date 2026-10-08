/**
 * Conservative shell-pattern inspection, not an interpreter or a permission
 * boundary. Recognize common literal shell rewrites without executing input.
 */
/**
 * Split only on top-level shell separators. Quoted examples and separators
 * inside command substitutions must not become independently executed stages.
 */
export declare function splitShellStages(command: string): string[][];
export declare function shellCommandVariants(command: string): string[];
/** Only active $(...) expressions; text inside single quotes is inert. */
export declare function activeCommandSubstitutions(command: string): string[];
/** Only active paired backtick substitutions; single-quoted text and escaped
 * delimiters are inert. The returned script is classified, never executed. */
export declare function activeBacktickSubstitutions(command: string): string[];
/** Literal script passed to a shell; dynamic scripts are not decoded here. */
export declare function literalShellScripts(command: string): string[];
/** Literal scripts passed through Windows command interpreters. Encoded
 * PowerShell payloads are intentionally not decoded and are treated opaque. */
export declare function literalWindowsShellScripts(command: string): string[];
/** Find's deletion actions do not require the rm binary to run directly. */
export declare function hasFindDeletion(command: string): boolean;
/**
 * Decoding into a shell conceals the executed script. This is a warning
 * signal only: it does not prove that the decoded payload is destructive.
 */
export declare function isOpaqueShellExecution(command: string): boolean;
/** An unresolved command substitution in executable position is opaque.
 * The strict preflight can reject it without treating ordinary echo output
 * or quoted documentation as a destructive action. */
export declare function hasDynamicCommandName(command: string, depth?: number): boolean;
