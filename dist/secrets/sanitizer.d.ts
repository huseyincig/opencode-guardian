import type { SanitizerOptions, SanitizeResult } from './types.js';
/**
 * Sanitizes text content against all secret rules.
 */
export declare function sanitizeString(text: string, options?: SanitizerOptions): SanitizeResult<string>;
/**
 * Recursively sanitizes JavaScript objects, arrays, and Error instances.
 */
export declare function sanitizeObject<T>(data: T, options?: SanitizerOptions, rootInsideMeshEnvelope?: boolean): SanitizeResult<T>;
/**
 * Universal Tool Result Sanitizer with redaction metadata.
 * Runs a single pass over any tool result shape (string, Error, V2 { content, output, metadata },
 * process { stdout, stderr }, or generic object/array) so callers do not need JSON.stringify diffs.
 */
export declare function sanitizeToolResultWithMeta<T>(result: T, options?: SanitizerOptions): {
    sanitized: T;
    redactedCount: number;
};
/**
 * Universal Tool Result Sanitizer.
 * Safely transforms any tool result shape (string, { output, metadata }, { stdout, stderr }, MCP content)
 * into a sanitized version without modifying internal non-string metadata.
 */
export declare function sanitizeToolResult<T>(result: T, options?: SanitizerOptions): T;
/**
 * Sanitizes an array of session messages and parts before sending to the model context.
 */
export declare function sanitizeMessages<T = unknown>(messages: T[], options?: SanitizerOptions): T[];
/**
 * Resolves SanitizerOptions from GuardianConfig or returns null if explicitly disabled.
 */
export declare function resolveSanitizerOptions(config?: {
    secrets?: {
        enabled?: boolean | undefined;
        replacement?: string | undefined;
        customSensitiveKeys?: (string | RegExp)[] | undefined;
        customSecretValues?: string[] | undefined;
        includeRuntimeEnv?: boolean | undefined;
        safeKeyNames?: string[] | undefined;
        safeValues?: string[] | undefined;
    } | undefined;
} | undefined): SanitizerOptions | null;
