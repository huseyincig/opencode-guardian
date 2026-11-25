/**
 * Canonical provider-agnostic shell tool action names shared across
 * preflight enforcement and turn evidence collection.
 */
export declare const KNOWN_SHELL_TOOLS: ReadonlySet<string>;
/**
 * Canonical provider-agnostic read-only tool action names shared across
 * agent capability classification and turn evidence collection.
 */
export declare const KNOWN_READ_ONLY_TOOLS: Set<string>;
export declare function isKnownReadOnlyTool(toolName: string): boolean;
/**
 * Extracts the provider-agnostic action name from built-in, dotted/colon/slash-namespaced,
 * or MCP-prefixed tool identifiers (e.g. `mcp__<provider>__<action>`, `mcp.<provider>.<action>`).
 * Never hardcodes or depends on any third-party MCP provider name.
 */
export declare function extractToolAction(tool: string): string;
/** Render process argv as literal words, never as additional shell source. */
export declare function quoteProcessArgument(value: string): string;
export interface FilePatch {
    filePath?: string;
    previousPath?: string;
    patch: string;
    deleted: boolean;
}
export declare const FILE_WRITE_WHOLE_KEYS: readonly ["content", "file_text", "CodeContent", "text"];
export declare const FILE_WRITE_EDIT_KEYS: readonly ["new_string", "newString", "new_str", "ReplacementContent"];
export declare const FILE_WRITE_ALL_KEYS: readonly ["content", "file_text", "CodeContent", "text", "new_string", "newString", "new_str", "ReplacementContent"];
export declare function extractToolTargetFile(input: Record<string, unknown>): string | undefined;
/** Preserve per-file boundaries in unified and native apply_patch input. */
export declare function splitFilePatches(value: unknown): FilePatch[];
export declare function extractToolCommand(input: Record<string, unknown>): string;
/**
 * Returns shell source only when the command appears to mutate file contents.
 * This covers common heredoc/redirection and in-place scripting paths without
 * treating ordinary read-only shell commands as file writes.
 */
export declare function extractLikelyShellMutation(input: Record<string, unknown>): string;
export interface StructuredEditText {
    text: string;
    filePath?: string;
}
export interface StructuredEditInspection {
    texts: StructuredEditText[];
    hasUninspectableEdit: boolean;
}
/**
 * Normalizes replacement text embedded in structured edit arrays and reports
 * whether any edit entry lacks a recognized inspectable text field.
 */
export declare function extractStructuredEditInspection(input: Record<string, unknown>, defaultFilePath?: string): StructuredEditInspection;
/**
 * Normalizes replacement text embedded in structured edit arrays.
 * Providers use several field aliases; rules should inspect the replacement
 * payload rather than treating the outer edits array as opaque.
 */
export declare function extractStructuredEditTexts(input: Record<string, unknown>, defaultFilePath?: string): StructuredEditText[];
