/** Render process argv as literal words, never as additional shell source. */
export declare function quoteProcessArgument(value: string): string;
export interface FilePatch {
    filePath?: string;
    previousPath?: string;
    patch: string;
    deleted: boolean;
}
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
/**
 * Normalizes replacement text embedded in structured edit arrays.
 * Providers use several field aliases; rules should inspect the replacement
 * payload rather than treating the outer edits array as opaque.
 */
export declare function extractStructuredEditTexts(input: Record<string, unknown>, defaultFilePath?: string): StructuredEditText[];
