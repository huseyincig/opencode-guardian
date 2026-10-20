export declare const TRUNCATION_PLACEHOLDERS: RegExp[];
export declare function findTruncationPlaceholder(text: string, filePath?: string): RegExpMatchArray | null;
export interface EditIntegrityEvidence {
    status: "observed" | "unavailable";
    filePath: string;
    beforeHash?: string;
    afterHash?: string;
    beforeBytes?: number;
    afterBytes?: number;
    removedDefinitions?: number;
}
export interface BeforeEditState {
    filePath: string;
    directory: string;
    hash?: string;
    bytes?: number;
    definitions?: Set<string>;
}
export declare function captureBeforeEdit(tool: string, input: Record<string, unknown>, directory: string): BeforeEditState | undefined;
export declare function finishEditObservation(before: BeforeEditState): EditIntegrityEvidence;
