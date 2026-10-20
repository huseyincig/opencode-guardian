/**
 * A bounded lexical view for pattern checks, not a language parser. Offsets and
 * line breaks stay stable. String delimiters remain for call-shape patterns;
 * literal contents (including template bodies) never become executable code.
 */
export declare function maskCodeLiterals(source: string, keepComments?: boolean, filePath?: string): string;
/** Literal configured exceptions only exempt the span they cover. */
export declare function withinConfiguredException(text: string, index: number, length: number, exceptions: string[]): boolean;
