/**
 * Strips quoted text, markdown code blocks, inline code, and blockquotes from
 * assistant prose so that meta-discussions, citations, and rule explanations do
 * not trigger false positive detections.
 */
export declare function sanitizeProseForInspection(text: string, options?: {
    preserveParagraphs?: boolean;
}): string;
