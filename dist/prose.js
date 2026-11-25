/**
 * Strips quoted text, markdown code blocks, inline code, and blockquotes from
 * assistant prose so that meta-discussions, citations, and rule explanations do
 * not trigger false positive detections.
 */
export function sanitizeProseForInspection(text, options) {
    if (typeof text !== "string")
        return "";
    const stripped = text
        // Strip fenced code blocks (``` ... ```)
        .replace(/```[\s\S]*?```/g, " ")
        // Strip inline code spans (` ... `)
        .replace(/`[^`\n]+`/g, " ")
        // Strip markdown blockquotes (> ...)
        .replace(/^>+[^\n]*/gm, " ")
        // Strip double-quoted or smart-quoted phrases ("..." or “...”)
        .replace(/(?:["“][^"”\n]{1,300}["”])/g, " ");
    if (options?.preserveParagraphs) {
        return stripped
            .replace(/\r\n?/g, "\n")
            .replace(/[ \t]+/g, " ")
            .replace(/ *\n */g, "\n")
            .replace(/\n{3,}/g, "\n\n")
            .trim();
    }
    return stripped
        // Collapse whitespace
        .replace(/\s+/g, " ")
        .trim();
}
