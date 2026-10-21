import { extractLikelyShellMutation, extractStructuredEditTexts, splitFilePatches } from "../tool-input.js";
import { findTruncationPlaceholder, TRUNCATION_PLACEHOLDERS } from "../edit-integrity.js";
/**
 * Regex patterns that detect lazy file truncation comments like:
 * "// ... existing code unchanged ..."
 * "# ... rest of code ..."
 * "<!-- ... previous content ... -->"
 */
export const TRUNCATION_PATTERNS = TRUNCATION_PLACEHOLDERS;
function extractAddedLines(text) {
    if (typeof text !== "string")
        return "";
    return text
        .split("\n")
        .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
        .map((line) => line.slice(1))
        .join("\n");
}
function extractSnippet(text, matchIndex, matchLen) {
    const maxPerSide = 80;
    const start = Math.max(0, matchIndex - maxPerSide);
    const end = Math.min(text.length, matchIndex + matchLen + maxPerSide);
    let snippet = text.slice(start, end).replace(/\r?\n/g, " ").replace(/\s+/g, " ").trim();
    if (start > 0)
        snippet = `…${snippet}`;
    if (end < text.length)
        snippet = `${snippet}…`;
    return snippet;
}
export const noTruncationRule = {
    id: "safety/no-truncation",
    description: "Prevents models from deleting existing code by using lazy truncation placeholders like '// ... existing code ...'.",
    inspect: (context) => {
        const findings = [];
        const seen = new Set();
        for (const record of context.evidence?.fileMutations ?? []) {
            const edit = record.editIntegrity;
            if (record.status !== "success" || edit?.status !== "observed" ||
                (edit.removedDefinitions ?? 0) < 2 || !edit.beforeBytes ||
                (edit.afterBytes ?? edit.beforeBytes) >= edit.beforeBytes / 2)
                continue;
            findings.push({ ruleId: "safety/no-truncation", pattern: "observed whole-file content loss",
                messageSnippet: "Whole-file replacement removed multiple observed definitions.",
                description: `Observed replacement reduced ${edit.beforeBytes} bytes to ${edit.afterBytes} and removed ${edit.removedDefinitions} definitions; confirm this matches the requested change`,
                filePath: edit.filePath, confidence: "medium",
                fingerprint: `${edit.filePath}:${edit.beforeHash}:${edit.afterHash}` });
        }
        const checkCode = (code, source, filePath) => {
            if (!code || typeof code !== "string")
                return;
            {
                const match = findTruncationPlaceholder(code, filePath);
                if (match) {
                    const matchedText = match[0].trim();
                    if (seen.has(matchedText))
                        return;
                    seen.add(matchedText);
                    const snippet = extractSnippet(code, match.index ?? 0, match[0].length);
                    findings.push({
                        ruleId: "safety/no-truncation",
                        pattern: matchedText,
                        messageSnippet: snippet,
                        description: `Lazy code truncation placeholder detected in ${source}: "${matchedText}" → "${snippet}"`,
                    });
                }
            }
        };
        for (const msg of context.currentTurn) {
            if (msg.info.role !== "assistant")
                continue;
            for (const part of msg.parts) {
                if (part.type === "tool" && part.state?.input) {
                    const input = part.state.input;
                    const target = input.path ?? input.filePath ?? input.file ?? input.targetFile;
                    const filePath = typeof target === "string" ? target : undefined;
                    if (typeof input.content === "string") {
                        checkCode(input.content, "file write content", filePath);
                    }
                    if (typeof input.new_string === "string") {
                        checkCode(input.new_string, "file edit", filePath);
                    }
                    if (typeof input.newString === "string") {
                        checkCode(input.newString, "file edit", filePath);
                    }
                    for (const edit of extractStructuredEditTexts(input)) {
                        checkCode(edit.text, "structured file edit", edit.filePath ?? filePath);
                    }
                    for (const section of splitFilePatches(input.patchText ?? input.patch)) {
                        const patchText = extractAddedLines(section.patch);
                        if (patchText)
                            checkCode(patchText, "patch added lines", section.filePath ?? filePath);
                    }
                    const shellMutation = extractLikelyShellMutation(input);
                    if (shellMutation) {
                        checkCode(shellMutation, "shell file mutation");
                    }
                }
            }
        }
        if (findings.length === 0) {
            return {
                ruleId: "safety/no-truncation",
                decision: "pass",
                findings: [],
            };
        }
        const blocking = findings.filter(f => f.pattern !== "observed whole-file content loss");
        if (!blocking.length)
            return { ruleId: "safety/no-truncation", decision: "pass", findings };
        const list = blocking.map((f) => `  - "${f.pattern}" → ${f.messageSnippet}`).join("\n");
        const remediationPrompt = `Lazy code truncation placeholder detected in this turn:\n${list}\n\n` +
            `ACTION REQUIRED:\n` +
            `1. Never write truncation placeholders like '// ... existing code unchanged ...' or '// ...' inside file modifications.\n` +
            `2. Provide the complete, untruncated file content or use a targeted search-and-replace edit that preserves all surrounding source code.`;
        return {
            ruleId: "safety/no-truncation",
            decision: "block",
            findings,
            remediationPrompt,
        };
    },
};
