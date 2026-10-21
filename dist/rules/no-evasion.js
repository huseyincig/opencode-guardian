import { sanitizeProseForInspection } from "../prose.js";
import { hasSuccessfulEvidence } from "../evidence.js";
/**
 * Dismissal phrases matched case-insensitively.
 */
export const DEFAULT_PATTERNS = [
    // Pre-existing
    "pre-existing issue",
    "pre-existing bug",
    "pre-existing problem",
    "pre-existing failure",
    "pre-existing error",
    "preexisting issue",
    "preexisting bug",
    "preexisting problem",
    "preexisting failure",
    "preexisting error",
    // Unrelated to this/my/the change/PR/work
    "unrelated to this change",
    "unrelated to my change",
    "unrelated to the change",
    "unrelated to these changes",
    "unrelated to my changes",
    "unrelated to this pr",
    "unrelated to my pr",
    "unrelated to this work",
    "unrelated to this task",
    "unrelated to this fix",
    // Not related / not caused / not introduced
    "not related to this change",
    "not related to my change",
    "not related to these changes",
    "not related to my changes",
    "not caused by this change",
    "not caused by my change",
    "not caused by these changes",
    "not introduced by this change",
    "not introduced by my change",
    "not introduced by these changes",
    "not introduced by my changes",
    "not something we introduced",
    "not something i introduced",
    // Already broken / failing on main
    "already broken on main",
    "already failing on main",
    "already failing before",
    "already broken before",
    "already present on main",
    "broken on main",
    // Out of scope
    "outside the scope of this",
    "outside the scope of my",
    "beyond the scope of this",
    "out of scope for this",
    // Separate
    "separate issue from",
    "separate bug from",
    "separate concern from",
];
function claimPaths(text) {
    const tokens = text.slice(0, 64_000).match(/[a-zA-Z0-9_@./-]+/g) ?? [];
    return [...new Set(tokens.map((token) => token.replace(/\.+$/, "")).filter((token) => /\.[a-zA-Z][a-zA-Z0-9]{0,12}$/.test(token))
            .map((file) => file.replace(/^\.\//, "")))].slice(0, 20);
}
function baselineCovers(record, path) {
    if (record.kind !== "baseline" || record.status !== "success")
        return false;
    const command = record.command ?? "";
    // Literal file scopes, or observed diff headers. Merely mentioning a file
    // in output prose is not a comparison of it.
    const show = /\bgit\s+show\s+[^\s;&|]+:([^\s;&|]+)/.exec(command);
    if (show)
        return show[1]?.replace(/^["']|["']$/g, "").replace(/^\.\//, "") === path;
    if (/\bgit\s+(?:diff|blame)\b/.test(command)) {
        const tail = command.split(/\s--\s/, 2)[1];
        if (tail && tail.split(/\s+/).some((token) => token.replace(/^["']|["']$/g, "").replace(/^\.\//, "") === path))
            return true;
        return (record.output ?? "").split("\n").some((line) => line === `+++ b/${path}` || line === `--- a/${path}`);
    }
    return false;
}
function canBeSupportedByBaseline(pattern) {
    const lower = pattern.toLowerCase();
    return (lower.includes("pre-existing") ||
        lower.includes("preexisting") ||
        lower.includes("already broken") ||
        lower.includes("already failing") ||
        lower.includes("already present") ||
        lower.includes("broken on main") ||
        lower.includes("unrelated") ||
        lower.includes("not related") ||
        lower.includes("not caused") ||
        lower.includes("not introduced") ||
        lower.includes("not something"));
}
function isNegatedUnrelatedPhrase(text, matchIndex, pattern) {
    if (!pattern.toLowerCase().startsWith("unrelated"))
        return false;
    const prefix = text.slice(Math.max(0, matchIndex - 12), matchIndex);
    return /(?:\bnot|n't)\s+$/i.test(prefix);
}
function extractSnippet(text, matchIndex, matchLen) {
    const maxPerSide = 100;
    const start = Math.max(0, matchIndex - maxPerSide);
    const end = Math.min(text.length, matchIndex + matchLen + maxPerSide);
    let snippet = text.slice(start, end).replace(/\r?\n/g, " ").replace(/\s+/g, " ").trim();
    if (start > 0)
        snippet = `…${snippet}`;
    if (end < text.length)
        snippet = `${snippet}…`;
    return snippet;
}
export const noEvasionRule = {
    id: "discipline/no-evasion",
    description: "Detects when an agent attempts to evade responsibility or dismiss failures as pre-existing or out of scope.",
    inspect: (context) => {
        const patterns = [
            ...DEFAULT_PATTERNS,
            ...(context.ruleConfig.customPhrases ?? []).filter((phrase) => phrase.trim().length > 0),
        ];
        const findings = [];
        const seenPatterns = new Set();
        for (const msg of context.currentTurn) {
            if (msg.info.role !== "assistant")
                continue;
            for (const part of msg.parts) {
                if (part.type !== "text" || !part.text || typeof part.text !== "string") {
                    continue;
                }
                // Preserve file mentions inside inline code while still excluding quoted
                // examples and code blocks from claims.
                const cleanText = sanitizeProseForInspection(part.text.slice(0, 64_000).replace(/`([^`\n]+)`/g, (span, value) => claimPaths(value).includes(value) ? value : span));
                if (!cleanText)
                    continue;
                const lowerText = cleanText.toLowerCase();
                for (const pattern of patterns) {
                    const lowerPattern = pattern.toLowerCase();
                    if (seenPatterns.has(lowerPattern))
                        continue;
                    let searchFrom = 0;
                    while (searchFrom < lowerText.length) {
                        const matchIdx = lowerText.indexOf(lowerPattern, searchFrom);
                        if (matchIdx === -1)
                            break;
                        if (isNegatedUnrelatedPhrase(cleanText, matchIdx, pattern)) {
                            searchFrom = matchIdx + lowerPattern.length;
                            continue;
                        }
                        const sentenceStart = Math.max(cleanText.lastIndexOf(". ", matchIdx), cleanText.lastIndexOf("! ", matchIdx), cleanText.lastIndexOf("? ", matchIdx));
                        const sentenceEnd = cleanText.indexOf(". ", matchIdx);
                        const paths = claimPaths(cleanText.slice(sentenceStart < 0 ? 0 : sentenceStart + 2, sentenceEnd < 0 ? undefined : sentenceEnd));
                        const supported = paths.length > 0
                            ? paths.every((path) => context.evidence?.records.some((record) => baselineCovers(record, path)))
                            : hasSuccessfulEvidence(context.evidence, "baseline");
                        if (canBeSupportedByBaseline(pattern) && supported) {
                            break;
                        }
                        seenPatterns.add(lowerPattern);
                        const snippet = extractSnippet(cleanText, matchIdx, pattern.length);
                        findings.push({
                            ruleId: "discipline/no-evasion",
                            pattern,
                            messageSnippet: snippet,
                            description: canBeSupportedByBaseline(pattern)
                                ? `Baseline/pre-existing claim lacks a successful baseline check: "${pattern}" → "${snippet}"`
                                : `Evasion phrase detected: "${pattern}" → "${snippet}"`,
                            ...(canBeSupportedByBaseline(pattern) ? {
                                evidence: ["No successful baseline comparison matching this claim observed in this turn"],
                            } : {}),
                            confidence: "high",
                        });
                        break;
                    }
                }
            }
        }
        if (findings.length === 0) {
            return {
                ruleId: "discipline/no-evasion",
                decision: "pass",
                findings: [],
            };
        }
        const list = findings.map((f) => `  - "${f.pattern}" → ${f.messageSnippet}`).join("\n");
        const remediationPrompt = `Evasion language detected in this turn:\n${list}\n\n` +
            `ACTION REQUIRED:\n` +
            `1. Do not dismiss errors or test failures as "unrelated" or "pre-existing" without concrete proof.\n` +
            `2. Explicitly report to the user each issue encountered: (1) exact symptom, (2) evidence why it occurred, (3) what is needed to fix it.\n` +
            `3. If genuinely outside scope, state the exact scope boundary clearly rather than ignoring the failure.`;
        return {
            ruleId: "discipline/no-evasion",
            decision: "block",
            findings,
            remediationPrompt,
        };
    },
};
