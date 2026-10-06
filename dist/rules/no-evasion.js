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
                const cleanText = sanitizeProseForInspection(part.text);
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
                        if (canBeSupportedByBaseline(pattern) &&
                            hasSuccessfulEvidence(context.evidence, "baseline")) {
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
                                evidence: ["No successful baseline comparison observed in this turn"],
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
            `Before moving on, explicitly report to the user each issue you dismissed. ` +
            `For each: (1) the exact symptom (error message, failing test, unexpected behavior), ` +
            `(2) the evidence it is pre-existing or unrelated (commit hash, line on main, a repro on main), ` +
            `(3) what you would investigate further if asked. Be specific — the user needs to make an informed judgement call.\n\n` +
            `If you claim the issue is pre-existing or unrelated, verify that claim against a baseline/main revision when possible. ` +
            `If it is genuinely outside the user-requested scope, state the concrete scope boundary without dismissing the symptom.`;
        return {
            ruleId: "discipline/no-evasion",
            decision: "block",
            findings,
            remediationPrompt,
        };
    },
};
