import { extractLikelyShellMutation, extractStructuredEditTexts, extractToolCommand, } from "../tool-input.js";
import { isVerificationFailureMask } from "../evidence.js";
const EMPTY_HANDLER_PATTERNS = [
    {
        name: "empty JavaScript/TypeScript catch",
        regex: /\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}/m,
    },
    {
        name: "empty Promise catch",
        regex: /\.catch\s*\(\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)?\s*=>\s*\{\s*\}\s*\)/m,
    },
    {
        name: "Python except: pass",
        regex: /\bexcept(?:\s+(?:\([^\n)]+\)|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)(?:\s+as\s+[A-Za-z_]\w*)?)?\s*:\s*(?:#[^\n]*\n\s*)*pass\b/m,
    },
];
const MASKED_VERIFICATION = /\b(?:npm|pnpm|yarn|bun)\s+(?:(?:run\s+)?(?:test|build|lint|typecheck)|audit)\b|\b(?:pytest|py\.test|go\s+test|cargo\s+(?:test|build|clippy|audit)|node\s+--test|jest|vitest|tsc\b[^\n;&|]*--noEmit|mypy|pyright|eslint|ruff|flake8|pip-audit|govulncheck)\b/i;
const EXPLORATORY_VERIFICATION = /(?:^|\s)(?:--help|--version|--listtests|--list-tests|--collect-only|--list|--dry-run|--showconfig|--show-config)(?=\s|$)/i;
function extractAddedLines(text) {
    if (typeof text !== "string")
        return "";
    return text
        .split("\n")
        .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
        .map((line) => line.slice(1))
        .join("\n");
}
function extractSnippet(text, index, length) {
    const start = Math.max(0, index - 80);
    const end = Math.min(text.length, index + length + 80);
    return text
        .slice(start, end)
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 220);
}
export const noSilentFailureRule = {
    id: "integrity/no-silent-failure",
    description: "Detects swallowed errors and verification commands whose failure status is deliberately masked.",
    inspect: (context) => {
        const findings = [];
        const blocking = [];
        const blockEmptyHandlers = context.ruleConfig.blockEmptyHandlers === true;
        const checkCode = (code, source) => {
            if (!code)
                return;
            for (const pattern of EMPTY_HANDLER_PATTERNS) {
                pattern.regex.lastIndex = 0;
                const match = pattern.regex.exec(code);
                if (!match)
                    continue;
                const finding = {
                    ruleId: "integrity/no-silent-failure",
                    pattern: pattern.name,
                    messageSnippet: extractSnippet(code, match.index, match[0].length),
                    description: `Error is swallowed without logging, propagation, or an explicit fallback in ${source}`,
                    confidence: "medium",
                };
                findings.push(finding);
                if (blockEmptyHandlers)
                    blocking.push(finding);
            }
        };
        for (const message of context.currentTurn) {
            if (message.info.role !== "assistant")
                continue;
            for (const part of message.parts) {
                if (part.type !== "tool" || !part.state?.input)
                    continue;
                const input = part.state.input;
                for (const value of [
                    input.content,
                    input.new_string,
                    input.newString,
                    extractAddedLines(input.patchText ?? input.patch),
                    extractLikelyShellMutation(input),
                ]) {
                    if (typeof value === "string" && value)
                        checkCode(value, "code mutation");
                }
                for (const edit of extractStructuredEditTexts(input)) {
                    checkCode(edit.text, "structured code mutation");
                }
                const command = extractToolCommand(input);
                if (command &&
                    MASKED_VERIFICATION.test(command) &&
                    !EXPLORATORY_VERIFICATION.test(command) &&
                    isVerificationFailureMask(command)) {
                    const finding = {
                        ruleId: "integrity/no-silent-failure",
                        pattern: "masked verification failure",
                        messageSnippet: command.replace(/\s+/g, " ").slice(0, 220),
                        description: "A test/build/lint/typecheck/audit command masks its failing exit status",
                        confidence: "high",
                    };
                    findings.push(finding);
                    blocking.push(finding);
                }
            }
        }
        if (findings.length === 0) {
            return {
                ruleId: "integrity/no-silent-failure",
                decision: "pass",
                findings: [],
            };
        }
        if (blocking.length === 0) {
            return {
                ruleId: "integrity/no-silent-failure",
                decision: "pass",
                findings,
            };
        }
        const list = blocking
            .map((finding) => `  - [${finding.pattern}] ${finding.messageSnippet}`)
            .join("\n");
        return {
            ruleId: "integrity/no-silent-failure",
            decision: "block",
            findings,
            remediationPrompt: `Silent failure masking detected:\n${list}\n\n` +
                `Do not force verification commands to succeed after a real failure. Preserve the actual exit status and report or handle errors explicitly.`,
        };
    },
};
