import { sanitizeProseForInspection } from "../prose.js";
import { extractLikelyShellMutation } from "../tool-input.js";
export const DEFAULT_HEDGING_PATTERNS = [
    // Deferred work
    "for now",
    "revisit later",
    "revisit this",
    "come back to this",
    "should be replaced",
    "should be updated",
    "should be revisited",
    "will need to be",
    // Quality shortcuts
    "good enough",
    "acceptable solution",
    "simple enough",
    "simple approach",
    "basic implementation",
    "simplified version",
    "quick and dirty",
    "not ideal",
    // Version hedging
    "first version",
    "initial version",
    // Placeholder/mock
    "placeholder",
    "hardcoded",
    "hard-coded",
    "workaround",
    "temporary fix",
    "temporary solution",
    "temporary",
];
const HIGH_CONFIDENCE_HEDGING_PATTERNS = new Set([
    "for now",
    "revisit later",
    "revisit this",
    "come back to this",
    "should be replaced",
    "should be updated",
    "should be revisited",
    "will need to be",
    "good enough",
    "quick and dirty",
    "temporary fix",
    "temporary solution",
]);
export const DEFAULT_CODE_MARKERS = ["TODO", "FIXME", "HACK", "XXX"];
export const DEFAULT_CODE_MARKER_REGEXES = DEFAULT_CODE_MARKERS.map((marker) => ({
    marker,
    // Marker words are only meaningful as comments. Do not flag identifiers,
    // string literals, fixture data, or documentation examples.
    regex: new RegExp(`(?:\\/\\/|#|\\/\\*+|\\*|<!--|--)\\s*${marker}\\b`),
}));
export const DEFAULT_EXCEPTIONS = [
    "temporarydirectory",
    "tempdirectory",
    "tempdir",
    "tmpdir",
];
function extractAddedPatchLines(patch) {
    if (typeof patch !== "string")
        return "";
    return patch
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
function hasLexicalBoundaries(text, start, length) {
    const word = /[\p{L}\p{N}_]/u;
    const before = start > 0 ? text[start - 1] : "";
    const after = start + length < text.length ? text[start + length] : "";
    return (!before || !word.test(before)) && (!after || !word.test(after));
}
function extractCodeComments(code) {
    const comments = [];
    let i = 0;
    const readUntil = (endToken) => {
        const start = i;
        const end = code.indexOf(endToken, i);
        i = end === -1 ? code.length : end + endToken.length;
        return code.slice(start, i);
    };
    while (i < code.length) {
        const ch = code[i];
        if (ch === "'" || ch === '"' || ch === "`") {
            const quote = ch;
            const triple = quote !== "`" && code[i + 1] === quote && code[i + 2] === quote;
            i += triple ? 3 : 1;
            while (i < code.length) {
                if (code[i] === "\\") {
                    i += 2;
                    continue;
                }
                if (triple &&
                    code[i] === quote &&
                    code[i + 1] === quote &&
                    code[i + 2] === quote) {
                    i += 3;
                    break;
                }
                if (!triple && code[i] === quote) {
                    i++;
                    break;
                }
                i++;
            }
            continue;
        }
        if (code.startsWith("<!--", i)) {
            i += 4;
            comments.push(`<!--${readUntil("-->")}`);
            continue;
        }
        if (code.startsWith("/*", i)) {
            i += 2;
            comments.push(`/*${readUntil("*/")}`);
            continue;
        }
        if (code.startsWith("//", i) || ch === "#") {
            const start = i;
            const end = code.indexOf("\n", i);
            i = end === -1 ? code.length : end;
            comments.push(code.slice(start, i));
            continue;
        }
        if (code.startsWith("--", i) &&
            (i === 0 || /\s/.test(code[i - 1] ?? ""))) {
            const start = i;
            const end = code.indexOf("\n", i);
            i = end === -1 ? code.length : end;
            comments.push(code.slice(start, i));
            continue;
        }
        i++;
    }
    return comments.join("\n");
}
/**
 * Checks if match at [pos, pos + len) is enclosed within any known exception substring.
 */
function isWithinException(text, pos, len, exceptions) {
    const lowerText = text.toLowerCase();
    for (const exc of exceptions) {
        if (!exc)
            continue;
        let fromIdx = 0;
        while (true) {
            const excIdx = lowerText.indexOf(exc, fromIdx);
            if (excIdx === -1)
                break;
            const excEnd = excIdx + exc.length;
            if (excIdx <= pos && pos + len <= excEnd) {
                return true;
            }
            fromIdx = excIdx + 1;
        }
    }
    return false;
}
export function explicitlyAuthorizedStubOrPlaceholder(text) {
    if (!text || typeof text !== "string")
        return false;
    return /(?:\b(?:add|create|use|put|write|leave)\b[^\n.!?]{0,50}\b(?:stub|mock|placeholder|todo|fixme)\b|\b(?:stub|mock|placeholder|todo|fixme|taslak|yer\s+tutucu)\b[^\n.!?]{0,50}\b(?:ekle|oluştur|yaz|kullan|bırak)\b)/iu.test(text);
}
function extractUserInstruction(context) {
    const messages = context.messages?.length ? context.messages : context.currentTurn;
    const human = messages?.findLast((m) => m.info.role === "user" &&
        !m.parts?.some((p) => p.synthetic === true) &&
        !m.parts?.some((p) => typeof p.text === "string" &&
            p.text.trimStart().startsWith("[opencode-guardian remediation]")));
    if (!human)
        return "";
    return human.parts
        ?.filter((p) => p.type === "text" && typeof p.text === "string")
        .map((p) => p.text ?? "")
        .join("\n") ?? "";
}
export const noShortcutsRule = {
    id: "quality/no-shortcuts",
    description: "Detects hedging language, shortcut phrases, or deferred work patterns in code and responses.",
    inspect: (context) => {
        const userInstruction = extractUserInstruction(context);
        const authorized = explicitlyAuthorizedStubOrPlaceholder(userInstruction);
        const isAuthorizedMarker = (marker, targetFile) => {
            if (!authorized)
                return false;
            if (/(?:do\s+not|don\u0027t|never|without)\s+(?:\w+\s+){0,3}(?:todo|fixme|hack|stub|placeholder|mock)\b|\b(?:todo|fixme|hack|taslak)\s+(?:ekleme|bırakma|yazma)\b/iu.test(userInstruction))
                return false;
            const instruction = userInstruction.toLowerCase();
            // A request for mocks does not permit arbitrary TODOs in production.
            const wantsCodePlaceholder = /\b(?:stub|placeholder|todo|fixme|hack|taslak|yer\s*tutucu)\b/iu.test(instruction);
            if (!wantsCodePlaceholder)
                return false;
            if (/TODO|FIXME|HACK/i.test(marker) && !wantsCodePlaceholder)
                return false;
            if (targetFile) {
                const base = targetFile.replace(/\\/g, "/").split("/").pop()?.replace(/\.[^.]+$/, "").toLowerCase();
                const hasExplicitScope = /(?:src\/|tests\/|\.ts\b|\.js\b|\.py\b|\.go\b)/i.test(instruction);
                if (hasExplicitScope && !instruction.includes(targetFile.toLowerCase()) &&
                    !(base && instruction.includes(base)))
                    return false;
                const taskNouns = ["payment", "auth", "http", "network", "database", "migration"];
                const requested = taskNouns.filter((noun) => instruction.includes(noun));
                const actual = taskNouns.filter((noun) => targetFile.toLowerCase().includes(noun));
                if (requested.length && actual.length && !requested.some((noun) => actual.includes(noun)))
                    return false;
                if (requested.length && !actual.length && /\b(?:and|ve)\b/i.test(instruction))
                    return false;
            }
            return true;
        };
        const customPhrases = (context.ruleConfig.customPhrases ?? []).filter((phrase) => phrase.trim().length > 0);
        const customPhraseSet = new Set(customPhrases.map((phrase) => phrase.trim().toLowerCase()));
        const patterns = [...DEFAULT_HEDGING_PATTERNS, ...customPhrases];
        const exceptions = [
            ...DEFAULT_EXCEPTIONS,
            ...(context.ruleConfig.exceptions
                ?.map((e) => e.trim().toLowerCase())
                .filter(Boolean) ?? []),
        ];
        const findings = [];
        const blocking = [];
        const seen = new Set();
        const checkText = (text, source, inspectCodeMarkers = false, targetFile) => {
            if (!text || typeof text !== "string")
                return;
            const lowerText = text.toLowerCase();
            // Check case-insensitive hedging patterns with localized exception boundary checking
            for (const pattern of patterns) {
                const lowerPattern = pattern.toLowerCase();
                if (seen.has(lowerPattern))
                    continue;
                let searchFrom = 0;
                while (true) {
                    const idx = lowerText.indexOf(lowerPattern, searchFrom);
                    if (idx === -1)
                        break;
                    // Skip identifier/subword matches (temporaryValue, isHardcoded, etc.)
                    // and known legitimate exception names such as TemporaryDirectory.
                    if (hasLexicalBoundaries(text, idx, pattern.length) &&
                        !isWithinException(text, idx, pattern.length, exceptions)) {
                        seen.add(lowerPattern);
                        const snippet = extractSnippet(text, idx, pattern.length);
                        const shouldBlock = customPhraseSet.has(lowerPattern) ||
                            HIGH_CONFIDENCE_HEDGING_PATTERNS.has(lowerPattern);
                        const finding = {
                            ruleId: "quality/no-shortcuts",
                            pattern,
                            messageSnippet: snippet,
                            description: `Shortcut/hedging detected in ${source}: "${pattern}" → "${snippet}"`,
                            confidence: shouldBlock ? "high" : "medium",
                        };
                        findings.push(finding);
                        if (shouldBlock)
                            blocking.push(finding);
                        break;
                    }
                    searchFrom = idx + 1;
                }
            }
            if (inspectCodeMarkers) {
                // Check case-sensitive marker comments only in code mutations.
                for (const { marker, regex } of DEFAULT_CODE_MARKER_REGEXES) {
                    if (seen.has(marker))
                        continue;
                    regex.lastIndex = 0;
                    const match = regex.exec(text);
                    if (match) {
                        seen.add(marker);
                        const markerIndex = match.index + match[0].lastIndexOf(marker);
                        const snippet = extractSnippet(text, markerIndex, marker.length);
                        const finding = {
                            ruleId: "quality/no-shortcuts",
                            pattern: marker,
                            messageSnippet: snippet,
                            description: `Code marker detected in ${source}: "${marker}" → "${snippet}"`,
                            confidence: "high",
                        };
                        findings.push(finding);
                        if (!isAuthorizedMarker(marker, targetFile))
                            blocking.push(finding);
                    }
                }
            }
        };
        for (const msg of context.currentTurn) {
            if (msg.info.role !== "assistant")
                continue;
            for (const part of msg.parts) {
                if (part.type === "text" && part.text) {
                    checkText(sanitizeProseForInspection(part.text), "assistant response");
                }
                if (part.type === "tool" && part.state?.input) {
                    const input = part.state.input;
                    if (typeof input.content === "string") {
                        checkText(extractCodeComments(input.content), "file write comments", true, typeof input.path === "string" ? input.path : typeof input.filePath === "string" ? input.filePath : undefined);
                    }
                    if (typeof input.new_string === "string") {
                        checkText(extractCodeComments(input.new_string), "file edit comments", true, typeof input.path === "string" ? input.path : typeof input.filePath === "string" ? input.filePath : undefined);
                    }
                    if (typeof input.newString === "string") {
                        checkText(extractCodeComments(input.newString), "file edit comments", true, typeof input.path === "string" ? input.path : typeof input.filePath === "string" ? input.filePath : undefined);
                    }
                    const patchText = extractAddedPatchLines(input.patchText ?? input.patch);
                    if (patchText) {
                        checkText(extractCodeComments(patchText), "patch added comments", true, typeof input.path === "string" ? input.path : typeof input.filePath === "string" ? input.filePath : undefined);
                    }
                    const shellMutation = extractLikelyShellMutation(input);
                    if (shellMutation) {
                        checkText(extractCodeComments(shellMutation), "shell file mutation comments", true);
                    }
                    const cmd = typeof input.command === "string" ? input.command : typeof input.cmd === "string" ? input.cmd : "";
                    if (cmd && /\bgit\s+commit\b/i.test(cmd)) {
                        const commitMatch = /\bgit\s+commit\b[^\n;&|]*-(?:m|-message)(?:=|\s+)(["'])([\s\S]*?)\1/i.exec(cmd) ??
                            /\bgit\s+commit\b[^\n;&|]*-m\s+([^\s;&|]+)/i.exec(cmd);
                        if (commitMatch) {
                            const msg = (commitMatch[2] ?? commitMatch[1] ?? "").trim();
                            if (msg.length < 4 || /^(?:fix|update|wip|done|test|temp|changes|commit|asdf|minor|stuff|work|misc|foo|bar|checkpoint|save|tmp|quick\s*fix|bug\s*fix|hotfix)$/i.test(msg)) {
                                const finding = {
                                    ruleId: "quality/no-shortcuts",
                                    pattern: `commit: "${msg}"`,
                                    messageSnippet: cmd,
                                    description: `Lazy or uninformative git commit message "${msg}" detected in shell command`,
                                    confidence: "high",
                                };
                                findings.push(finding);
                                blocking.push(finding);
                            }
                        }
                    }
                }
            }
        }
        if (findings.length === 0) {
            return {
                ruleId: "quality/no-shortcuts",
                decision: "pass",
                findings: [],
            };
        }
        if (blocking.length === 0) {
            return {
                ruleId: "quality/no-shortcuts",
                decision: "pass",
                findings,
            };
        }
        const list = blocking
            .map((finding) => `  - "${finding.pattern}" → ${finding.messageSnippet}`)
            .join("\n");
        const remediationPrompt = `Shortcut/assumption language detected in this turn:\n${list}\n\n` +
            `Before stopping, explicitly report to the user each material shortcut or deferred task. ` +
            `For each: (1) what exactly remains, (2) why it remains, and (3) what a complete solution requires. ` +
            `Do not rewrite technically accurate prose merely to avoid a flagged word.`;
        return {
            ruleId: "quality/no-shortcuts",
            decision: "block",
            findings,
            remediationPrompt,
        };
    },
};
