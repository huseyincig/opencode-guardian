import path from "node:path";
import { extractLikelyShellMutation, extractStructuredEditTexts, splitFilePatches } from "../tool-input.js";
import { extractFilePathFromPatch } from "./no-secrets.js";
import { maskCodeLiterals } from "../code-context.js";
/** Split a single-line shell command on unquoted `&&`, `||`, `;` without breaking heredoc bodies. */
function splitInlineShellList(line) {
    const parts = [];
    let cur = "";
    let q = null;
    for (let i = 0; i < line.length; i++) {
        const c = line[i];
        if (c === "\\" && q !== "'") {
            cur += c + (line[++i] ?? "");
            continue;
        }
        if (q === null && c === "$" && line[i + 1] === "'") {
            q = "$'";
            cur += "$'";
            i++;
            continue;
        }
        if (q) {
            cur += c;
            if ((q === "$'" && c === "'") || c === q)
                q = null;
            continue;
        }
        if (c === "'" || c === '"') {
            q = c;
            cur += c;
            continue;
        }
        if (c === ";") {
            if (cur.trim())
                parts.push(cur.trim());
            cur = "";
            continue;
        }
        if ((c === "&" && line[i + 1] === "&") || (c === "|" && line[i + 1] === "|")) {
            if (cur.trim())
                parts.push(cur.trim());
            cur = "";
            i++;
            continue;
        }
        cur += c;
    }
    if (cur.trim())
        parts.push(cur.trim());
    return parts;
}
/** Detect unquoted heredoc redirections (`<<EOF`, `<<- 'EOF'`, `<<\EOF`) on a single command part. */
function extractUnquotedHeredocs(part) {
    const results = [];
    let q = null;
    for (let i = 0; i < part.length; i++) {
        const c = part[i];
        if (c === "\\" && q !== "'") {
            i++;
            continue;
        }
        if (q === null && c === "$" && part[i + 1] === "'") {
            q = "$'";
            i++;
            continue;
        }
        if (q) {
            if ((q === "$'" && c === "'") || c === q)
                q = null;
            continue;
        }
        if (c === "'" || c === '"') {
            q = c;
            continue;
        }
        if (c === "<" && part[i + 1] === "<" && part[i + 2] !== "<") {
            let j = i + 2;
            let stripTabs = false;
            if (part[j] === "-") {
                stripTabs = true;
                j++;
            }
            while (j < part.length && (part[j] === " " || part[j] === "\t"))
                j++;
            const rest = part.slice(j);
            const dm = /^(?:'([A-Za-z_][A-Za-z0-9_-]*)'|"([A-Za-z_][A-Za-z0-9_-]*)"|\\([A-Za-z_][A-Za-z0-9_-]*)|([A-Za-z_][A-Za-z0-9_-]*))/.exec(rest);
            if (dm) {
                const delim = dm[1] ?? dm[2] ?? dm[3] ?? dm[4] ?? "";
                if (delim)
                    results.push({ stripTabs, delim });
                i = j + dm[0].length - 1;
            }
        }
    }
    return results;
}
/**
 * Extract shell mutation units in a single stateful pass:
 * - Preserves multi-line quoted strings on header lines (`printf '%s\n' 'def f():\n    pass' > a.py`).
 * - Detects unquoted heredocs in any inline part (never matching `<<EOF` inside quotes).
 * - Consumes heredoc bodies as raw physical lines (so apostrophes like `// don't` never corrupt parsing).
 */
function splitShellCommandsPreservingHeredocs(command) {
    const units = [];
    let pos = 0;
    const len = command.length;
    while (pos < len) {
        // Read one logical command header line, preserving quotes across newlines.
        let header = "";
        let q = null;
        while (pos < len) {
            const c = command[pos];
            if (c === "\\" && q !== "'") {
                header += c + (command[pos + 1] ?? "");
                pos += pos + 1 < len ? 2 : 1;
                continue;
            }
            if (q === null && c === "$" && command[pos + 1] === "'") {
                q = "$'";
                header += "$'";
                pos += 2;
                continue;
            }
            if (q) {
                header += c;
                pos++;
                if ((q === "$'" && c === "'") || c === q)
                    q = null;
                continue;
            }
            if (c === "'" || c === '"') {
                q = c;
                header += c;
                pos++;
                continue;
            }
            if (c === "\n") {
                pos++;
                break;
            }
            header += c;
            pos++;
        }
        const inlineParts = splitInlineShellList(header);
        if (inlineParts.length === 0)
            continue;
        const partBodies = inlineParts.map((part) => [part]);
        const pendingHeredocs = [];
        for (let p = 0; p < inlineParts.length; p++) {
            for (const hd of extractUnquotedHeredocs(inlineParts[p])) {
                pendingHeredocs.push({ partIdx: p, ...hd });
            }
        }
        for (const hd of pendingHeredocs) {
            while (pos < len) {
                const nl = command.indexOf("\n", pos);
                const rawLine = nl === -1 ? command.slice(pos) : command.slice(pos, nl);
                pos = nl === -1 ? len : nl + 1;
                partBodies[hd.partIdx].push(rawLine);
                const cmp = hd.stripTabs ? rawLine.replace(/^\t+/, "") : rawLine;
                if (cmp.trimEnd() === hd.delim)
                    break;
            }
        }
        for (const lines of partBodies) {
            units.push(lines.join("\n"));
        }
    }
    return units.length > 0 ? units : [command];
}
/** Extract unquoted string argument payloads from `echo`/`printf` shell mutation commands (decoding `\n`/`\t` for `printf` and `echo -e`). */
function extractQuotedShellWritePayloads(unit) {
    if (!/^\s*(?:sudo\s+)?(?:echo|printf)\b/i.test(unit))
        return [];
    const interpretsEscapes = /^\s*(?:[sS][uU][dD][oO]\s+)?(?:[pP][rR][iI][nN][tT][fF]\b|[eE][cC][hH][oO](?:\s+-[a-zA-Z]+)*\s+-[a-zA-Z]*e)/.test(unit);
    const decodePrintfEscapes = (raw) => interpretsEscapes
        ? raw.replace(/\\([ntrv\\])/g, (_m, ch) => ch === "n" ? "\n" : ch === "t" ? "\t" : ch === "r" ? "\r" : ch === "\\" ? "\\" : `\\${ch}`)
        : raw;
    const payloads = [];
    let i = 0;
    while (i < unit.length) {
        const c = unit[i];
        if (c === "\\" && i + 1 < unit.length) {
            i += 2;
            continue;
        }
        if (c === "$" && unit[i + 1] === "'") {
            i += 2;
            let val = "";
            while (i < unit.length && unit[i] !== "'") {
                if (unit[i] === "\\" && i + 1 < unit.length) {
                    const esc = unit[++i];
                    val += esc === "n" ? "\n" : esc === "t" ? "\t" : esc;
                }
                else {
                    val += unit[i];
                }
                i++;
            }
            if (i < unit.length)
                i++;
            if (val)
                payloads.push(val);
            continue;
        }
        if (c === "'" || c === '"') {
            const q = c;
            i++;
            let val = "";
            while (i < unit.length && unit[i] !== q) {
                if (q === '"' && unit[i] === "\\" && i + 1 < unit.length) {
                    const next = unit[++i];
                    // In POSIX double quotes, only `"`, `\`, `$`, `` ` `` are shell-escaped; keep `\n`/`\t` for printf/echo -e!
                    if (next === '"' || next === "\\" || next === "$" || next === "`") {
                        val += next;
                    }
                    else {
                        val += `\\${next}`;
                    }
                }
                else {
                    val += unit[i];
                }
                i++;
            }
            if (i < unit.length)
                i++;
            const decoded = decodePrintfEscapes(val);
            if (decoded)
                payloads.push(decoded);
            continue;
        }
        i++;
    }
    return payloads;
}
/** Extract the unquoted or quoted stdout redirection/tee file target from a command header line. */
function extractShellRedirectionTarget(headerLine) {
    const tokens = [];
    let cur = "";
    let has = false;
    let q = null;
    for (let i = 0; i < headerLine.length; i++) {
        const c = headerLine[i];
        if (c === "\\" && q !== "'") {
            has = true;
            cur += headerLine[++i] ?? "";
            continue;
        }
        if (q === null && c === "$" && headerLine[i + 1] === "'") {
            has = true;
            q = "$'";
            i++;
            continue;
        }
        if (q) {
            if ((q === "$'" && c === "'") || c === q)
                q = null;
            else
                cur += c;
            continue;
        }
        if (c === "'" || c === '"') {
            has = true;
            q = c;
            continue;
        }
        if (c === "|") {
            if (has) {
                tokens.push({ kind: "word", text: cur });
                cur = "";
                has = false;
            }
            tokens.push({ kind: "pipe", text: "|" });
            continue;
        }
        if (c === ">") {
            let kind = "stdout-redir";
            if (has) {
                if (/^\d+$/.test(cur)) {
                    const fd = Number(cur);
                    if (fd >= 2)
                        kind = "other-fd-redir";
                    cur = "";
                    has = false;
                }
                else if (cur === "&") {
                    cur = "";
                    has = false;
                }
                else {
                    tokens.push({ kind: "word", text: cur });
                    cur = "";
                    has = false;
                }
            }
            if (headerLine[i + 1] === ">") {
                tokens.push({ kind, text: ">>" });
                i++;
            }
            else
                tokens.push({ kind, text: ">" });
            continue;
        }
        if (/\s/.test(c)) {
            if (has) {
                tokens.push({ kind: "word", text: cur });
                cur = "";
                has = false;
            }
            continue;
        }
        has = true;
        cur += c;
    }
    if (has)
        tokens.push({ kind: "word", text: cur });
    for (let idx = 0; idx < tokens.length; idx++) {
        const tok = tokens[idx];
        if (tok.kind === "other-fd-redir") {
            // Skip stderr / fd>=2 target token so `2>fixtures/err.log > src/app.ts` finds `src/app.ts`.
            idx++;
            continue;
        }
        if (tok.kind === "stdout-redir") {
            const next = tokens[idx + 1];
            if (next?.kind === "word" && !next.text.startsWith("&") && next.text !== "/dev/null") {
                return next.text;
            }
            continue;
        }
        const isCommandPos = idx === 0 || tokens[idx - 1]?.kind === "pipe";
        if (isCommandPos && tok.kind === "word" && /^(?:\/[^\s]*\/)?tee$/i.test(tok.text)) {
            let j = idx + 1;
            while (j < tokens.length && tokens[j].kind === "word" && tokens[j].text.startsWith("-"))
                j++;
            const next = tokens[j];
            if (next?.kind === "word" && next.text !== "/dev/null")
                return next.text;
        }
    }
    return undefined;
}
/**
 * Patterns that indicate fake or stubbed implementations in code.
 */
export const STUB_PATTERNS = [
    {
        regex: /throw\s+new\s+(?:NotImplementedError|Error\s*\(\s*["'`][^"'`]*(?:\bnot\s+implemented\b|\btodo\b|\bto\s+be\s+implemented\b|\bstub\b|\bplaceholder\b)[^"'`]*["'`]\s*\))/i,
        name: "throw NotImplementedError",
    },
    {
        regex: /raise\s+NotImplementedError(?:\s*\(.*\))?/i,
        name: "raise NotImplementedError (Python)",
    },
    {
        regex: /\b(?:todo!|unimplemented!)\s*\(/i,
        name: "todo! / unimplemented! macro (Rust)",
    },
    {
        regex: /\bpanic\s*\(\s*["'`][^"'`]*(?:\bnot\s+implemented\b|\btodo\b|\bstub\b)[^"'`]*["'`]\s*\)/i,
        name: "panic('not implemented') (Go/Rust)",
    },
    {
        regex: /(?:\/\/|#|\/\*)\s*(?:TODO|FIXME|STUB|PLACEHOLDER)\s*:\s*(?:implement|add\s+logic|fill\s+in|complete\s+this)/i,
        name: "TODO: implement comment",
    },
    {
        regex: /def\s+\w+\s*\(.*?\)\s*:\s*(?:#[^\n]*\n\s*)*pass\b/,
        name: "empty def ...: pass (Python stub)",
    },
    {
        regex: /\breturn\s+(?:null|undefined|true|false|\[\]|\{\})\s*;?\s*(?:\/\/|#)\s*(?:TODO|FIXME|stub|placeholder|temporary)\b/i,
        name: "placeholder constant return",
    },
    {
        regex: /\breturn\s+None\s*(?:#\s*(?:TODO|FIXME|stub|placeholder|temporary)\b)/i,
        name: "placeholder return None (Python)",
    },
];
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
export const noStubsRule = {
    id: "integrity/no-stubs",
    description: "Prevents unfinished functions, NotImplemented stubs, and placeholder methods in code.",
    inspect: (context) => {
        const findings = [];
        const seen = new Set();
        const checkCode = (code, source, filePath) => {
            if (!code || typeof code !== "string")
                return;
            const executable = maskCodeLiterals(code, false, filePath);
            const withComments = maskCodeLiterals(code, true, filePath);
            const fixture = /(?:^|[/\\])(?:__fixtures__|fixtures)(?:[/\\]|$)/i.test(filePath ?? "");
            if (fixture || /\.d\.[cm]?ts$/i.test(filePath ?? ""))
                return;
            const normalizedPath = (filePath ?? "").replace(/\\/g, "/");
            const relPath = filePath && context.directory
                ? path.relative(path.resolve(context.directory), path.resolve(context.directory, normalizedPath)).replace(/\\/g, "/")
                : normalizedPath;
            const isTestFile = /(?:^|\/)(?:__tests__|tests)(?:\/|$)|^test\/|\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(normalizedPath) ||
                /^test\//i.test(relPath);
            const isJsTsFile = !filePath || /\.[cm]?[jt]sx?$/i.test(filePath);
            const fileScope = filePath ?? source;
            const perCallCounts = new Map();
            for (const pattern of STUB_PATTERNS) {
                if (findings.length >= 20)
                    break;
                const view = /comment|placeholder (?:constant return|return None)/.test(pattern.name) ? withComments : executable;
                const regex = new RegExp(pattern.regex.source, `${pattern.regex.flags.replace(/g/g, "")}g`);
                let match = regex.exec(code);
                while (match && findings.length < 20) {
                    if (view[match.index] === code[match.index]) {
                        const matchText = match[0].trim();
                        const baseKey = `${fileScope}:${pattern.name}:${matchText}`;
                        const occ = (perCallCounts.get(baseKey) ?? 0) + 1;
                        perCallCounts.set(baseKey, occ);
                        const dedupKey = occ === 1 ? baseKey : `${baseKey}#${occ}`;
                        if (!seen.has(dedupKey)) {
                            seen.add(dedupKey);
                            const snippet = extractSnippet(code, match.index, match[0].length);
                            findings.push({
                                ruleId: "integrity/no-stubs",
                                pattern: pattern.name,
                                messageSnippet: snippet,
                                description: `Stub / incomplete implementation detected in ${source}: "${match[0]}" → "${snippet}"`,
                                ...(filePath ? {
                                    filePath,
                                    fingerprint: occ === 1
                                        ? `${filePath}:${pattern.name}:${matchText}`
                                        : `${filePath}:${pattern.name}:${matchText}#${occ}`,
                                } : {}),
                            });
                        }
                    }
                    if (match[0].length === 0)
                        regex.lastIndex++;
                    match = regex.exec(code);
                }
            }
            if (!isTestFile && isJsTsFile) {
                const emptyPatterns = [
                    /\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?::\s*[A-Za-z_$][^{};]*)?\{\s*\}/g,
                    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{\s*\}/g,
                    /(?:^|[{};\n])\s*(?:(?:public|private|protected|static|async|override)\s+)*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?::\s*[A-Za-z_$][^{};]*)?\{\s*\}/g,
                ];
                for (const regex of emptyPatterns) {
                    for (const match of executable.matchAll(regex)) {
                        if (findings.length >= 20)
                            break;
                        if (/^(?:constructor|noop|if|for|while|switch|catch)$/i.test(match[1] ?? ""))
                            continue;
                        const name = "empty named JavaScript/TypeScript implementation";
                        const dedupKey = `${fileScope}:${name}:${match[1] ?? ""}`;
                        if (seen.has(dedupKey))
                            continue;
                        seen.add(dedupKey);
                        findings.push({ ruleId: "integrity/no-stubs", pattern: name,
                            messageSnippet: extractSnippet(code, match.index, match[0].length),
                            description: `Empty named implementation detected in ${source}; implement it or use an explicit no-op callback contract.`,
                            ...(filePath ? { filePath, fingerprint: `${filePath}:${name}:${match[1]}` } : {}),
                        });
                    }
                }
            }
        };
        for (const msg of context.currentTurn) {
            if (msg.info.role !== "assistant")
                continue;
            for (const part of msg.parts) {
                if (part.type === "tool" && part.state?.input) {
                    const input = part.state.input;
                    const patchRaw = input.patchText ?? input.patch;
                    const targetFile = input.path ??
                        input.targetFile ??
                        input.TargetFile ??
                        input.filePath ??
                        input.file ??
                        extractFilePathFromPatch(patchRaw);
                    for (const [key, label] of [
                        ["content", "file write content"],
                        ["new_string", "file edit"],
                        ["newString", "file edit"],
                        ["new_str", "file edit"],
                        ["appendContent", "file edit"],
                        ["prependContent", "file edit"],
                        ["file_text", "file write content"],
                        ["CodeContent", "file write content"],
                        ["ReplacementContent", "file edit"],
                        ["text", "file write content"],
                    ]) {
                        if (typeof input[key] === "string") {
                            checkCode(input[key], label, targetFile);
                        }
                    }
                    for (const edit of extractStructuredEditTexts(input, targetFile)) {
                        checkCode(edit.text, "structured file edit", edit.filePath);
                    }
                    for (const section of splitFilePatches(patchRaw)) {
                        const patchText = extractAddedLines(section.patch);
                        if (patchText)
                            checkCode(patchText, "patch added lines", section.filePath ?? targetFile);
                    }
                    const shellMutation = extractLikelyShellMutation(input);
                    if (shellMutation) {
                        // Split top-level command units while preserving multi-line heredoc bodies intact,
                        // so an earlier harmless redirection (`echo "" > types.d.ts && cat << EOF > src/app.ts`)
                        // cannot exempt a later stubbed write and heredoc targets (`tests/`, `__fixtures__/`) remain scoped.
                        for (const unit of splitShellCommandsPreservingHeredocs(shellMutation)) {
                            const firstLine = unit.split("\n", 1)[0] ?? unit;
                            const isHeredoc = extractUnquotedHeredocs(firstLine).length > 0;
                            const shellTarget = extractShellRedirectionTarget(isHeredoc ? firstLine : unit);
                            checkCode(unit, "shell file mutation", shellTarget);
                            if (!isHeredoc) {
                                for (const payload of extractQuotedShellWritePayloads(unit)) {
                                    checkCode(payload, "shell file mutation", shellTarget);
                                }
                            }
                        }
                    }
                }
            }
        }
        if (findings.length === 0) {
            return {
                ruleId: "integrity/no-stubs",
                decision: "pass",
                findings: [],
            };
        }
        const list = findings.map((f) => `  - [${f.pattern}] → ${f.messageSnippet}`).join("\n");
        const remediationPrompt = `Incomplete or stubbed implementation detected in this turn:\n${list}\n\n` +
            `ACTION REQUIRED:\n` +
            `1. Open the file containing the stub/placeholder.\n` +
            `2. Replace the placeholder (TODO, pass, empty stub, or NotImplementedError) with the actual, working implementation.\n` +
            `3. Do NOT stop or claim completion until all flagged methods and logic are fully implemented.`;
        return {
            ruleId: "integrity/no-stubs",
            decision: "block",
            findings,
            remediationPrompt,
        };
    },
};
