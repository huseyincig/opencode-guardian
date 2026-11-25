/**
 * Conservative shell-pattern inspection, not an interpreter or a permission
 * boundary. Recognize common literal shell rewrites without executing input.
 */
/**
 * Split only on top-level shell separators. Quoted examples and separators
 * inside command substitutions must not become independently executed stages.
 */
export function splitShellStages(command) {
    const groups = [];
    let pipeline = [];
    let segment = "";
    const stack = [
        { quote: null, parens: 0 },
    ];
    const pushStage = () => {
        if (segment.trim())
            pipeline.push(segment.trim());
        segment = "";
    };
    const pushPipeline = () => {
        pushStage();
        if (pipeline.length)
            groups.push(pipeline);
        pipeline = [];
    };
    for (let i = 0; i < command.length; i++) {
        const ch = command[i];
        const top = stack[stack.length - 1];
        if (ch === "\\" && top.quote !== "'") {
            segment += ch + (command[++i] ?? "");
            continue;
        }
        if (top.quote === null && ch === "$" && command[i + 1] === "'") {
            top.quote = "$'";
            segment += "$'";
            i++;
            continue;
        }
        if (ch === "$" && command[i + 1] === "(" && top.quote !== "'" && top.quote !== "$'") {
            stack.push({ quote: null, parens: 1 });
            segment += "$(";
            i++;
            continue;
        }
        if (ch === "'" && top.quote === "$'") {
            top.quote = null;
        }
        else if (ch === "'" && top.quote !== '"') {
            top.quote = top.quote === "'" ? null : "'";
        }
        else if (ch === '"' && top.quote !== "'" && top.quote !== "$'") {
            top.quote = top.quote === '"' ? null : '"';
        }
        if (stack.length > 1 && !top.quote) {
            if (ch === "(")
                top.parens++;
            else if (ch === ")") {
                top.parens--;
                if (top.parens === 0)
                    stack.pop();
            }
        }
        if (stack.length === 1 && !top.quote) {
            if (ch === "|" && command[i + 1] !== "|") {
                pushStage();
                if (command[i + 1] === "&")
                    i++;
                continue;
            }
            const isRedirectionAmpersand = ch === "&" &&
                (command[i - 1] === ">" ||
                    command[i - 1] === "<" ||
                    (command[i + 1] === ">" && command[i - 1] !== "&"));
            if (!isRedirectionAmpersand &&
                (ch === ";" || ch === "\n" || ch === "&" || (ch === "|" && command[i + 1] === "|"))) {
                pushPipeline();
                if ((ch === "&" || ch === "|") && command[i + 1] === ch)
                    i++;
                continue;
            }
        }
        segment += ch;
    }
    pushPipeline();
    return groups;
}
const ABS_BIN_PREFIX = "(?:\\/(?:[A-Za-z0-9._-]+\\/)+)?";
function stripOuterGroupDelimiters(stage) {
    let current = stage.trim();
    for (let i = 0; i < 6; i++) {
        let next = current;
        if (next.startsWith("(") && next.endsWith(")")) {
            next = next.slice(1, -1).trim();
        }
        else if (next.startsWith("{") && next.endsWith("}")) {
            next = next.slice(1, -1).trim().replace(/;\s*$/, "").trim();
        }
        else if (next.startsWith("(")) {
            next = next.slice(1).trim();
        }
        else if (next.startsWith("{")) {
            next = next.slice(1).trim();
        }
        else if (next.endsWith(")") && !next.includes("(")) {
            next = next.slice(0, -1).trim();
        }
        else if (next.endsWith("}") && !next.includes("{")) {
            next = next.slice(0, -1).trim().replace(/;\s*$/, "").trim();
        }
        if (next === current)
            break;
        current = next;
    }
    return current;
}
const WRAPPER_PREFIX_REGEXES = [
    // Leading redirections before a command (e.g. `2>/dev/null rm -rf /`, `< in.txt rm -rf /`)
    /^(?:\d*>>?|\d*<&|\d*>&|&>>?|<)\s*(?:"[^"]*"|'[^']*'|[^\s;&|]+)\s+/,
    /^\d*>&\d+\s+/,
    // sudo with case-sensitive boolean vs value-taking short flags (never let `-H`/`-P` or `-uroot`/`-Dtmp` eat the command!)
    new RegExp(`^${ABS_BIN_PREFIX}[sS][uU][dD][oO](?:\\s+(?:(?:-[ABEFGHIJKLMNOPQSTUVWXYZabdefijklmnoqsvwxyz]*[ugCprthDUcRT]|--user|--group|--chdir|--host|--prompt|--role|--type|--other-user|--close-from|--login-class|--selinux-role|--selinux-type)\\s+\\S+|-[ABEFGHIJKLMNOPQSTUVWXYZabdefijklmnoqsvwxyz]*[ugCprthDUcRT]\\S+|-[ABEFGHIJKLMNOPQSTUVWXYZabdefijklmnoqsvwxyz]+|--[a-z-]+(?:=\\S+)?))*(?:\\s+--)?\\s+`),
    // command / command -p ONLY (never strip command -v or -V!)
    /^command(?:\s+-p)*(?:\s+--)?\s+/i,
    new RegExp(`^${ABS_BIN_PREFIX}time(?:\\s+-\\S+)*\\s+`, "i"),
    new RegExp(`^${ABS_BIN_PREFIX}nohup\\s+`, "i"),
    new RegExp(`^${ABS_BIN_PREFIX}setsid(?:\\s+(?:--?[a-zA-Z-]+))*\\s+`, "i"),
    new RegExp(`^${ABS_BIN_PREFIX}nice(?:\\s+(?:-n\\s*-?\\d+|--adjustment(?:=\\S+|\\s+\\S+)|-\\d+))?\\s+`, "i"),
    new RegExp(`^${ABS_BIN_PREFIX}ionice(?:\\s+(?:-[cn]\\s*\\S+|--class(?:=\\S+|\\s+\\S+)|-t))*\\s+`, "i"),
    new RegExp(`^${ABS_BIN_PREFIX}stdbuf(?:\\s+(?:-[ioe]\\s+\\S+|-[ioe]\\S+|--(?:input|output|error)(?:=\\S+|\\s+\\S+)))*\\s+`, "i"),
    /^exec(?:\s+(?:-a\s+\S+|-[cl]+))*(?:\s+--)?\s+/i,
    /^builtin\s+/i,
    new RegExp(`^${ABS_BIN_PREFIX}timeout(?:\\s+(?:(?:-[ks]|--kill-after|--signal)\\s+\\S+|-[ks]\\S+|--?[a-z-]+(?:=\\S+)?))*\\s+\\d+(?:\\.\\d+)?[smhd]?\\s+`, "i"),
    // Leading VAR=VAL assignments before an executable
    /^(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S+)\s+)+/,
];
/**
 * Strip `env [opts] [VAR=VAL ...] <command>` ONLY when a real downstream command
 * is present. Preserves `env`, `env -0`, `env --null`, `env FOO=1`, `env -u PATH`,
 * `env > file`, and `env -S "..."` unchanged.
 */
function stripEnvWrapper(stage) {
    const head = new RegExp(`^${ABS_BIN_PREFIX}env(?:\\s+|$)`, "i").exec(stage);
    if (!head)
        return stage;
    let i = head[0].length;
    const len = stage.length;
    const readWord = () => {
        while (i < len && /\s/.test(stage[i]))
            i++;
        if (i >= len)
            return undefined;
        const start = i;
        let q = null;
        while (i < len) {
            const ch = stage[i];
            if (ch === "\\" && q !== "'") {
                i += 2;
                continue;
            }
            if (q === null && ch === "$" && stage[i + 1] === "'") {
                q = "$'";
                i += 2;
                continue;
            }
            if (q) {
                if ((q === "$'" && ch === "'") || ch === q)
                    q = null;
                i++;
                continue;
            }
            if (ch === "'" || ch === '"') {
                q = ch;
                i++;
                continue;
            }
            if (/\s/.test(ch))
                break;
            i++;
        }
        return { raw: stage.slice(start, i), start, end: i };
    };
    let endOfOpts = false;
    while (true) {
        const word = readWord();
        if (!word)
            return stage;
        const tok = word.raw;
        if (!endOfOpts) {
            if (tok === "--" || tok === "-") {
                endOfOpts = true;
                continue;
            }
            // Leave `-S` / `--split-string` for `literalShellScripts` (only boolean flags `[i0v]` may precede `S`,
            // never `-uSECRET` or `-CSrc`).
            if (tok === "-S" ||
                tok.startsWith("-S") ||
                tok === "--split-string" ||
                tok.startsWith("--split-string=") ||
                /^-[i0v]+S/.test(tok)) {
                return stage;
            }
            if (tok === "-u" ||
                tok === "--unset" ||
                tok === "-C" ||
                tok === "--chdir" ||
                /^-[i0v]+[uC]$/.test(tok)) {
                if (!readWord())
                    return stage;
                continue;
            }
            if (tok.startsWith("-C") ||
                tok.startsWith("--chdir=") ||
                tok.startsWith("--unset=") ||
                tok.startsWith("-u") ||
                /^-[i0v]+[uC].+/.test(tok) ||
                /^--(?:ignore-signal|default-signal|block-signal)(?:=\S*)?$/.test(tok)) {
                continue;
            }
            if (/^-[i0v]+$/.test(tok) || /^--(?:ignore-environment|null|debug)$/.test(tok)) {
                continue;
            }
            if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tok)) {
                continue;
            }
            if (tok.startsWith("-") || /^(?:\d*>>?|\d*<&|\d*>&|&>>?|<)/.test(tok)) {
                return stage;
            }
        }
        else {
            if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tok)) {
                continue;
            }
            if (/^(?:\d*>>?|\d*<&|\d*>&|&>>?|<)/.test(tok)) {
                return stage;
            }
        }
        return stage.slice(word.start).trim();
    }
}
// Case-sensitive flock flags so boolean `-e` (`--exclusive`) never matches value-taking `-E` (`--conflict-exit-code`).
const FLOCK_WRAPPER_REGEX = new RegExp(`^${ABS_BIN_PREFIX}[fF][lL][oO][cC][kK](?:\\s+(?:(?:-w|--timeout|-E|--conflict-exit-code)\\s+\\S+|--(?:timeout|conflict-exit-code)=\\S+|-[sxnoueF]+|--(?:shared|exclusive|nonblock|nb|unlock|no-fork|close|verbose)))*\\s+(?:"[^"]*"|'[^']*'|\\S+)(?:\\s+--)?\\s+(?!(?:-c|--command)\\b)`);
/**
 * Strip common transparent process launchers, subshell parens, env assignments,
 * and leading absolute binary paths on the command token (never stripping
 * `command -v`/`-V` or bare `env`).
 */
export function stripShellWrappersAndPath(stage, options = {}) {
    let current = stripOuterGroupDelimiters(stage);
    for (let i = 0; i < 8; i++) {
        let next = stripOuterGroupDelimiters(current);
        if (options.stripNegation) {
            next = next.replace(/^!\s+/, "").trim();
        }
        next = stripEnvWrapper(next);
        for (const pattern of WRAPPER_PREFIX_REGEXES) {
            next = next.replace(pattern, "").trim();
        }
        if (options.stripFlock !== false) {
            next = next.replace(FLOCK_WRAPPER_REGEX, "").trim();
        }
        // Unquote a quoted executable name token like `'rm' -rf /` or `"rm" -rf /`.
        next = next.replace(/^(['"])([A-Za-z0-9._+/=-]+)\1(?=\s|$)/, "$2");
        if (next === current)
            break;
        current = next;
    }
    // Normalize leading absolute executable path (e.g. /bin/rm -> rm, /usr/bin/env -> env).
    current = current.replace(/^\/(?:[A-Za-z0-9._-]+\/)+([A-Za-z0-9._+-]+)(?=\s|$)/, "$1");
    return current.trim();
}
export function shellCommandVariants(command) {
    return splitShellStages(command).flatMap((stages) => stages.flatMap((stage) => {
        const canonical = stage
            // Empty quote pairs and escaped command letters disappear in the shell.
            .replace(/(?<!\\)(?:''|"")/g, "")
            .replace(/\\([A-Za-z])/g, "$1")
            // A literal IFS expansion can separate shell arguments.
            .replace(/\$\{IFS\}|\$IFS(?=[^A-Za-z0-9_]|$)/g, " ")
            // Strip inline file-descriptor duplication/redirections so e.g. 'git 2>&1 reset --hard' matches.
            .replace(/(?:^|\s)(?:\d*>&\d+|\d*<&\d+)(?=\s|$)/g, " ")
            // Only resolve a known literal command name, not arbitrary substitutions.
            .replace(/\$\(\s*(?:echo|printf(?:\s+%s)?)\s+(?:(["'])rm\1|rm)\s*\)/gi, "rm");
        // A literal backtick substitution in command position supplies the
        // executable name. This is unlike a passive \`echo \`...\`\` example.
        const expanded = canonical.replace(/^(\s*(?:sudo\s+)?)(?:\x60(?:echo\s+|printf(?:\s+%s)?\s+)(?:['"]?rm['"]?)\x60)(?=\s|$)/i, "$1rm");
        const unwrappedStage = stripShellWrappersAndPath(stage, { stripNegation: true });
        const unwrappedExpanded = stripShellWrappersAndPath(expanded, { stripNegation: true });
        return [...new Set([stage, canonical, expanded, unwrappedStage, unwrappedExpanded])].filter(Boolean);
    }));
}
/** Only active $(...) expressions; text inside single quotes is inert. */
export function activeCommandSubstitutions(command) {
    const found = [];
    let quote = null;
    for (let i = 0; i < command.length; i++) {
        const ch = command[i];
        if (ch === "\\" && quote !== "'") {
            i++;
            continue;
        }
        if (quote === null && ch === "$" && command[i + 1] === "'") {
            quote = "$'";
            i++;
            continue;
        }
        if (ch === "'" && quote === "$'") {
            quote = null;
            continue;
        }
        if (ch === "'" && quote !== '"') {
            quote = quote === "'" ? null : "'";
            continue;
        }
        if (ch === '"' && quote !== "'" && quote !== "$'") {
            quote = quote === '"' ? null : '"';
            continue;
        }
        if (quote === "'" || quote === "$'" || ch !== "$" || command[i + 1] !== "(")
            continue;
        const start = i + 2;
        let depth = 1;
        let nestedQuote = null;
        let end = start;
        for (; end < command.length; end++) {
            const next = command[end];
            if (next === "\\" && nestedQuote !== "'") {
                end++;
                continue;
            }
            if (nestedQuote === null && next === "$" && command[end + 1] === "'") {
                nestedQuote = "$'";
                end++;
                continue;
            }
            if (next === "'" && nestedQuote === "$'") {
                nestedQuote = null;
                continue;
            }
            if (next === "'" && nestedQuote !== '"') {
                nestedQuote = nestedQuote === "'" ? null : "'";
                continue;
            }
            if (next === '"' && nestedQuote !== "'" && nestedQuote !== "$'") {
                nestedQuote = nestedQuote === '"' ? null : '"';
                continue;
            }
            if (nestedQuote)
                continue;
            if (next === "(")
                depth++;
            if (next === ")" && --depth === 0)
                break;
        }
        if (depth === 0) {
            found.push(command.slice(start, end));
            i = end;
        }
    }
    return found;
}
/** Only active paired backtick substitutions; single-quoted text and escaped
 * delimiters are inert. The returned script is classified, never executed. */
export function activeBacktickSubstitutions(command) {
    const scripts = [];
    let quote = null;
    for (let i = 0; i < command.length; i++) {
        const ch = command[i];
        if (ch === "\\" && quote !== "'") {
            i++;
            continue;
        }
        if (quote === null && ch === "$" && command[i + 1] === "'") {
            quote = "$'";
            i++;
            continue;
        }
        if (ch === "'" && quote === "$'") {
            quote = null;
            continue;
        }
        if (ch === "'" && quote !== '"') {
            quote = quote === "'" ? null : "'";
            continue;
        }
        if (ch === '"' && quote !== "'" && quote !== "$'") {
            quote = quote === '"' ? null : '"';
            continue;
        }
        if (ch !== "\x60" || quote === "'" || quote === "$'")
            continue;
        let end = i + 1;
        for (; end < command.length; end++) {
            if (command[end] === "\\") {
                end++;
                continue;
            }
            if (command[end] === "\x60")
                break;
        }
        if (end < command.length) {
            scripts.push(command.slice(i + 1, end));
            i = end;
        }
    }
    return scripts;
}
/** Unquote simple eval arguments like `eval "rm" "-rf" "/"` or `eval rm -rf /`. */
function unwrapEvalArgs(rawArgs) {
    const tokens = [];
    let cur = "";
    let has = false;
    let quote = null;
    for (let i = 0; i < rawArgs.length; i++) {
        const ch = rawArgs[i];
        if (ch === "\\" && quote !== "'") {
            has = true;
            cur += rawArgs[++i] ?? "";
            continue;
        }
        if (quote === null && ch === "$" && rawArgs[i + 1] === "'") {
            quote = "$'";
            has = true;
            i++;
            continue;
        }
        if (quote) {
            if ((quote === "$'" && ch === "'") || ch === quote) {
                quote = null;
            }
            else {
                cur += ch;
            }
            continue;
        }
        if (ch === "'" || ch === '"') {
            quote = ch;
            has = true;
            continue;
        }
        if (/\s/.test(ch)) {
            if (has) {
                tokens.push(cur);
                cur = "";
                has = false;
            }
            continue;
        }
        has = true;
        cur += ch;
    }
    if (has)
        tokens.push(cur);
    return tokens.join(" ").trim();
}
/** Split a single shell stage into raw shell words preserving quotes/escapes. */
function splitRawShellWords(stage) {
    const words = [];
    let i = 0;
    const len = stage.length;
    while (i < len) {
        while (i < len && /\s/.test(stage[i]))
            i++;
        if (i >= len)
            break;
        const start = i;
        let q = null;
        while (i < len) {
            const ch = stage[i];
            if (ch === "\\" && q !== "'") {
                i += 2;
                continue;
            }
            if (q === null && ch === "$" && stage[i + 1] === "'") {
                q = "$'";
                i += 2;
                continue;
            }
            if (q) {
                if ((q === "$'" && ch === "'") || ch === q)
                    q = null;
                i++;
                continue;
            }
            if (ch === "'" || ch === '"') {
                q = ch;
                i++;
                continue;
            }
            if (/\s/.test(ch))
                break;
            i++;
        }
        words.push(stage.slice(start, i));
    }
    return words;
}
/** Extract the literal command string passed to `sh/bash/zsh/dash/ksh -c` (including flags after `-c`, `-`, `-O`, `-eo`, and mixed-quote words). */
function extractPosixShellCScript(stage) {
    const words = splitRawShellWords(stage);
    if (words.length < 3 || !/^(?:sh|bash|zsh|dash|ksh)$/i.test(words[0]))
        return undefined;
    let sawC = false;
    let idx = 1;
    while (idx < words.length) {
        const tok = words[idx];
        if (tok === "--" || tok === "-") {
            idx++;
            break;
        }
        if (tok === "-o" || tok === "+o" || tok === "-O" || tok === "+O" || tok === "--rcfile" || tok === "--init-file") {
            idx += 2;
            continue;
        }
        if (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(tok)) {
            sawC = true;
            idx += /[oO]/.test(tok) ? 2 : 1;
            continue;
        }
        if (/^[+-][a-zA-Z]*[oO][a-zA-Z]*$/.test(tok)) {
            idx += 2;
            continue;
        }
        if (/^[+-][a-zA-Z0-9-]+(?:=\S+)?$/.test(tok)) {
            idx++;
            continue;
        }
        break;
    }
    if (!sawC || idx >= words.length)
        return undefined;
    return unwrapEvalArgs(words[idx]);
}
/** Extract the combined command string from `env -S/--split-string <str> [trailing...]`. */
function extractEnvSplitScript(stage) {
    const words = splitRawShellWords(stage);
    if (words.length < 2 || !/^env$/i.test(words[0]))
        return undefined;
    const finalize = (head, tailWords) => {
        const tail = tailWords.join(" ");
        const combined = tail ? `${head} ${tail}`.trim() : head.trim();
        // GNU `env -S` re-parses the split tokens through `env`'s own option/assignment parser
        // (e.g. `env -S "-i rm -rf /"`, `env -S "FOO=1"`, `env -S "-- rm -rf /"`).
        if (combined &&
            (/^(?:-(?![i0v]*S\b)(?!--split-string\b))/.test(combined) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(combined))) {
            return `env ${combined}`;
        }
        return combined;
    };
    let idx = 1;
    while (idx < words.length) {
        const tok = words[idx];
        if (tok === "--" || tok === "-")
            return undefined;
        if (tok === "-S" || tok === "--split-string") {
            const payload = words[idx + 1];
            if (payload === undefined)
                return undefined;
            return finalize(unwrapEvalArgs(payload), words.slice(idx + 2));
        }
        if (tok.startsWith("--split-string=")) {
            return finalize(unwrapEvalArgs(tok.slice("--split-string=".length)), words.slice(idx + 1));
        }
        if (tok.startsWith("-S") || /^-[i0v]+S/.test(tok)) {
            const sPos = tok.indexOf("S");
            const attached = tok.slice(sPos + 1);
            if (attached) {
                return finalize(unwrapEvalArgs(attached), words.slice(idx + 1));
            }
            const payload = words[idx + 1];
            if (payload === undefined)
                return undefined;
            return finalize(unwrapEvalArgs(payload), words.slice(idx + 2));
        }
        if (tok === "-u" || tok === "--unset" || tok === "-C" || tok === "--chdir" || /^-[i0v]+[uC]$/.test(tok)) {
            idx += 2;
            continue;
        }
        if (tok.startsWith("-u") ||
            tok.startsWith("-C") ||
            tok.startsWith("--unset=") ||
            tok.startsWith("--chdir=") ||
            /^-[i0v]+[uC].+/.test(tok) ||
            /^--(?:ignore-signal|default-signal|block-signal)(?:=\S*)?$/.test(tok) ||
            /^-[i0v]+$/.test(tok) ||
            /^--(?:ignore-environment|null|debug)$/.test(tok) ||
            /^[A-Za-z_][A-Za-z0-9_]*=/.test(tok)) {
            idx++;
            continue;
        }
        return undefined;
    }
    return undefined;
}
/** Literal script passed to a shell; dynamic scripts are not decoded here. */
export function literalShellScripts(command) {
    const scripts = [];
    // Match literal shell scripts, including common wrappers, full paths, extra flags
    // (-o/+o/long options, combined `-co <opt>`, flags after `-c`), `--`, ANSI-C `$'...'`,
    // mixed/concatenated quotes (`'rm'' -rf /'`, `rm' -rf /'`), flock -c/--command, env -S/-vS, and eval.
    const quotedChunk = `(?:\\$'(?:\\\\.|[^'\\\\])*'|'[^']*'|"(?:\\\\.|[^"\\\\])*")`;
    const quotedPayload = `(${quotedChunk}+)`;
    const flockPattern = new RegExp(`^[fF][lL][oO][cC][kK](?:\\s+(?:(?:-w|--timeout|-E|--conflict-exit-code)\\s+\\S+|--(?:timeout|conflict-exit-code)=\\S+|-[sxnoueF]+|--(?:shared|exclusive|nonblock|nb|unlock|no-fork|close|verbose)))*\\s+(?:"[^"]*"|'[^']*'|\\S+)\\s+(?:-c|--command)(?:\\s+--)?\\s+${quotedPayload}(?=\\s|$)`);
    const evalPattern = /^eval(?:\s+--)?\s+([\s\S]+)$/i;
    for (const stage of splitShellStages(command).flat()) {
        const withoutNonFlock = stripShellWrappersAndPath(stage, { stripFlock: false, stripNegation: true });
        const flockMatch = flockPattern.exec(withoutNonFlock);
        if (flockMatch?.[1] !== undefined) {
            scripts.push(unwrapEvalArgs(flockMatch[1]));
            continue;
        }
        const envSplitScript = extractEnvSplitScript(withoutNonFlock);
        if (envSplitScript !== undefined) {
            scripts.push(envSplitScript);
            continue;
        }
        const stripped = stripShellWrappersAndPath(stage, { stripFlock: true, stripNegation: true });
        const shellScript = extractPosixShellCScript(stripped);
        if (shellScript !== undefined) {
            scripts.push(shellScript);
            continue;
        }
        const evalMatch = evalPattern.exec(stripped);
        if (evalMatch?.[1]) {
            const evalScript = unwrapEvalArgs(evalMatch[1]);
            if (evalScript)
                scripts.push(evalScript);
        }
    }
    return scripts;
}
function unwrapLiteralWindowsScript(value) {
    const trimmed = value.trim();
    if (trimmed.length >= 2) {
        const first = trimmed[0];
        const last = trimmed.at(-1);
        if ((first === '"' || first === "'") && first === last) {
            return trimmed.slice(1, -1);
        }
    }
    return trimmed;
}
/** Literal scripts passed through Windows command interpreters. Encoded
 * PowerShell payloads are intentionally not decoded and are treated opaque. */
export function literalWindowsShellScripts(command) {
    const scripts = [];
    for (const stage of splitShellStages(command).flat()) {
        const stripped = stripShellWrappersAndPath(stage, { stripNegation: true });
        const cmd = /^(?:cmd(?:\.exe)?)(?:\s+\/[a-z](?::\S+)?)*\s+\/[ck]\s+([\s\S]+)$/i.exec(stripped);
        if (cmd?.[1]) {
            scripts.push(unwrapLiteralWindowsScript(cmd[1]));
            continue;
        }
        const powershell = /^(?:powershell|pwsh)(?:\.exe)?\b[\s\S]*?\s-(?:command|c)\s+([\s\S]+)$/i.exec(stripped);
        if (powershell?.[1]) {
            scripts.push(unwrapLiteralWindowsScript(powershell[1]));
        }
    }
    return scripts;
}
/** Find's deletion actions do not require the rm binary to run directly. */
export function hasFindDeletion(command) {
    return splitShellStages(command).flat().some((stage) => /^(?:sudo\s+)?find\b[^\n;&|]*\s(?:-delete\b|-exec(?:dir)?\s+(?:sudo\s+)?(?:\/(?:[A-Za-z0-9._-]+\/)+)?(?:rm|unlink)\b)/i.test(stripShellWrappersAndPath(stage, { stripNegation: true })));
}
/**
 * Decoding into a shell conceals the executed script. This is a warning
 * signal only: it does not prove that the decoded payload is destructive.
 */
export function isOpaqueShellExecution(command, depth = 0) {
    if (splitShellStages(command).flat().some((stage) => /^(?:powershell|pwsh)(?:\.exe)?\b[\s\S]*?\s-(?:encodedcommand|enc|ec|e)\b/i.test(stripShellWrappersAndPath(stage, { stripNegation: true })))) {
        return true;
    }
    if (splitShellStages(command).some((stages) => stages.some((stage, index) => {
        const left = stripShellWrappersAndPath(stage, { stripNegation: true });
        const right = stripShellWrappersAndPath(stages[index + 1] ?? "", { stripNegation: true });
        return (/^(?:openssl\s+)?base64\s+(?:-[dD]\b|--decode\b)/i.test(left) &&
            /^(?:sh|bash|zsh|dash|ksh)(?=\s|$)/i.test(right));
    }))) {
        return true;
    }
    return (depth < 4 &&
        [...literalShellScripts(command), ...literalWindowsShellScripts(command)].some((script) => isOpaqueShellExecution(script, depth + 1)));
}
/** An unresolved command substitution in executable position is opaque.
 * The strict preflight can reject it without treating ordinary echo output
 * or quoted documentation as a destructive action. */
export function hasDynamicCommandName(command, depth = 0) {
    for (const stage of splitShellStages(command).flat()) {
        const stripped = stripShellWrappersAndPath(stage, { stripNegation: true });
        if (/^\s*(?:sudo\s+)?(?:"|)(?:\x60|\$\(|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)/.test(stripped)) {
            return true;
        }
    }
    return depth < 4 && [
        ...literalShellScripts(command),
        ...literalWindowsShellScripts(command),
    ].some((script) => hasDynamicCommandName(script, depth + 1));
}
