import { isDestructiveCommand, isOpaqueShellExecution, isSimpleFileRemoval } from "./evidence.js";
import { assessCommandPreflight } from "./secrets/preflight.js";
import { hasDynamicCommandName, literalWindowsShellScripts, splitShellStages, stripShellWrappersAndPath } from "./shell-risk.js";
import { extractAddedLines, extractFilePathFromPatch, findSecretInCode } from "./rules/no-secrets.js";
import { extractStructuredEditInspection, extractToolAction, KNOWN_SHELL_TOOLS, quoteProcessArgument, splitFilePatches } from "./tool-input.js";
export { extractToolAction } from "./tool-input.js";
import { findTruncationPlaceholder } from "./edit-integrity.js";
/**
 * Shell tools known to execute shell commands (shared canonical set).
 */
const SHELL_TOOLS = KNOWN_SHELL_TOOLS;
/**
 * Tools that write or mutate files on disk.
 */
const FILE_MUTATION_TOOLS = new Set([
    "write", "write_to_file", "write_file", "create_file", "save_file",
    "replace_file_content", "edit_file", "edit", "patch", "apply_patch",
    "str_replace_editor", "multiedit", "file_editor",
    "file_mutate", "file_write", "file_edit",
]);
export function isShellExecutionTool(tool, additionalTools = []) {
    const normalized = tool.toLowerCase().trim();
    // MCP tool IDs use provider-agnostic double-underscore or dotted separators,
    // e.g. mcp__<provider>__shell_exec. Never treat an arbitrary file_* MCP
    // action as a shell, but recognize a known shell action by its suffix.
    const last = extractToolAction(normalized);
    return SHELL_TOOLS.has(last) || additionalTools.some((entry) => {
        const candidate = entry.trim().toLowerCase();
        return candidate === normalized || candidate === last;
    });
}
export function isFileMutationTool(tool) {
    const last = extractToolAction(tool);
    return FILE_MUTATION_TOOLS.has(last);
}
/** A process launcher requires inspection of both the executable and argv. */
export function isProcessStartTool(tool) {
    return extractToolAction(tool) === "process_start";
}
function unwrapProcessStartLauncher(executable, args) {
    let curExec = executable;
    let curArgs = args;
    for (let depth = 0; depth < 6; depth++) {
        let idx = 0;
        if (curExec === "sudo") {
            while (idx < curArgs.length) {
                const a = curArgs[idx];
                if (a === "--") {
                    idx++;
                    break;
                }
                // Only consume next token when a value-taking flag is standalone or ends a pure-boolean cluster
                // (never for attached values like `-uroot` or `-Dtmp`, and never for boolean `-H`/`-P`).
                if (/^(?:-[ABEFGHIJKLMNOPQSTUVWXYZabdefijklmnoqsvwxyz]*[ugCprthDUcRT]|--user|--group|--chdir|--host|--prompt|--role|--type|--other-user|--close-from|--login-class|--selinux-role|--selinux-type)$/.test(a)) {
                    idx += 2;
                    continue;
                }
                if (a.startsWith("-")) {
                    idx++;
                    continue;
                }
                break;
            }
        }
        else if (curExec === "env") {
            const joinEnvSplit = (head, tailStart) => {
                const tail = curArgs.slice(tailStart).map(quoteProcessArgument).join(" ");
                return tail ? `${head} ${tail}`.trim() : head;
            };
            while (idx < curArgs.length) {
                const a = curArgs[idx];
                if (a === "--" || a === "-") {
                    idx++;
                    while (idx < curArgs.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(curArgs[idx]))
                        idx++;
                    break;
                }
                if (a === "-S" || a === "--split-string") {
                    const splitScript = joinEnvSplit(curArgs[idx + 1] ?? "", idx + 2);
                    return { executable: curExec, args: curArgs, envSplitScript: splitScript };
                }
                if (a.startsWith("--split-string=")) {
                    const splitScript = joinEnvSplit(a.slice("--split-string=".length), idx + 1);
                    return { executable: curExec, args: curArgs, envSplitScript: splitScript };
                }
                if (a.startsWith("-S") || /^-[i0v]+S/.test(a)) {
                    const sPos = a.indexOf("S");
                    const attached = a.slice(sPos + 1);
                    const splitScript = attached
                        ? joinEnvSplit(attached, idx + 1)
                        : joinEnvSplit(curArgs[idx + 1] ?? "", idx + 2);
                    return { executable: curExec, args: curArgs, envSplitScript: splitScript };
                }
                if (/^(?:-[uC]|-[i0v]+[uC]|--unset|--chdir)$/.test(a)) {
                    idx += 2;
                    continue;
                }
                if (a.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(a)) {
                    idx++;
                    continue;
                }
                break;
            }
        }
        else if (curExec === "timeout") {
            while (idx < curArgs.length) {
                const a = curArgs[idx];
                if (a === "--") {
                    idx++;
                    break;
                }
                if (/^(?:-[ks]|--kill-after|--signal)$/.test(a)) {
                    idx += 2;
                    continue;
                }
                if (a.startsWith("-")) {
                    idx++;
                    continue;
                }
                break;
            }
            // Consume duration token (even after `--`).
            if (idx < curArgs.length)
                idx++;
        }
        else if (curExec === "flock") {
            while (idx < curArgs.length) {
                const a = curArgs[idx];
                if (a === "--") {
                    idx++;
                    break;
                }
                if (/^(?:-w|--timeout|-E|--conflict-exit-code)$/.test(a)) {
                    idx += 2;
                    continue;
                }
                if (a.startsWith("-")) {
                    idx++;
                    continue;
                }
                break;
            }
            // Consume lockfile token (even after `--`).
            if (idx < curArgs.length)
                idx++;
            if (curArgs[idx] === "--")
                idx++;
            if (curArgs[idx] === "-c" || curArgs[idx] === "--command")
                return { executable: curExec, args: curArgs };
        }
        else if (curExec === "nice") {
            while (idx < curArgs.length) {
                const a = curArgs[idx];
                if (a === "-n" || a === "--adjustment") {
                    idx += 2;
                    continue;
                }
                if (a.startsWith("-")) {
                    idx++;
                    continue;
                }
                break;
            }
        }
        else if (curExec === "stdbuf") {
            while (idx < curArgs.length) {
                const a = curArgs[idx];
                if (a === "--") {
                    idx++;
                    break;
                }
                if (/^(?:-[ioe]|--input|--output|--error)$/.test(a)) {
                    idx += 2;
                    continue;
                }
                if (a.startsWith("-")) {
                    idx++;
                    continue;
                }
                break;
            }
        }
        else if (curExec === "ionice") {
            while (idx < curArgs.length) {
                const a = curArgs[idx];
                if (a === "--") {
                    idx++;
                    break;
                }
                if (/^(?:-[cn]|--class|--classdata)$/.test(a)) {
                    idx += 2;
                    continue;
                }
                if (a.startsWith("-")) {
                    idx++;
                    continue;
                }
                break;
            }
        }
        else if (curExec === "exec") {
            while (idx < curArgs.length) {
                const a = curArgs[idx];
                if (a === "--") {
                    idx++;
                    break;
                }
                if (a === "-a") {
                    idx += 2;
                    continue;
                }
                if (a.startsWith("-")) {
                    idx++;
                    continue;
                }
                break;
            }
        }
        else if (curExec === "nohup" || curExec === "time" || curExec === "setsid" || curExec === "builtin") {
            while (idx < curArgs.length && curArgs[idx].startsWith("-"))
                idx++;
        }
        else if (curExec === "command") {
            if (curArgs.some((a) => /^-[a-z]*[vV]/.test(a)))
                break;
            while (idx < curArgs.length && (curArgs[idx] === "-p" || curArgs[idx] === "--")) {
                const isEnd = curArgs[idx] === "--";
                idx++;
                if (isEnd)
                    break;
            }
        }
        else {
            break;
        }
        const nextExecRaw = curArgs[idx];
        if (!nextExecRaw)
            break;
        const nextExecName = nextExecRaw.trim().split(/[\\/]/).at(-1);
        if (!nextExecName)
            break;
        curExec = nextExecName.toLowerCase().replace(/\.(exe|cmd|bat)$/, "");
        curArgs = curArgs.slice(idx + 1);
    }
    return { executable: curExec, args: curArgs };
}
function splitEnvSplitTokens(script) {
    const tokens = [];
    let cur = "";
    let has = false;
    let q = null;
    for (let i = 0; i < script.length; i++) {
        const ch = script[i];
        if (ch === "\\" && q !== "'") {
            has = true;
            cur += script[++i] ?? "";
            continue;
        }
        if (q) {
            if (ch === q)
                q = null;
            else
                cur += ch;
            continue;
        }
        if (ch === "'" || ch === '"') {
            has = true;
            q = ch;
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
    return tokens;
}
function evaluateProcessStartPreflight(input, mode = "strict", depth = 0) {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
        return "uninspectable-shell-input";
    }
    const value = input;
    if (typeof value.executable !== "string" || !value.executable.trim() ||
        (value.args !== undefined && (!Array.isArray(value.args) ||
            !value.args.every((arg) => typeof arg === "string")))) {
        return "uninspectable-shell-input";
    }
    const executableName = value.executable.trim().split(/[\\/]/).at(-1);
    if (!executableName)
        return "uninspectable-shell-input";
    const rawExecutable = executableName.toLowerCase().replace(/\.(exe|cmd|bat)$/, "");
    const rawArgs = value.args ?? [];
    const unwrapped = unwrapProcessStartLauncher(rawExecutable, rawArgs);
    if (unwrapped.envSplitScript !== undefined) {
        const trimmedSplit = unwrapped.envSplitScript.trim();
        if (!trimmedSplit)
            return "uninspectable-shell-input";
        const bashCmd = /^(?:-(?![i0v]*S\b)(?!--split-string\b)|[A-Za-z_][A-Za-z0-9_]*=)/.test(trimmedSplit)
            ? `env ${trimmedSplit}`
            : trimmedSplit;
        const bashResult = evaluatePreflight("bash", { command: bashCmd }, [], mode);
        if (bashResult)
            return bashResult;
        if (depth < 4) {
            const splitTokens = splitEnvSplitTokens(trimmedSplit);
            const nextUnwrapped = unwrapProcessStartLauncher("env", splitTokens);
            if (nextUnwrapped.envSplitScript !== undefined) {
                return evaluateProcessStartPreflight({ executable: "env", args: splitTokens }, mode, depth + 1);
            }
            if (nextUnwrapped.executable !== "env") {
                return evaluateProcessStartPreflight({ executable: nextUnwrapped.executable, args: nextUnwrapped.args }, mode, depth + 1);
            }
            if (mode === "strict") {
                const envCmd = ["env", ...splitTokens].map(quoteProcessArgument).join(" ");
                if (assessCommandPreflight(envCmd).isHighRiskEnvDump) {
                    return "high-risk-environment-dump";
                }
            }
        }
        return undefined;
    }
    const executable = unwrapped.executable;
    const args = unwrapped.args;
    const posixShells = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish"]);
    const windowsShells = new Set(["powershell", "pwsh", "cmd"]);
    if (posixShells.has(executable) || windowsShells.has(executable)) {
        const isPosix = posixShells.has(executable);
        const isPowerShell = executable === "powershell" || executable === "pwsh";
        let option = -1;
        if (isPosix) {
            for (let i = 0; i < args.length; i++) {
                const a = args[i];
                if (a === "--" || a === "-" || (!a.startsWith("-") && !a.startsWith("+")))
                    break;
                if (a === "--rcfile" || a === "--init-file" || a === "-o" || a === "+o" || a === "-O" || a === "+O") {
                    i++;
                    continue;
                }
                if (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(a)) {
                    option = i;
                    break;
                }
                if (/^[+-][a-zA-Z]*[oO][a-zA-Z]*$/.test(a)) {
                    i++;
                    continue;
                }
            }
        }
        else if (isPowerShell) {
            for (let i = 0; i < args.length; i++) {
                const a = args[i];
                // `-File` / `-f` or a positional script file executes an uninspectable script and consumes all remaining args.
                if (/^(?:-file|-f)$/i.test(a) || !a.startsWith("-"))
                    break;
                if (/^(?:-executionpolicy|-ep|-workingdirectory|-wd|-configurationname|-settingsfile|-outputformat|-inputformat)$/i.test(a)) {
                    i++;
                    continue;
                }
                if (/^(?:-command|-c|-encodedcommand|-enc|-ec|-e)$/i.test(a)) {
                    option = i;
                    break;
                }
            }
        }
        else {
            option = args.findIndex((a) => /^\/[ck]$/i.test(a));
        }
        const shellOption = option >= 0 ? args[option] : undefined;
        if (option < 0 ||
            shellOption === undefined ||
            /^(?:-encodedcommand|-enc)$/i.test(shellOption) ||
            (isPowerShell && /^(?:-ec|-e)$/i.test(shellOption))) {
            return "uninspectable-shell-input";
        }
        let scriptIndex = option + 1;
        if (isPosix) {
            if (/[oO]/.test(shellOption)) {
                // Combined option like `-co errexit <script>` or `-cO extglob <script>` consumes `<opt>` before `<script>`.
                scriptIndex++;
            }
            // POSIX shells continue parsing options placed after `-c` (e.g. `bash -c -e <script>`, `bash -c -o errexit <script>`, `bash -c - <script>`).
            while (scriptIndex < args.length) {
                const nextArg = args[scriptIndex];
                if (nextArg === "--" || nextArg === "-") {
                    scriptIndex++;
                    break;
                }
                if (nextArg === "-o" ||
                    nextArg === "+o" ||
                    nextArg === "-O" ||
                    nextArg === "+O" ||
                    nextArg === "--rcfile" ||
                    nextArg === "--init-file" ||
                    /^[+-][a-zA-Z]*[oO][a-zA-Z]*$/.test(nextArg)) {
                    scriptIndex += 2;
                    continue;
                }
                if (/^[+-][a-zA-Z0-9-]+(?:=\S+)?$/.test(nextArg)) {
                    scriptIndex++;
                    continue;
                }
                break;
            }
        }
        if (scriptIndex >= args.length) {
            return "uninspectable-shell-input";
        }
        const script = isPosix
            ? args[scriptIndex]
            : args.slice(scriptIndex).join(" ");
        return evaluatePreflight("bash", { command: script }, [], mode);
    }
    if (["node", "bun", "deno", "ruby", "perl"].includes(executable)) {
        const valueFlags = new Set([
            "-r", "--require", "--import", "--loader", "--experimental-loader",
            "--env-file", "--env-file-if-exists", "--conditions", "--input-type",
            "-C", "--eval-file", "-I",
        ]);
        const isPerlOrRuby = executable === "perl" || executable === "ruby";
        for (let i = 0; i < args.length; i++) {
            const arg = args[i];
            if (arg === "--")
                break;
            if (valueFlags.has(arg)) {
                i++;
                continue;
            }
            if (!arg.startsWith("-"))
                break;
            if (arg === "-e" ||
                arg === "--eval" ||
                arg.startsWith("--eval=") ||
                arg === "-p" ||
                arg === "--print" ||
                arg.startsWith("--print=") ||
                arg === "-E" ||
                /^-(?![ICrMm])[a-z]*[ep][a-z]*$/.test(arg) ||
                (isPerlOrRuby && /^-(?![ICrMm])[a-zA-Z]*[eE]/.test(arg))) {
                return "uninspectable-shell-input";
            }
        }
    }
    if (["python", "python3"].includes(executable)) {
        const valueFlags = new Set(["-W", "-X", "-Q", "--check-hash-based-pycs"]);
        for (let i = 0; i < args.length; i++) {
            const arg = args[i];
            if (arg === "--" || arg === "-m" || arg.startsWith("-m") || !arg.startsWith("-"))
                break;
            if (valueFlags.has(arg)) {
                i++;
                continue;
            }
            if (arg === "-c" || /^-(?![WXQ])[a-zA-Z]*c/.test(arg)) {
                return "uninspectable-shell-input";
            }
        }
    }
    const command = [rawExecutable, ...rawArgs].map(quoteProcessArgument).join(" ");
    if (mode === "strict" && assessCommandPreflight(command).isHighRiskEnvDump) {
        return "high-risk-environment-dump";
    }
    if (isDestructiveCommand(command) ||
        (mode === "strict" && isSimpleFileRemoval(command)) ||
        isWindowsDestructiveCommand(command)) {
        return "destructive-command";
    }
    if (isOpaqueShellExecution(command))
        return "opaque-shell-execution";
    if (hasDynamicCommandName(command))
        return "uninspectable-shell-input";
    return undefined;
}
/** Bounded recognition of literal Windows shell removal commands. */
function isWindowsDestructiveCommand(command, depth = 0) {
    // Inspect executable stages, not quoted arguments containing examples.
    if (splitShellStages(command).flat().some((stage) => /^(?:del|erase|rd|rmdir|remove-item|format)\b/i.test(stage.trim())))
        return true;
    // cmd /c and PowerShell -Command execute literal quoted scripts.
    return depth < 4 && literalWindowsShellScripts(command).some((script) => isWindowsDestructiveCommand(script, depth + 1));
}
export function evaluateFileMutationPreflight(tool, input, mode = "strict", secretOptions) {
    if (!isFileMutationTool(tool))
        return undefined;
    if (!input || typeof input !== "object" || Array.isArray(input))
        return "uninspectable-file-input";
    const args = input;
    const patchRaw = args.patchText ?? args.patch;
    const targetFile = args.path ??
        args.targetFile ??
        args.TargetFile ??
        args.filePath ??
        args.file ??
        (typeof patchRaw === "string" ? extractFilePathFromPatch(patchRaw) : undefined);
    const textsToCheck = [];
    for (const key of ["content", "new_string", "newString", "new_str", "appendContent", "prependContent", "CodeContent", "ReplacementContent", "text", "file_text"]) {
        if (typeof args[key] === "string") {
            textsToCheck.push({
                text: args[key],
                ...(typeof targetFile === "string" ? { filePath: targetFile } : {}),
            });
        }
    }
    let hasValidPatchStructure = false;
    const deletedPatchTargets = [];
    if (typeof patchRaw === "string") {
        const sections = splitFilePatches(patchRaw);
        if (sections.length > 0 &&
            /(?:^|\n)(?:@@|\+\+\+|---|\*\*\*\s+(?:Begin|Update|Add|Delete|Move)\s+(?:Patch|File))/m.test(patchRaw)) {
            hasValidPatchStructure = true;
        }
        if (sections.length > 0) {
            for (const section of sections) {
                if (section.deleted) {
                    deletedPatchTargets.push(section.filePath ?? section.previousPath ?? "");
                }
                const sectionAdded = extractAddedLines(section.patch);
                if (sectionAdded) {
                    const sectionPath = section.filePath ?? (typeof targetFile === "string" ? targetFile : undefined);
                    textsToCheck.push({
                        text: sectionAdded,
                        ...(sectionPath ? { filePath: sectionPath } : {}),
                    });
                }
            }
        }
        else {
            const addedLines = extractAddedLines(patchRaw);
            if (addedLines) {
                textsToCheck.push({
                    text: addedLines,
                    ...(typeof targetFile === "string" ? { filePath: targetFile } : {}),
                });
            }
        }
    }
    // File mutation providers also accept structured edit arrays. Preserve each
    // edit's own target path and reject any array containing an uninspectable edit.
    if (Array.isArray(args.edits)) {
        const editInspection = extractStructuredEditInspection(args, typeof targetFile === "string" ? targetFile : undefined);
        if (editInspection.hasUninspectableEdit) {
            return "uninspectable-file-input";
        }
        textsToCheck.push(...editInspection.texts);
    }
    const isCatastrophicPath = (raw) => {
        const trimmed = raw.trim().replace(/[\\/]+$/, (m, offset) => (offset === 0 ? m : ""));
        return !trimmed || /^(?:[\\/]+\*+|[\\/]+|~(?:[\\/]+\*+)?|\.\.?(?:[\\/]+\*+)?|\*+|[a-z]:(?:[\\/]+\*+)?|[a-z]:[\\/]?)$/i.test(trimmed);
    };
    if (deletedPatchTargets.length > 0) {
        if (mode === "strict") {
            return "destructive-command";
        }
        if (deletedPatchTargets.some((p) => isCatastrophicPath(p))) {
            return "destructive-command";
        }
    }
    const action = typeof args.action === "string" ? args.action.toLowerCase() : "";
    if (action === "delete" || action === "remove") {
        if (mode === "strict") {
            return "destructive-command";
        }
        const delTarget = typeof targetFile === "string" ? targetFile.trim() : "";
        const isCatastrophicDelete = args.recursive === true ||
            args.force === true ||
            isCatastrophicPath(delTarget);
        if (isCatastrophicDelete) {
            return "destructive-command";
        }
        // Fall through to scan any attached textsToCheck instead of returning early.
    }
    else if (action === "move" || action === "copy") {
        const src = (typeof args.source === "string" && args.source.trim()) ||
            (typeof args.from === "string" && args.from.trim()) ||
            (typeof targetFile === "string" && targetFile.trim());
        const dst = (typeof args.destination === "string" && args.destination.trim()) ||
            (typeof args.to === "string" && args.to.trim()) ||
            (typeof args.dest === "string" && args.dest.trim()) ||
            (typeof args.target === "string" && args.target.trim());
        if (!src || !dst) {
            return "uninspectable-file-input";
        }
        const isNullDevice = (raw) => {
            const slashNorm = raw.trim().replace(/\\/g, "/");
            const segments = slashNorm.split("/");
            const collapsed = [];
            for (const seg of segments) {
                if (!seg || seg === ".")
                    continue;
                if (seg === "..") {
                    collapsed.pop();
                    continue;
                }
                collapsed.push(seg);
            }
            const joined = (slashNorm.startsWith("/") ? "/" : "") + collapsed.join("/");
            return /^(?:\/dev\/null|nul)$/i.test(joined);
        };
        if (isCatastrophicPath(src) ||
            isCatastrophicPath(dst) ||
            (action === "move" && isNullDevice(dst))) {
            return "destructive-command";
        }
    }
    else if (!hasValidPatchStructure && textsToCheck.length === 0) {
        return "uninspectable-file-input";
    }
    for (const item of textsToCheck) {
        const found = findSecretInCode(item.text, item.filePath, secretOptions);
        if (found) {
            return "hardcoded-secret-in-file-write";
        }
        if (findTruncationPlaceholder(item.text, item.filePath))
            return "truncation-placeholder-in-file-write";
    }
    return undefined;
}
function shellWords(text) {
    const words = [];
    let current = "";
    let hasToken = false;
    let quote = null;
    for (let i = 0; i < text.length; i++) {
        const ch = text[i];
        if (ch === "\\" && quote !== "'") {
            hasToken = true;
            current += text[++i] ?? "";
            continue;
        }
        if (quote) {
            if (ch === quote) {
                quote = null;
            }
            else {
                current += ch;
            }
            continue;
        }
        if (ch === "'" || ch === '"') {
            hasToken = true;
            quote = ch;
            continue;
        }
        if (/\s/.test(ch)) {
            if (hasToken) {
                words.push(current);
                current = "";
                hasToken = false;
            }
            continue;
        }
        hasToken = true;
        current += ch;
    }
    if (hasToken)
        words.push(current);
    return words;
}
function normalizeCommitMessage(value) {
    let message = value.trim().replace(/^=/, "");
    if (message.length >= 2 &&
        ((message.startsWith('"') && message.endsWith('"')) ||
            (message.startsWith("'") && message.endsWith("'")))) {
        message = message.slice(1, -1);
    }
    return message.trim();
}
function extractGitCommitMessageFromStage(stage) {
    const stripped = stripShellWrappersAndPath(stage);
    const match = /^git(?:\s+(?:-C|-c)\s+(?:"[^"]*"|'[^']*'|[^\s;&|\n]+))*\s+commit\b([^\n]*)/i.exec(stripped);
    if (!match)
        return undefined;
    const words = shellWords(match[1] ?? "");
    for (let index = 0; index < words.length; index++) {
        const word = words[index] ?? "";
        if (word === "--")
            break;
        if (word === "-m" || word === "--message") {
            const next = words[index + 1];
            return next === undefined ? undefined : normalizeCommitMessage(next);
        }
        if (word.startsWith("--message=")) {
            return normalizeCommitMessage(word.slice("--message=".length));
        }
        if (/^-[^-]/.test(word) && !/^-[ucCFtS]/.test(word)) {
            const messageOption = word.indexOf("m", 1);
            if (messageOption >= 0) {
                const attached = word.slice(messageOption + 1);
                if (attached)
                    return normalizeCommitMessage(attached);
                const next = words[index + 1];
                return next === undefined ? undefined : normalizeCommitMessage(next);
            }
        }
    }
    return undefined;
}
export function extractGitCommitMessage(command) {
    for (const stage of splitShellStages(command).flat()) {
        const msg = extractGitCommitMessageFromStage(stage);
        if (msg !== undefined)
            return msg;
    }
    return undefined;
}
function isCommitMessageLazy(msg) {
    if (msg.length < 4)
        return true;
    return /^(?:fix|update|wip|done|test|temp|changes|commit|asdf|minor|stuff|work|misc|foo|bar|checkpoint|save|tmp|quick\s*fix|bug\s*fix|hotfix)$/i.test(msg);
}
export function isLazyCommitMessage(command) {
    for (const stage of splitShellStages(command).flat()) {
        const msg = extractGitCommitMessageFromStage(stage);
        if (msg !== undefined && isCommitMessageLazy(msg))
            return true;
    }
    return false;
}
function npmPackageNameFromSpec(spec) {
    const value = spec.trim();
    if (!value)
        return undefined;
    if (/^(?:\.{1,2}(?:\/|$)|\/|~\/|file:|link:|workspace:|https?:|git(?:\+|:)|github:|gitlab:|bitbucket:|gist:|ssh:)/i.test(value) ||
        (!value.startsWith("@") && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:#[^\s]+)?$/.test(value))) {
        return undefined;
    }
    if (value.startsWith("@")) {
        const slash = value.indexOf("/");
        if (slash < 2)
            return value;
        const versionAt = value.indexOf("@", slash + 1);
        return versionAt > slash ? value.slice(0, versionAt) : value;
    }
    const versionAt = value.indexOf("@", 1);
    return versionAt > 0 ? value.slice(0, versionAt) : value;
}
function suspiciousNpmPackageName(name) {
    return (/[A-Z]/.test(name) ||
        /(?:-official|-security-patch|-security-update|-fixed-version|-patched-release)$/i.test(name));
}
const PM_OPTIONS_WITH_VALUE = new Set([
    "--filter", "-F", "--workspace", "-w", "--cwd", "--dir", "-C", "--prefix",
    "--registry", "--tag", "--config", "--cache", "--loglevel", "--reporter",
    "--store-dir", "--lockfile-dir", "--virtual-store-dir", "--modules-dir",
    "--config-file", "--userconfig", "--cafile",
]);
export function isHallucinatedOrMalformedPackageInstall(command) {
    for (const stage of splitShellStages(command).flat()) {
        const trimmed = stripShellWrappersAndPath(stage);
        const npmMatch = /^(?:npm\s+(?:i|install|add)|pnpm\s+(?:i|install|add)|yarn\s+add|bun\s+(?:i|install|add))\s+([^\n]+)/i.exec(trimmed);
        if (!npmMatch?.[1])
            continue;
        const words = shellWords(npmMatch[1]);
        let skipNext = false;
        for (const arg of words) {
            if (skipNext) {
                skipNext = false;
                continue;
            }
            if (!arg)
                continue;
            if (arg === "--")
                break;
            if (/^(?:\d*>>?|\d*<&|\d*>&|&>>?|<)$/.test(arg)) {
                skipNext = true;
                continue;
            }
            if (/^(?:\d*>>?|\d*<|&>>?)\S/.test(arg)) {
                continue;
            }
            if (PM_OPTIONS_WITH_VALUE.has(arg)) {
                skipNext = true;
                continue;
            }
            if (arg.startsWith("-"))
                continue;
            const packageName = npmPackageNameFromSpec(arg);
            if (packageName && suspiciousNpmPackageName(packageName))
                return true;
        }
    }
    return false;
}
export function evaluatePreflight(tool, input, additionalTools = [], mode = "strict", secretOptions) {
    if (isProcessStartTool(tool)) {
        return evaluateProcessStartPreflight(input, mode);
    }
    if (isShellExecutionTool(tool, additionalTools)) {
        if (!input || typeof input !== "object" || Array.isArray(input)) {
            return "uninspectable-shell-input";
        }
        const args = input;
        const fields = ["command", "cmd", "script"].filter((key) => Object.hasOwn(args, key));
        if (fields.length === 0)
            return "uninspectable-shell-input";
        const values = fields.map((key) => args[key]);
        if (values.some((value) => typeof value !== "string" || !value.trim())) {
            return "uninspectable-shell-input";
        }
        const commands = values;
        if (mode === "strict" &&
            commands.some((command) => assessCommandPreflight(command).isHighRiskEnvDump)) {
            return "high-risk-environment-dump";
        }
        if (commands.some((command) => isDestructiveCommand(command) ||
            (mode === "strict" && isSimpleFileRemoval(command)) ||
            isWindowsDestructiveCommand(command))) {
            return "destructive-command";
        }
        if (commands.some(isOpaqueShellExecution))
            return "opaque-shell-execution";
        if (commands.some(hasDynamicCommandName))
            return "uninspectable-shell-input";
        if (mode === "strict" && commands.some(isLazyCommitMessage))
            return "lazy-commit-message";
        if (commands.some(isHallucinatedOrMalformedPackageInstall))
            return "hallucinated-or-malformed-package";
        // Different shell command aliases give no reliable way to know which the
        // host will execute. Do not pick only the first, apparently safe value.
        if (new Set(commands).size > 1)
            return "uninspectable-shell-input";
        return undefined;
    }
    if (isFileMutationTool(tool)) {
        return evaluateFileMutationPreflight(tool, input, mode, secretOptions);
    }
    return undefined;
}
export class GuardianPreflightError extends Error {
    reason;
    constructor(reason) {
        const descriptions = {
            "destructive-command": "recognized destructive shell operation",
            "opaque-shell-execution": "decoded content piped into a shell",
            "uninspectable-shell-input": "missing or uninspectable shell command",
            "hardcoded-secret-in-file-write": "potential hardcoded secret in file write",
            "truncation-placeholder-in-file-write": "code placeholder would replace real source content",
            "uninspectable-file-input": "missing or uninspectable file mutation payload",
            "high-risk-environment-dump": "broad environment or container metadata dump that may expose credentials",
            "lazy-commit-message": "lazy or uninformative git commit message; write a descriptive conventional commit (feat:, fix:, etc.)",
            "hallucinated-or-malformed-package": "malformed or suspicious package installation command",
        };
        super(`[opencode-guardian preflight] Tool execution rejected: ${descriptions[reason]}. Disable the optional preflight feature only if you understand and accept the risk.`);
        this.name = "GuardianPreflightError";
        this.reason = reason;
    }
}
/**
 * Opt-in strict guard: reject recognized risks before a host executes a tool.
 * This does not parse arbitrary shell syntax or replace OS/host permissions.
 */
export function enforcePreflight(tool, input, additionalTools = [], mode = "strict", secretOptions) {
    const finding = evaluatePreflight(tool, input, additionalTools, mode, secretOptions);
    if (finding)
        throw new GuardianPreflightError(finding);
}
