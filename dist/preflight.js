import { isDestructiveCommand, isOpaqueShellExecution, isSimpleFileRemoval } from "./evidence.js";
import { assessCommandPreflight } from "./secrets/preflight.js";
import { hasDynamicCommandName, literalWindowsShellScripts, splitShellStages } from "./shell-risk.js";
import { extractAddedLines, extractFilePathFromPatch, findSecretInCode } from "./rules/no-secrets.js";
import { extractStructuredEditTexts, extractToolAction, quoteProcessArgument, splitFilePatches } from "./tool-input.js";
export { extractToolAction } from "./tool-input.js";
import { findTruncationPlaceholder } from "./edit-integrity.js";
/**
 * Shell tools known to execute shell commands.
 */
const SHELL_TOOLS = new Set([
    "bash", "sh", "zsh", "shell", "terminal", "exec", "shell_exec",
    "execute_command", "command", "run_command", "run_shell_command",
    "powershell", "pwsh", "cmd", "privileged_shell_exec",
]);
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
function evaluateProcessStartPreflight(input, mode = "strict") {
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
    const executable = executableName.toLowerCase().replace(/\.(exe|cmd|bat)$/, "");
    const args = value.args ?? [];
    const shells = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish",
        "powershell", "pwsh", "cmd"]);
    if (shells.has(executable)) {
        const isPowerShell = executable === "powershell" || executable === "pwsh";
        const option = args.findIndex((arg) => /^-[a-z]*c[a-z]*$/i.test(arg) ||
            /^(?:\/c|-command|-encodedcommand|-enc)$/i.test(arg) ||
            (isPowerShell && /^(?:-ec|-e)$/i.test(arg)));
        const shellOption = args[option];
        if (option < 0 ||
            shellOption === undefined ||
            args.length <= option + 1 ||
            /^(?:-encodedcommand|-enc)$/i.test(shellOption) ||
            (isPowerShell && /^(?:-ec|-e)$/i.test(shellOption))) {
            return "uninspectable-shell-input";
        }
        const script = ["sh", "bash", "zsh", "dash", "ksh", "fish"].includes(executable)
            ? args[option + 1]
            : args.slice(option + 1).join(" ");
        return evaluatePreflight("bash", { command: script }, [], mode);
    }
    if (["node", "python", "python3", "ruby", "perl"].includes(executable) &&
        args.some((arg) => ["-e", "--eval", "-c", "-E"].includes(arg))) {
        return "uninspectable-shell-input";
    }
    const command = [executable, ...args].map(quoteProcessArgument).join(" ");
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
export function evaluateFileMutationPreflight(tool, input, mode = "strict") {
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
    for (const key of ["content", "new_string", "newString", "new_str", "CodeContent", "ReplacementContent", "text", "file_text"]) {
        if (typeof args[key] === "string") {
            textsToCheck.push({
                text: args[key],
                ...(typeof targetFile === "string" ? { filePath: targetFile } : {}),
            });
        }
    }
    let hasValidPatchStructure = false;
    if (typeof patchRaw === "string") {
        const sections = splitFilePatches(patchRaw);
        if (sections.length > 0 &&
            /(?:^|\n)(?:@@|\+\+\+|---|\*\*\*\s+(?:Begin|Update|Add|Delete|Move)\s+(?:Patch|File))/m.test(patchRaw)) {
            hasValidPatchStructure = true;
        }
        if (sections.length > 0) {
            for (const section of sections) {
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
    // edit's own target path so path-based sample/template exceptions can never
    // bleed from one file into another.
    if (Array.isArray(args.edits)) {
        for (const edit of args.edits) {
            if (!edit || typeof edit !== "object" || Array.isArray(edit)) {
                return "uninspectable-file-input";
            }
        }
        textsToCheck.push(...extractStructuredEditTexts(args, typeof targetFile === "string" ? targetFile : undefined));
    }
    const action = typeof args.action === "string" ? args.action.toLowerCase() : "";
    if (action === "delete" || action === "remove") {
        if (mode === "strict") {
            return "destructive-command";
        }
        const delTarget = typeof targetFile === "string" ? targetFile.trim() : "";
        const isCatastrophicDelete = args.recursive === true ||
            args.force === true ||
            !delTarget ||
            /^(?:\/+|~|\.\.?|\*|[a-z]:\\?)$/i.test(delTarget);
        if (isCatastrophicDelete) {
            return "destructive-command";
        }
        return undefined;
    }
    if (!["move", "copy"].includes(action) &&
        !hasValidPatchStructure &&
        textsToCheck.length === 0) {
        return "uninspectable-file-input";
    }
    for (const item of textsToCheck) {
        const found = findSecretInCode(item.text, item.filePath);
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
    const pattern = /"([^"]*)"|'([^']*)'|([^\s]+)/g;
    let match = pattern.exec(text);
    while (match) {
        words.push(match[1] ?? match[2] ?? match[3] ?? "");
        match = pattern.exec(text);
    }
    return words.filter(Boolean);
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
    const match = /\bgit(?:\s+(?:-C|-c)\s+(?:"[^"]*"|'[^']*'|[^\s;&|\n]+))*\s+commit\b([^\n]*)/i.exec(stage);
    if (!match)
        return undefined;
    const words = shellWords(match[1] ?? "");
    for (let index = 0; index < words.length; index++) {
        const word = words[index] ?? "";
        if (word === "-m" || word === "--message") {
            const next = words[index + 1];
            return next === undefined ? undefined : normalizeCommitMessage(next);
        }
        if (word.startsWith("--message=")) {
            return normalizeCommitMessage(word.slice("--message=".length));
        }
        if (/^-[^-]/.test(word)) {
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
    if (/^(?:\.{1,2}(?:\/|$)|\/|~\/|file:|link:|workspace:|https?:|git(?:\+|:)|github:|ssh:)/i.test(value)) {
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
export function isHallucinatedOrMalformedPackageInstall(command) {
    for (const stage of splitShellStages(command).flat()) {
        const trimmed = stage.trim();
        const npmMatch = /^(?:sudo\s+)?(?:npm\s+(?:i|install|add)|pnpm\s+(?:i|install|add)|yarn\s+add|bun\s+(?:i|install|add))\s+([^\n]+)/i.exec(trimmed);
        if (!npmMatch?.[1])
            continue;
        for (const arg of shellWords(npmMatch[1])) {
            if (!arg || arg.startsWith("-"))
                continue;
            const packageName = npmPackageNameFromSpec(arg);
            if (packageName && suspiciousNpmPackageName(packageName))
                return true;
        }
    }
    return false;
}
export function evaluatePreflight(tool, input, additionalTools = [], mode = "strict") {
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
        return evaluateFileMutationPreflight(tool, input, mode);
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
export function enforcePreflight(tool, input, additionalTools = [], mode = "strict") {
    const finding = evaluatePreflight(tool, input, additionalTools, mode);
    if (finding)
        throw new GuardianPreflightError(finding);
}
