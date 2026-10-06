import { isDestructiveCommand, isOpaqueShellExecution, isSimpleFileRemoval } from "./evidence.js";
import { hasDynamicCommandName } from "./shell-risk.js";
import { extractAddedLines, extractFilePathFromPatch, findSecretInCode } from "./rules/no-secrets.js";
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
    "write_to_file", "write_file", "create_file", "save_file",
    "replace_file_content", "edit_file", "edit", "patch", "apply_patch",
    "str_replace_editor", "multiedit", "file_editor",
    "file_mutate", "file_write", "file_edit",
]);
export function isShellExecutionTool(tool, additionalTools = []) {
    const normalized = tool.toLowerCase();
    // MCP tool IDs use double-underscore separators, e.g.
    // mcp__Node_Command__shell_exec. Never treat an arbitrary file_* MCP
    // action as a shell, but recognize a known shell action by its full suffix.
    const mcpAction = /^mcp__[a-z0-9_]+__(.+)$/.exec(normalized)?.[1];
    const last = mcpAction ?? normalized.split(/[.:/]/).at(-1) ?? "";
    return SHELL_TOOLS.has(last) || additionalTools.some((entry) => {
        const candidate = entry.trim().toLowerCase();
        return candidate === normalized || candidate === last;
    });
}
export function isFileMutationTool(tool) {
    const normalized = tool.toLowerCase();
    const mcpAction = /^mcp__[a-z0-9_]+__(.+)$/.exec(normalized)?.[1];
    const last = mcpAction ?? normalized.split(/[.:/]/).at(-1) ?? "";
    return FILE_MUTATION_TOOLS.has(last);
}
/** A process launcher requires inspection of both the executable and argv. */
export function isProcessStartTool(tool) {
    const normalized = tool.toLowerCase();
    const action = /^mcp__[a-z0-9_]+__(.+)$/.exec(normalized)?.[1]
        ?? normalized.split(/[.:/]/).at(-1);
    return action === "process_start";
}
function evaluateProcessStartPreflight(input) {
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
        const option = args.findIndex((arg) => /^-[a-z]*c[a-z]*$/i.test(arg) || /^(?:\/c|-command|-encodedcommand|-enc)$/i.test(arg));
        const shellOption = args[option];
        if (option < 0 || shellOption === undefined || args.length <= option + 1 ||
            /^(?:-encodedcommand|-enc)$/i.test(shellOption)) {
            return "uninspectable-shell-input";
        }
        return evaluatePreflight("bash", { command: args.slice(option + 1).join(" ") });
    }
    if (["node", "python", "python3", "ruby", "perl"].includes(executable) &&
        args.some((arg) => ["-e", "--eval", "-c", "-E"].includes(arg))) {
        return "uninspectable-shell-input";
    }
    const command = [executable, ...args].join(" ");
    if (isDestructiveCommand(command) || isSimpleFileRemoval(command) ||
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
function isWindowsDestructiveCommand(command) {
    return /(?:^|[;&|]\s*)(?:del|erase|rd|rmdir|remove-item|format)\b/i.test(command.trim());
}
export function evaluateFileMutationPreflight(tool, input) {
    if (!isFileMutationTool(tool))
        return undefined;
    if (!input || typeof input !== "object" || Array.isArray(input))
        return "uninspectable-file-input";
    const args = input;
    const patchRaw = args.patchText ?? args.patch;
    const targetFile = args.path ??
        args.targetFile ??
        args.filePath ??
        args.file ??
        (typeof patchRaw === "string" ? extractFilePathFromPatch(patchRaw) : undefined);
    const textsToCheck = [];
    for (const key of ["content", "new_string", "newString", "CodeContent", "ReplacementContent", "text"]) {
        if (typeof args[key] === "string" && args[key].length > 0) {
            textsToCheck.push(args[key]);
        }
    }
    if (typeof patchRaw === "string") {
        const addedLines = extractAddedLines(patchRaw);
        if (addedLines)
            textsToCheck.push(addedLines);
    }
    // File mutation providers also accept structured edit arrays. Inspect the
    // replacement data, not only the outer tool argument object.
    if (Array.isArray(args.edits)) {
        for (const edit of args.edits) {
            if (!edit || typeof edit !== "object" || Array.isArray(edit))
                return "uninspectable-file-input";
            for (const key of ["content", "text", "new_text", "newText", "replacement", "new_string", "newString"]) {
                const value = edit[key];
                if (typeof value === "string")
                    textsToCheck.push(value);
            }
        }
    }
    const action = typeof args.action === "string" ? args.action.toLowerCase() : "";
    if (isFileMutationTool(tool) && ["file_mutate", "file_write", "file_edit"].some((name) => tool.toLowerCase().endsWith(name)) &&
        !["move", "copy"].includes(action) && textsToCheck.length === 0) {
        return "uninspectable-file-input";
    }
    for (const text of textsToCheck) {
        const found = findSecretInCode(text, targetFile);
        if (found) {
            return "hardcoded-secret-in-file-write";
        }
    }
    return undefined;
}
export function evaluatePreflight(tool, input, additionalTools = []) {
    if (isProcessStartTool(tool)) {
        return evaluateProcessStartPreflight(input);
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
        if (commands.some((command) => isDestructiveCommand(command) || isSimpleFileRemoval(command) ||
            isWindowsDestructiveCommand(command)))
            return "destructive-command";
        if (commands.some(isOpaqueShellExecution))
            return "opaque-shell-execution";
        if (commands.some(hasDynamicCommandName))
            return "uninspectable-shell-input";
        // Different shell command aliases give no reliable way to know which the
        // host will execute. Do not pick only the first, apparently safe value.
        if (new Set(commands).size > 1)
            return "uninspectable-shell-input";
        return undefined;
    }
    if (isFileMutationTool(tool)) {
        return evaluateFileMutationPreflight(tool, input);
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
            "uninspectable-file-input": "missing or uninspectable file mutation payload",
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
export function enforcePreflight(tool, input, additionalTools = []) {
    const finding = evaluatePreflight(tool, input, additionalTools);
    if (finding)
        throw new GuardianPreflightError(finding);
}
