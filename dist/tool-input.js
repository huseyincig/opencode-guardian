/**
 * Canonical provider-agnostic shell tool action names shared across
 * preflight enforcement and turn evidence collection.
 */
export const KNOWN_SHELL_TOOLS = new Set([
    "bash", "sh", "zsh", "shell", "terminal", "exec", "shell_exec",
    "execute_command", "command", "run_command", "run_shell_command",
    "run_terminal_cmd", "powershell", "pwsh", "cmd", "privileged_shell_exec",
]);
/**
 * Canonical provider-agnostic read-only tool action names shared across
 * agent capability classification and turn evidence collection.
 */
export const KNOWN_READ_ONLY_TOOLS = new Set([
    "read_file", "view_file", "cat", "read", "file_read", "read_text_file",
    "glob", "list", "file_list", "dir", "ls", "directory_list", "list_files", "file_search",
    "grep", "search", "code_search", "find",
    "webfetch", "web_fetch", "websearch", "web_search", "read_url_content", "fetch",
    "ask_question", "question", "form", "form_create", "form_get", "form_reply", "form_list",
    "subagent", "task",
    "lsp", "definition", "hover", "references", "document_symbols",
    "status", "git_status", "vcs", "diff", "git_diff", "log", "git_log", "show", "git_show",
]);
export function isKnownReadOnlyTool(toolName) {
    const normalized = toolName.toLowerCase().trim();
    const last = extractToolAction(normalized);
    return KNOWN_READ_ONLY_TOOLS.has(normalized) || KNOWN_READ_ONLY_TOOLS.has(last);
}
/**
 * Extracts the provider-agnostic action name from built-in, dotted/colon/slash-namespaced,
 * or MCP-prefixed tool identifiers (e.g. `mcp__<provider>__<action>`, `mcp.<provider>.<action>`).
 * Never hardcodes or depends on any third-party MCP provider name.
 */
export function extractToolAction(tool) {
    const normalized = tool.toLowerCase().trim();
    if (!normalized)
        return "";
    if (normalized.startsWith("mcp__")) {
        const rest = normalized.slice(5);
        const sep = rest.indexOf("__");
        if (sep > 0 && sep + 2 < rest.length) {
            const action = rest.slice(sep + 2);
            return action.split(/[.:/]/).at(-1) ?? action;
        }
    }
    return normalized.split(/[.:/]/).at(-1) ?? "";
}
/** Render process argv as literal words, never as additional shell source. */
export function quoteProcessArgument(value) {
    return /^[a-zA-Z0-9_./:@%+=,-]+$/.test(value)
        ? value
        : "'" + value.replace(/'/g, "'\\''") + "'";
}
export const FILE_WRITE_WHOLE_KEYS = [
    "content",
    "file_text",
    "CodeContent",
    "text",
];
export const FILE_WRITE_EDIT_KEYS = [
    "new_string",
    "newString",
    "new_str",
    "ReplacementContent",
];
export const FILE_WRITE_ALL_KEYS = [
    ...FILE_WRITE_WHOLE_KEYS,
    ...FILE_WRITE_EDIT_KEYS,
];
export function extractToolTargetFile(input) {
    for (const key of ["path", "targetFile", "TargetFile", "filePath", "file"]) {
        const val = input[key];
        if (typeof val === "string" && val.length > 0)
            return val;
    }
    return undefined;
}
/** Preserve per-file boundaries in unified and native apply_patch input. */
export function splitFilePatches(value) {
    if (typeof value !== "string" || !value)
        return [];
    const normalized = value.replace(/\r\n?/g, "\n");
    const lines = normalized.split("\n");
    const sections = [];
    let current;
    let nativeSection = false;
    let oldRemaining = 0;
    let newRemaining = 0;
    const headerPath = (line) => {
        let name = line.replace(/^(?:---|\+\+\+)\s+/, "").split("\t")[0]?.trim() ?? "";
        if (name.startsWith('"')) {
            try {
                name = JSON.parse(name);
            }
            catch {
                return "";
            }
        }
        return name.replace(/^[ab]\//, "");
    };
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        const next = lines[i + 1] ?? "";
        // Hunk contents are data, even when removed/added source resembles a pair
        // of file headers. Only exhausted hunk counts permit a new file section.
        if (current && (oldRemaining > 0 || newRemaining > 0)) {
            current.patch += line + "\n";
            if (line.startsWith(" ") || line === "") {
                oldRemaining--;
                newRemaining--;
            }
            else if (line.startsWith("-"))
                oldRemaining--;
            else if (line.startsWith("+"))
                newRemaining--;
            continue;
        }
        const hunk = /^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@/.exec(line);
        if (current && !nativeSection && hunk) {
            oldRemaining = Number(hunk[1] ?? 1);
            newRemaining = Number(hunk[2] ?? 1);
            current.patch += line + "\n";
            continue;
        }
        const move = /^\*\*\* Move to: (.+)$/.exec(line);
        if (current && nativeSection && move?.[1]) {
            if (current.filePath)
                current.previousPath = current.filePath;
            current.filePath = move[1].trim();
            current.patch += line + "\n";
            continue;
        }
        const native = /^\*\*\* (Update|Add|Delete) File: (.+)$/.exec(line);
        const unified = !nativeSection && /^---\s+/.test(line) && /^\+\+\+\s+/.test(next);
        if (native || unified) {
            if (current)
                sections.push(current);
            const deleted = native ? native[1] === "Delete" : headerPath(next) === "/dev/null";
            const filePath = native ? native[2]?.trim() : headerPath(deleted ? line : next);
            current = { ...(filePath && filePath !== "/dev/null" ? { filePath } : {}), patch: line + "\n", deleted };
            nativeSection = Boolean(native);
            if (unified && !deleted) {
                const previous = headerPath(line);
                if (previous && previous !== "/dev/null" && previous !== filePath)
                    current.previousPath = previous;
            }
            if (unified) {
                current.patch += next + "\n";
                i++;
            }
        }
        else if (current) {
            current.patch += line + "\n";
        }
    }
    if (current)
        sections.push(current);
    return sections.length ? sections : [{ patch: normalized, deleted: false }];
}
export function extractToolCommand(input) {
    return typeof input.command === "string"
        ? input.command
        : typeof input.cmd === "string"
            ? input.cmd
            : typeof input.script === "string"
                ? input.script
                : typeof input.executable === "string" &&
                    input.executable.trim() &&
                    (input.args === undefined ||
                        (Array.isArray(input.args) &&
                            input.args.every((arg) => typeof arg === "string")))
                    ? [
                        quoteProcessArgument(input.executable.trim()),
                        ...(input.args ?? []).map(quoteProcessArgument),
                    ].join(" ")
                    : "";
}
/**
 * Returns shell source only when the command appears to mutate file contents.
 * This covers common heredoc/redirection and in-place scripting paths without
 * treating ordinary read-only shell commands as file writes.
 */
export function extractLikelyShellMutation(input) {
    const command = extractToolCommand(input);
    if (!command)
        return "";
    const mutatesFile = /(?:^|[;&|]\s*|\n)\s*(?:cat|printf|echo)\b[\s\S]*?(?<!\d)>{1,2}\s*(?!&)(?!\/dev\/null\b)\S+/im.test(command) ||
        /\btee(?:\s+-a)?\s+(?!\/dev\/null\b)\S+/i.test(command) ||
        /\bsed\b[^\n;]*\s-i(?:\s|['"]|$)/i.test(command) ||
        /\bperl\b[^\n;]*\s-(?:pi|ip)\b/i.test(command) ||
        /\b(?:python(?:3)?|node)\b[\s\S]*(?:writeFile(?:Sync)?|appendFile(?:Sync)?|write_text|write_bytes|open\s*\([^)]*,\s*["'][wax])/i.test(command);
    return mutatesFile ? command : "";
}
const STRUCTURED_EDIT_TEXT_KEYS = [
    "content",
    "text",
    "new_text",
    "newText",
    "replacement",
    "ReplacementContent",
    "CodeContent",
    "file_text",
    "new_string",
    "newString",
    "new_str",
];
/**
 * Normalizes replacement text embedded in structured edit arrays and reports
 * whether any edit entry lacks a recognized inspectable text field.
 */
export function extractStructuredEditInspection(input, defaultFilePath) {
    if (!Array.isArray(input.edits)) {
        return { texts: [], hasUninspectableEdit: false };
    }
    const texts = [];
    let hasUninspectableEdit = false;
    for (const raw of input.edits) {
        if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
            hasUninspectableEdit = true;
            continue;
        }
        const edit = raw;
        const filePath = (typeof edit.path === "string" ? edit.path : undefined) ??
            (typeof edit.targetFile === "string" ? edit.targetFile : undefined) ??
            (typeof edit.TargetFile === "string" ? edit.TargetFile : undefined) ??
            (typeof edit.filePath === "string" ? edit.filePath : undefined) ??
            (typeof edit.file === "string" ? edit.file : undefined) ??
            defaultFilePath;
        let extractedAny = false;
        for (const key of STRUCTURED_EDIT_TEXT_KEYS) {
            const value = edit[key];
            // Empty replacements delete content and still represent real edits.
            if (typeof value !== "string")
                continue;
            extractedAny = true;
            texts.push({
                text: value,
                ...(filePath ? { filePath } : {}),
            });
        }
        if (!extractedAny) {
            hasUninspectableEdit = true;
        }
    }
    return { texts, hasUninspectableEdit };
}
/**
 * Normalizes replacement text embedded in structured edit arrays.
 * Providers use several field aliases; rules should inspect the replacement
 * payload rather than treating the outer edits array as opaque.
 */
export function extractStructuredEditTexts(input, defaultFilePath) {
    return extractStructuredEditInspection(input, defaultFilePath).texts;
}
