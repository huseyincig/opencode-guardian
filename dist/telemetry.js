/** Privacy-safe local Guardian audit log, shared by the server, status CLI and TUI. */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { SAFE_REASON_CODES, SAFE_RULE_IDS } from "./audit.js";
export const GUARDIAN_MAX_LOG_BYTES = 2 * 1024 * 1024;
const ISO_EVENT_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ACTIONS = {
    "runtime-started": ["started", "started"],
    "preflight-allowed": ["allowed", "allowed"],
    "preflight-blocked": ["blocked-before-execution", "prevented"],
    "post-warning": ["warned", "reported"],
    // Queuing an instruction proves nothing about whether the agent fixed it.
    "post-remediation": ["remediation-requested", "unverified"],
    "remediation-verified": ["remediation-checked", "verified"],
    "remediation-failed": ["remediation-checked", "reported"],
    "remediation-unverified": ["remediation-checked", "unverified"],
    "verification-unavailable": ["warned", "unverified"],
    "inspection-error": ["inspection-failed", "error"],
    "statistics-reset": ["statistics-reset", "reported"],
};
const SAFE_TOOLS = new Set([
    "bash", "sh", "zsh", "shell", "terminal", "exec", "shell_exec",
    "execute_command", "command", "run_command", "run_shell_command",
    "powershell", "pwsh", "cmd", "privileged_shell_exec", "process_start",
    "write_to_file", "write_file", "create_file", "save_file",
    "replace_file_content", "edit_file", "edit", "patch", "apply_patch",
    "str_replace_editor", "multiedit", "file_editor",
    "file_mutate", "file_write", "file_edit",
]);
export function guardianStateDirectory(directory) {
    if (process.env.OPENCODE_GUARDIAN_STATE_DIR)
        return process.env.OPENCODE_GUARDIAN_STATE_DIR;
    if (directory && typeof directory === "string" && directory.trim().length > 0) {
        return path.join(directory, ".opencode");
    }
    // Isolate Node tests so synthetic checks never pollute live counters.
    if (process.env.NODE_TEST_CONTEXT)
        return path.join(os.tmpdir(), `opencode-guardian-tests-${process.pid}`);
    return path.join(os.homedir(), ".local", "state", "opencode-guardian");
}
export function guardianEventPath(directory) {
    const dir = guardianStateDirectory(directory);
    if (fs.existsSync(path.join(dir, "events.jsonl")) && !fs.existsSync(path.join(dir, "guardian-events.jsonl"))) {
        return path.join(dir, "events.jsonl");
    }
    return path.join(dir, "guardian-events.jsonl");
}
export function sessionFingerprint(value) {
    return value ? createHash("sha256").update(value).digest("hex").slice(0, 16) : undefined;
}
function safeEvent(event) {
    if (!Object.hasOwn(ACTIONS, event.kind))
        throw new Error("Unknown Guardian event");
    const [action, outcome] = ACTIONS[event.kind];
    const safe = {
        at: new Date().toISOString(), id: randomUUID(),
        kind: event.kind, action, outcome,
    };
    if (event.runtime === "v1" || event.runtime === "v2")
        safe.runtime = event.runtime;
    if (event.preflight === "active" || event.preflight === "disabled" || event.preflight === "unavailable") {
        safe.preflight = event.preflight;
    }
    if (typeof event.session === "string" && /^[a-f0-9]{16}$/.test(event.session)) {
        safe.session = event.session;
    }
    if (typeof event.tool === "string") {
        const tool = event.tool.toLowerCase().split(/[.:/]/).at(-1) ?? "";
        safe.tool = SAFE_TOOLS.has(tool) ? tool : "custom-shell-tool";
    }
    if (Array.isArray(event.rules)) {
        const rules = event.rules.filter((rule) => typeof rule === "string" && SAFE_RULE_IDS.has(rule));
        if (rules.length)
            safe.rules = [...new Set(rules)].slice(0, 20);
    }
    if (Array.isArray(event.reasons)) {
        const reasons = event.reasons.filter((reason) => Boolean(reason && SAFE_RULE_IDS.has(reason.rule) && SAFE_REASON_CODES.has(reason.code)));
        if (reasons.length)
            safe.reasons = reasons.slice(0, 20).map(({ rule, code }) => ({ rule, code }));
    }
    if (event.kind === "preflight-blocked" && safe.rules?.length) {
        safe.reasons = safe.rules
            .filter((code) => SAFE_REASON_CODES.has(code))
            .map((code) => ({ rule: "preflight", code }));
    }
    return safe;
}
function checkFile(file) {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
        throw new Error("Guardian log must be a regular file owned by this user");
    }
    // Existing archives must not be publicly readable or symlinks.
    if (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
        fs.chmodSync(file, 0o600);
}
let reportedWriteFailure = false;
export function recordGuardianEvent(event, directoryArg) {
    try {
        const dir = guardianStateDirectory(directoryArg);
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
        const stat = fs.lstatSync(dir);
        const isProjectDirectory = Boolean(directoryArg && !process.env.OPENCODE_GUARDIAN_STATE_DIR);
        if (!stat.isDirectory() || (process.platform !== "win32" &&
            ((!isProjectDirectory && (stat.mode & 0o077) !== 0) ||
                (typeof process.getuid === "function" && stat.uid !== process.getuid())))) {
            throw new Error("Guardian state directory is not private to the current user");
        }
        const line = JSON.stringify(safeEvent(event)) + "\n";
        const filePath = guardianEventPath(directoryArg);
        const archive = filePath + ".1";
        let fd = fs.openSync(filePath, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT |
            (fs.constants.O_NOFOLLOW ?? 0), 0o600);
        try {
            const info = fs.fstatSync(fd);
            if (!info.isFile() || (typeof process.getuid === "function" && info.uid !== process.getuid())) {
                throw new Error("Guardian event log is not owned by the current user");
            }
            if (process.platform !== "win32" && (info.mode & 0o777) !== 0o600)
                fs.fchmodSync(fd, 0o600);
            if (info.size + Buffer.byteLength(line) > GUARDIAN_MAX_LOG_BYTES) {
                // Keep exactly one bounded archive. Refuse unsafe pre-existing archive paths.
                if (fs.existsSync(archive) || fs.lstatSync(archive, { throwIfNoEntry: false })) {
                    checkFile(archive);
                }
                fs.closeSync(fd);
                fd = -1;
                if (fs.existsSync(archive))
                    fs.unlinkSync(archive);
                fs.renameSync(filePath, archive);
                fd = fs.openSync(filePath, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT |
                    (fs.constants.O_NOFOLLOW ?? 0), 0o600);
                const current = fs.fstatSync(fd);
                if (!current.isFile() ||
                    (typeof process.getuid === "function" && current.uid !== process.getuid())) {
                    throw new Error("Rotated Guardian log is not owned by this user");
                }
                if (process.platform !== "win32" && (current.mode & 0o777) !== 0o600)
                    fs.fchmodSync(fd, 0o600);
            }
            if (fs.writeSync(fd, line) !== Buffer.byteLength(line)) {
                throw new Error("Guardian audit write was incomplete");
            }
            return true;
        }
        finally {
            if (fd !== -1)
                fs.closeSync(fd);
        }
    }
    catch (error) {
        if (!reportedWriteFailure) {
            reportedWriteFailure = true;
            // Do not print error objects (which can contain private paths) into the TUI.
            console.error("[opencode-guardian] Could not write local audit log.");
        }
        return false;
    }
}
/** Reads at most the newest 2 MiB across the current log and one archive. */
export function readGuardianStatus(directoryOrMaxBytes, maxBytesArg = GUARDIAN_MAX_LOG_BYTES) {
    let directory;
    let maxBytes = maxBytesArg;
    if (typeof directoryOrMaxBytes === "number") {
        maxBytes = directoryOrMaxBytes;
    }
    else if (typeof directoryOrMaxBytes === "string") {
        directory = directoryOrMaxBytes;
    }
    maxBytes = Number.isFinite(maxBytes) ? Math.max(1, Math.min(GUARDIAN_MAX_LOG_BYTES, Math.floor(maxBytes))) : GUARDIAN_MAX_LOG_BYTES;
    const result = {
        preflight: "unknown", inspected: 0, blocked: 0, warnings: 0,
        remediations: 0, errors: 0, verified: 0, failed: 0, unverified: 0, truncated: false,
    };
    try {
        const file = guardianEventPath(directory);
        const buffers = [];
        for (const candidate of [file, file + ".1"]) {
            if (maxBytes <= 0) {
                if (fs.existsSync(candidate))
                    result.truncated = true;
                continue;
            }
            let fd;
            try {
                fd = fs.openSync(candidate, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
                const size = fs.fstatSync(fd).size;
                const start = Math.max(0, size - maxBytes);
                const buffer = Buffer.alloc(size - start);
                const read = fs.readSync(fd, buffer, 0, buffer.length, start);
                let source = buffer.toString("utf8", 0, read);
                if (start > 0) {
                    result.truncated = true;
                    source = source.slice(source.indexOf("\n") + 1);
                }
                buffers.unshift(source);
                maxBytes -= read;
            }
            catch (error) {
                if (error.code !== "ENOENT") {
                    // Malformed or unreadable logs must not print paths over the host prompt.
                    result.truncated = true;
                }
            }
            finally {
                if (fd !== undefined)
                    fs.closeSync(fd);
            }
        }
        let recentPreflightAt = "";
        for (const line of buffers.join("").split("\n")) {
            if (!line)
                continue;
            let entry;
            try {
                entry = JSON.parse(line);
            }
            catch {
                continue;
            }
            if (!entry || !Object.hasOwn(ACTIONS, entry.kind) ||
                typeof entry.at !== "string" || !ISO_EVENT_TIME.test(entry.at))
                continue;
            result.lastEvent = entry.at;
            result.lastKind = entry.kind;
            if (entry.kind === "runtime-started" &&
                (entry.preflight === "active" || entry.preflight === "disabled" ||
                    entry.preflight === "unavailable") && entry.at >= recentPreflightAt) {
                recentPreflightAt = entry.at;
                result.preflight = entry.preflight;
            }
            if (entry.kind === "statistics-reset") {
                result.inspected = result.blocked = result.warnings = result.remediations = 0;
                result.errors = result.verified = result.failed = result.unverified = 0;
                continue;
            }
            if (entry.kind === "preflight-allowed" || entry.kind === "preflight-blocked")
                result.inspected++;
            if (entry.kind === "preflight-blocked")
                result.blocked++;
            if (entry.kind === "post-warning")
                result.warnings++;
            if (entry.kind === "post-remediation")
                result.remediations++;
            if (entry.kind === "inspection-error")
                result.errors++;
            if (entry.kind === "remediation-verified")
                result.verified++;
            if (entry.kind === "remediation-failed")
                result.failed++;
            if (entry.kind === "remediation-unverified")
                result.unverified++;
        }
    }
    catch {
        // A damaged audit file must not prevent the plugin or TUI from starting.
        result.truncated = true;
    }
    return result;
}
/** Reset displayed counters without deleting or rewriting the security event trail. */
export function resetGuardianStatistics(directory) {
    return recordGuardianEvent({ kind: "statistics-reset" }, directory);
}
/** Bounded, redacted activity. Never return arbitrary fields from the log. */
export function readGuardianActivity(directory, limit = 12) {
    const count = Number.isFinite(limit) ? Math.max(1, Math.min(30, Math.floor(limit))) : 12;
    const file = guardianEventPath(directory);
    const output = [];
    for (const candidate of [file + ".1", file]) {
        let fd;
        try {
            fd = fs.openSync(candidate, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
            const stat = fs.fstatSync(fd);
            if (!stat.isFile() || (typeof process.getuid === "function" && stat.uid !== process.getuid()) ||
                (process.platform !== "win32" && (stat.mode & 0o077) !== 0))
                continue;
            const start = Math.max(0, stat.size - GUARDIAN_MAX_LOG_BYTES);
            const buffer = Buffer.alloc(stat.size - start);
            const size = fs.readSync(fd, buffer, 0, buffer.length, start);
            let raw = buffer.toString("utf8", 0, size);
            if (start > 0)
                raw = raw.slice(raw.indexOf("\n") + 1);
            for (const line of raw.split("\n")) {
                if (!line)
                    continue;
                let event;
                try {
                    event = JSON.parse(line);
                }
                catch {
                    continue;
                }
                if (!event || typeof event.at !== "string" || !ISO_EVENT_TIME.test(event.at) ||
                    !Object.hasOwn(ACTIONS, event.kind))
                    continue;
                const safe = { at: event.at, kind: event.kind };
                if (typeof event.tool === "string" && SAFE_TOOLS.has(event.tool))
                    safe.tool = event.tool;
                if (Array.isArray(event.rules)) {
                    safe.rules = event.rules.filter((id) => typeof id === "string" && SAFE_RULE_IDS.has(id)).slice(0, 5);
                }
                output.push(safe);
                if (output.length > count)
                    output.shift();
            }
        }
        catch {
            // Activity display must not leak paths or interrupt the host.
        }
        finally {
            if (fd !== undefined)
                fs.closeSync(fd);
        }
    }
    return output.reverse();
}
