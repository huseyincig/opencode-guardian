/** Privacy-safe local Guardian audit log, shared by the server, status CLI and TUI. */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { SAFE_REASON_CODES, SAFE_RULE_IDS, type AuditReason } from "./audit.js";
import type { GuardianTelemetryConfig, TelemetryLevel } from "./types.js";

export type { GuardianTelemetryConfig, TelemetryLevel };

export type GuardianEventKind =
  | "stream-interrupt-requested" | "stream-interrupt-verified" | "stream-interrupt-ineffective" | "runtime-started" | "preflight-allowed" | "preflight-blocked" | "post-inspected"
  | "post-warning" | "post-remediation" | "remediation-verified" | "remediation-failed" | "remediation-unverified" | "verification-unavailable" | "inspection-error" | "statistics-reset";
export type PreflightState = "active" | "disabled" | "unavailable";
export type GuardianAction =
  | "interrupt-requested" | "interrupt-checked" | "started" | "allowed" | "inspected" | "blocked-before-execution" | "warned"
  | "remediation-requested" | "remediation-checked" | "inspection-failed" | "statistics-reset";
export type GuardianOutcome =
  | "started" | "allowed" | "prevented" | "reported"
  | "unverified" | "verified" | "error";
export interface GuardianEvent {
  at: string;
  id?: string;
  kind: GuardianEventKind;
  action?: GuardianAction;
  outcome?: GuardianOutcome;
  runtime?: "v2";
  preflight?: PreflightState;
  /** Only a 16-character SHA-256 fingerprint, never the raw session ID. */
  session?: string;
  /** Known shell tool category, never raw arguments or a custom tool name. */
  tool?: string;
  rules?: string[];
  /** Fixed codebook values only: never a finding snippet, pattern or description. */
  reasons?: AuditReason[];
}
export type GuardianStatus = {
  preflight: PreflightState | "unknown";
  inspected: number;
  blocked: number;
  warnings: number;
  remediations: number;
  errors: number;
  verified: number;
  failed: number;
  unverified: number;
  redacted?: number;
  /** Stream interrupts requested; verified/ineffective are the host-observed outcomes of those requests. */
  streamStops: number;
  streamVerified: number;
  streamIneffective: number;
  telemetryLevel?: TelemetryLevel;
  truncated: boolean;
  lastEvent?: string;
  /** Most recent event kind; counters above cover retained history. */
  lastKind?: GuardianEventKind;
};

export const DEFAULT_GUARDIAN_LOG_BYTES = 512 * 1024;
export const GUARDIAN_MAX_LOG_BYTES = 2 * 1024 * 1024;
const ISO_EVENT_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const ACTIONS: Record<GuardianEventKind, [GuardianAction, GuardianOutcome]> = {
  "stream-interrupt-requested": ["interrupt-requested", "unverified"],
  "stream-interrupt-verified": ["interrupt-checked", "verified"],
  "stream-interrupt-ineffective": ["interrupt-checked", "reported"],
  "runtime-started": ["started", "started"],
  "preflight-allowed": ["allowed", "allowed"],
  "preflight-blocked": ["blocked-before-execution", "prevented"],
  "post-inspected": ["inspected", "reported"],
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
  "write", "write_to_file", "write_file", "create_file", "save_file",
  "replace_file_content", "edit_file", "edit", "patch", "apply_patch",
  "str_replace_editor", "multiedit", "file_editor",
  "file_mutate", "file_write", "file_edit",
]);

function projectStateKey(directory: string): string {
  let canonical = path.resolve(directory);
  try {
    canonical = fs.realpathSync(canonical);
  } catch {
    // Directory may not exist yet in synthetic tests.
  }
  return createHash("sha256").update(canonical).digest("hex").slice(0, 16);
}

let testStateCleanupRegistered = false;
function registerTestStateCleanup(testBase: string): void {
  if (testStateCleanupRegistered) return;
  testStateCleanupRegistered = true;
  process.once("exit", () => {
    try {
      fs.rmSync(testBase, { recursive: true, force: true });
    } catch {
      // Fail safe on process exit.
    }
  });
}

export function guardianStateDirectory(directory?: string): string {
  if (process.env.OPENCODE_GUARDIAN_STATE_DIR) return process.env.OPENCODE_GUARDIAN_STATE_DIR;
  // Isolate Node tests so synthetic checks never pollute live counters or project directories.
  if (process.env.NODE_TEST_CONTEXT) {
    const testBase = path.join(os.tmpdir(), `opencode-guardian-tests-${process.pid}`);
    registerTestStateCleanup(testBase);
    if (directory && typeof directory === "string" && directory.trim().length > 0) {
      return path.join(testBase, "projects", projectStateKey(directory));
    }
    return testBase;
  }
  const xdgState = process.env.XDG_STATE_HOME?.trim();
  const stateRoot =
    xdgState && path.isAbsolute(xdgState) ? xdgState : path.join(os.homedir(), ".local", "state");
  const globalBase = path.join(stateRoot, "opencode-guardian");
  if (directory && typeof directory === "string" && directory.trim().length > 0) {
    return path.join(globalBase, "projects", projectStateKey(directory));
  }
  return globalBase;
}
export function guardianEventPath(directory?: string): string {
  const dir = guardianStateDirectory(directory);
  if (fs.existsSync(path.join(dir, "events.jsonl")) && !fs.existsSync(path.join(dir, "guardian-events.jsonl"))) {
    return path.join(dir, "events.jsonl");
  }
  return path.join(dir, "guardian-events.jsonl");
}
export function sessionFingerprint(value: string): string;
export function sessionFingerprint(value?: string): string | undefined;
export function sessionFingerprint(value?: string): string | undefined {
  return value ? createHash("sha256").update(value).digest("hex").slice(0, 16) : undefined;
}

function safeEvent(event: Omit<GuardianEvent, "at">): GuardianEvent {
  if (!Object.hasOwn(ACTIONS, event.kind)) throw new Error("Unknown Guardian event");
  const [action, outcome] = ACTIONS[event.kind];
  const safe: GuardianEvent = {
    at: new Date().toISOString(), id: randomUUID(),
    kind: event.kind, action, outcome,
  };
  if (event.runtime === "v2") safe.runtime = event.runtime;
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
    const rules = event.rules.filter((rule): rule is string =>
      typeof rule === "string" && SAFE_RULE_IDS.has(rule));
    if (rules.length) safe.rules = [...new Set(rules)].slice(0, 20);
  }
  if (Array.isArray(event.reasons)) {
    const reasons = event.reasons.filter((reason): reason is AuditReason =>
      Boolean(reason && SAFE_RULE_IDS.has(reason.rule) && SAFE_REASON_CODES.has(reason.code)));
    if (reasons.length) safe.reasons = reasons.slice(0, 20).map(({ rule, code }) => ({ rule, code }));
  }
  if (event.kind === "preflight-blocked" && safe.rules?.length) {
    safe.reasons = safe.rules
      .filter((code) => SAFE_REASON_CODES.has(code))
      .map((code) => ({ rule: "preflight", code }));
  }
  return safe;
}

function checkFile(file: string): void {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Guardian log must be a regular file owned by this user");
  }
  // Existing archives must not be publicly readable or symlinks.
  if (process.platform !== "win32" && (stat.mode & 0o077) !== 0) fs.chmodSync(file, 0o600);
}

const telemetryConfigRegistry = new Map<string, Map<string, GuardianTelemetryConfig>>();
const verifiedStateDirs = new Set<string>();
const liveMemoryCounters = new Map<string, { inspectedSkippedDisk: number; redactions: number }>();
type FileSignature = string;
type StatusCacheEntry = {
  sig1: FileSignature;
  sig2: FileSignature;
  inspectedSkippedDisk: number;
  redactions: number;
  telemetryLevel: TelemetryLevel;
  status: GuardianStatus;
};
const statusFileCache = new Map<string, StatusCacheEntry>();

function fileStatSignature(filePath: string): FileSignature {
  try {
    const st = fs.lstatSync(filePath, { bigint: true });
    if (!st.isFile() || st.isSymbolicLink()) return "invalid";
    return `${st.ino}:${st.size}:${st.mtimeNs}:${st.ctimeNs}:${st.mode}`;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT" ? "missing" : "error";
  }
}

function invalidateStatusCacheForFile(filePath: string): void {
  const prefix = `${filePath}\0`;
  for (const key of statusFileCache.keys()) {
    if (key.startsWith(prefix)) statusFileCache.delete(key);
  }
}

function memoryCounterKey(directory?: string): string {
  return directory && typeof directory === "string" && directory.trim().length > 0
    ? projectStateKey(directory)
    : "__default__";
}

function getOrCreateMemoryCounter(directory?: string): { inspectedSkippedDisk: number; redactions: number } {
  const key = memoryCounterKey(directory);
  let entry = liveMemoryCounters.get(key);
  if (!entry) {
    entry = { inspectedSkippedDisk: 0, redactions: 0 };
    liveMemoryCounters.set(key, entry);
    while (liveMemoryCounters.size > 256) {
      const oldest = liveMemoryCounters.keys().next().value;
      if (oldest === undefined) break;
      liveMemoryCounters.delete(oldest);
    }
  }
  return entry;
}

export function recordGuardianRedaction(count = 1, directory?: string): void {
  if (!Number.isFinite(count) || count <= 0) return;
  const entry = getOrCreateMemoryCounter(directory);
  entry.redactions += Math.floor(count);
}

export function configureGuardianTelemetry(
  directory: string | undefined,
  config?: GuardianTelemetryConfig,
  ownerId: string | number = "__default__"
): void {
  const key = directory ? path.resolve(directory) : "__default__";
  const ownerKey = String(ownerId);
  if (config) {
    let owners = telemetryConfigRegistry.get(key);
    if (!owners) {
      owners = new Map();
      telemetryConfigRegistry.set(key, owners);
    }
    owners.delete(ownerKey);
    owners.set(ownerKey, config);
  } else {
    const owners = telemetryConfigRegistry.get(key);
    if (!owners) return;
    if (ownerId === "__default__") {
      telemetryConfigRegistry.delete(key);
    } else {
      owners.delete(ownerKey);
      if (owners.size === 0) telemetryConfigRegistry.delete(key);
    }
  }
}

function latestRegisteredTelemetryConfig(key: string): GuardianTelemetryConfig | undefined {
  const owners = telemetryConfigRegistry.get(key);
  if (!owners || owners.size === 0) return undefined;
  let latest: GuardianTelemetryConfig | undefined;
  for (const cfg of owners.values()) {
    latest = cfg;
  }
  return latest;
}

export function clearGuardianTelemetryConfig(): void {
  telemetryConfigRegistry.clear();
  verifiedStateDirs.clear();
  liveMemoryCounters.clear();
  statusFileCache.clear();
}

export function resolveTelemetrySettings(directory?: string): {
  enabled: boolean;
  level: TelemetryLevel;
  maxBytes: number;
} {
  const envTelemetry = process.env.OPENCODE_GUARDIAN_TELEMETRY?.trim().toLowerCase();
  if (envTelemetry === "off" || envTelemetry === "0" || envTelemetry === "false") {
    return { enabled: false, level: "off", maxBytes: DEFAULT_GUARDIAN_LOG_BYTES };
  }

  const envLevel = process.env.OPENCODE_GUARDIAN_LOG_LEVEL?.trim().toLowerCase();
  const envMaxBytes = Number(process.env.OPENCODE_GUARDIAN_MAX_LOG_BYTES);

  const key = directory ? path.resolve(directory) : "__default__";
  const registered =
    latestRegisteredTelemetryConfig(key) ?? latestRegisteredTelemetryConfig("__default__");

  const enabled = registered?.enabled !== false;
  // Unconfigured processes (TUI, status CLI) must show the documented default.
  let level: TelemetryLevel = registered?.level ?? "violations";

  if (envLevel === "violations" || envLevel === "audit") {
    level = "violations";
  } else if (envLevel === "off") {
    level = "off";
  } else if (envLevel === "all") {
    level = "all";
  }

  let maxBytes =
    registered?.maxBytes !== undefined &&
    Number.isFinite(registered.maxBytes) &&
    registered.maxBytes >= 256
      ? Math.min(GUARDIAN_MAX_LOG_BYTES, Math.floor(registered.maxBytes))
      : DEFAULT_GUARDIAN_LOG_BYTES;

  if (Number.isFinite(envMaxBytes) && envMaxBytes >= 256) {
    maxBytes = Math.min(GUARDIAN_MAX_LOG_BYTES, Math.floor(envMaxBytes));
  }

  return { enabled, level, maxBytes };
}

const ROTATION_LOCK_STALE_MS = 5_000;
function acquireRotationLock(lockPath: string): (() => void) | undefined {
  const token = `${process.pid}:${randomUUID()}`;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const lockFd = fs.openSync(
        lockPath,
        fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW ?? 0),
        0o600
      );
      try {
        fs.writeSync(lockFd, token);
      } finally {
        try { fs.closeSync(lockFd); } catch {}
      }
      let released = false;
      return () => {
        if (released) return;
        released = true;
        try {
          if (fs.readFileSync(lockPath, "utf8") === token) {
            fs.unlinkSync(lockPath);
          }
        } catch {}
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== "EEXIST") {
        return undefined;
      }
      try {
        const lockStat = fs.lstatSync(lockPath);
        if (
          !lockStat.isSymbolicLink() &&
          Date.now() - lockStat.mtimeMs > ROTATION_LOCK_STALE_MS
        ) {
          fs.unlinkSync(lockPath);
          continue;
        }
      } catch {}
      return undefined;
    }
  }
  return undefined;
}

let reportedWriteFailure = false;
export function recordGuardianEvent(event: Omit<GuardianEvent, "at">, directoryArg?: string): boolean {
  const settings = resolveTelemetrySettings(directoryArg);
  if (!settings.enabled || settings.level === "off") {
    // Explicit statistics-reset cannot persist a reset marker when telemetry is disabled.
    return event.kind === "statistics-reset" ? false : true;
  }

  if (settings.level === "violations") {
    if (event.kind === "preflight-allowed" || event.kind === "post-inspected") {
      getOrCreateMemoryCounter(directoryArg).inspectedSkippedDisk += 1;
      return true;
    }
  }

  try {
    const dir = guardianStateDirectory(directoryArg);
    let stat = fs.lstatSync(dir, { throwIfNoEntry: false });
    if (!stat) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      stat = fs.lstatSync(dir);
    }
    if (!stat.isDirectory() || stat.isSymbolicLink() || (process.platform !== "win32" &&
        ((stat.mode & 0o077) !== 0 ||
        (typeof process.getuid === "function" && stat.uid !== process.getuid())))) {
      verifiedStateDirs.delete(dir);
      throw new Error("Guardian state directory is not private to the current user");
    }
    if (!verifiedStateDirs.has(dir)) {
      if (verifiedStateDirs.size >= 128) {
        const oldest = verifiedStateDirs.values().next().value;
        if (oldest !== undefined) verifiedStateDirs.delete(oldest);
      }
      verifiedStateDirs.add(dir);
    }

    const line = JSON.stringify(safeEvent(event)) + "\n";
    const filePath = guardianEventPath(directoryArg);
    const archive = filePath + ".1";
    let fd = fs.openSync(filePath,
      fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT |
      (fs.constants.O_NOFOLLOW ?? 0), 0o600);
    try {
      const info = fs.fstatSync(fd);
      if (!info.isFile() || (typeof process.getuid === "function" && info.uid !== process.getuid())) {
        throw new Error("Guardian event log is not owned by the current user");
      }
      if (process.platform !== "win32" && (info.mode & 0o777) !== 0o600) fs.fchmodSync(fd, 0o600);
      if (info.size + Buffer.byteLength(line) > settings.maxBytes) {
        const releaseLock = acquireRotationLock(filePath + ".lock");
        if (releaseLock) {
          try {
            // Re-check file size and inode after acquiring lock so concurrent processes
            // neither double-rotate nor append into a rotated archive via a stale fd.
            const freshStat = fs.lstatSync(filePath, { throwIfNoEntry: false });
            if (freshStat && freshStat.isFile() && freshStat.ino !== info.ino) {
              fs.closeSync(fd);
              fd = fs.openSync(filePath,
                fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT |
                (fs.constants.O_NOFOLLOW ?? 0), 0o600);
            }
            const activeStat = fs.fstatSync(fd);
            if (activeStat.isFile() && activeStat.size + Buffer.byteLength(line) > settings.maxBytes) {
              // Keep exactly one bounded archive. Refuse unsafe pre-existing archive paths.
              if (fs.existsSync(archive) || fs.lstatSync(archive, { throwIfNoEntry: false })) {
                checkFile(archive);
              }
              fs.closeSync(fd);
              fd = -1;
              try {
                fs.unlinkSync(archive);
              } catch (err) {
                if ((err as NodeJS.ErrnoException)?.code !== "ENOENT") throw err;
              }
              try {
                fs.renameSync(filePath, archive);
              } catch (err) {
                if ((err as NodeJS.ErrnoException)?.code !== "ENOENT") throw err;
              }
              fd = fs.openSync(filePath,
                fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT |
                (fs.constants.O_NOFOLLOW ?? 0), 0o600);
              const current = fs.fstatSync(fd);
              if (!current.isFile() ||
                  (typeof process.getuid === "function" && current.uid !== process.getuid())) {
                throw new Error("Rotated Guardian log is not owned by this user");
              }
              if (process.platform !== "win32" && (current.mode & 0o777) !== 0o600) fs.fchmodSync(fd, 0o600);
            }
          } finally {
            releaseLock();
          }
        }
      }
      if (fs.writeSync(fd, line) !== Buffer.byteLength(line)) {
        throw new Error("Guardian audit write was incomplete");
      }
      if (event.kind === "statistics-reset") {
        liveMemoryCounters.delete(memoryCounterKey(directoryArg));
      }
      invalidateStatusCacheForFile(filePath);
      return true;
    } finally {
      if (fd !== -1) fs.closeSync(fd);
    }
  } catch {
    if (!reportedWriteFailure) {
      reportedWriteFailure = true;
      // Do not print error objects (which can contain private paths) into the TUI.
      console.error("[opencode-guardian] Could not write local audit log.");
    }
    return false;
  }
}

/** Reads at most the newest 2 MiB across the current log and one archive. */
export function readGuardianStatus(
  directoryOrMaxBytes?: string | number,
  maxBytesArg = GUARDIAN_MAX_LOG_BYTES
): GuardianStatus {
  let directory: string | undefined;
  let maxBytes = maxBytesArg;
  if (typeof directoryOrMaxBytes === "number") {
    maxBytes = directoryOrMaxBytes;
  } else if (typeof directoryOrMaxBytes === "string") {
    directory = directoryOrMaxBytes;
  }
  maxBytes = Number.isFinite(maxBytes) ? Math.max(1, Math.min(GUARDIAN_MAX_LOG_BYTES, Math.floor(maxBytes))) : GUARDIAN_MAX_LOG_BYTES;
  const mem = liveMemoryCounters.get(memoryCounterKey(directory));
  const settings = resolveTelemetrySettings(directory);
  const inspectedSkippedDisk = typeof directoryOrMaxBytes === "number" ? 0 : (mem?.inspectedSkippedDisk ?? 0);
  const redactions = mem?.redactions ?? 0;
  let cacheKey: string | undefined;
  let sig1: FileSignature = "missing";
  let sig2: FileSignature = "missing";
  try {
    const file = guardianEventPath(directory);
    sig1 = fileStatSignature(file);
    sig2 = fileStatSignature(file + ".1");
    cacheKey = `${file}\0${maxBytes}`;
    const cached = statusFileCache.get(cacheKey);
    if (
      cached &&
      cached.sig1 === sig1 &&
      cached.sig2 === sig2 &&
      cached.inspectedSkippedDisk === inspectedSkippedDisk &&
      cached.redactions === redactions &&
      cached.telemetryLevel === settings.level
    ) {
      return { ...cached.status };
    }
  } catch {
    // Fall through to normal read path on path resolution issues.
  }
  const result: GuardianStatus = {
    preflight: "unknown",
    inspected: inspectedSkippedDisk,
    blocked: 0,
    warnings: 0,
    remediations: 0,
    errors: 0,
    verified: 0,
    failed: 0,
    unverified: 0,
    streamStops: 0,
    streamVerified: 0,
    streamIneffective: 0,
    redacted: redactions,
    telemetryLevel: settings.level,
    truncated: false,
  };
  try {
    const file = guardianEventPath(directory);
    const buffers: string[] = [];
    for (const candidate of [file, file + ".1"]) {
      if (maxBytes <= 0) {
        if (fs.existsSync(candidate)) result.truncated = true;
        continue;
      }
      let fd: number | undefined;
      try {
        fd = fs.openSync(candidate, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
        const stat = fs.fstatSync(fd);
        if (!stat.isFile() || (typeof process.getuid === "function" && stat.uid !== process.getuid()) ||
            (process.platform !== "win32" && (stat.mode & 0o077) !== 0)) {
          result.truncated = true;
          continue;
        }
        const size = stat.size;
        const start = Math.max(0, size - maxBytes);
        const buffer = Buffer.alloc(size - start);
        const read = fs.readSync(fd, buffer, 0, buffer.length, start);
        let source = buffer.toString("utf8", 0, read);
        if (start > 0) {
          result.truncated = true;
          const nl = source.indexOf("\n");
          source = nl >= 0 ? source.slice(nl + 1) : "";
        }
        buffers.unshift(source);
        maxBytes -= read;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
          // Malformed or unreadable logs must not print paths over the host prompt.
          result.truncated = true;
        }
      } finally {
        if (fd !== undefined) fs.closeSync(fd);
      }
    }
    let recentPreflightAt = "";
    for (const line of buffers.join("").split("\n")) {
      if (!line) continue;
      let entry: GuardianEvent;
      try { entry = JSON.parse(line) as GuardianEvent; } catch { continue; }
      if (!entry || !Object.hasOwn(ACTIONS, entry.kind) ||
          typeof entry.at !== "string" || !ISO_EVENT_TIME.test(entry.at)) continue;
      result.lastEvent = entry.at;
      result.lastKind = entry.kind;
      if (entry.kind === "runtime-started" &&
          (entry.preflight === "active" || entry.preflight === "disabled" ||
            entry.preflight === "unavailable") && entry.at >= recentPreflightAt) {
        recentPreflightAt = entry.at;
        result.preflight = entry.preflight;
      }
      if (entry.kind === "statistics-reset") {
        result.inspected = typeof directoryOrMaxBytes === "number" ? 0 : (mem?.inspectedSkippedDisk ?? 0);
        result.blocked = result.warnings = result.remediations = 0;
        result.errors = result.verified = result.failed = result.unverified = 0;
        result.streamStops = result.streamVerified = result.streamIneffective = 0;
        continue;
      }
      if (entry.kind === "stream-interrupt-requested") result.streamStops++;
      if (entry.kind === "stream-interrupt-verified") result.streamVerified++;
      if (entry.kind === "stream-interrupt-ineffective") result.streamIneffective++;
      if (entry.kind === "preflight-allowed" || entry.kind === "preflight-blocked" || entry.kind === "post-inspected") result.inspected++;
      if (entry.kind === "preflight-blocked") result.blocked++;
      if (entry.kind === "post-warning") result.warnings++;
      if (entry.kind === "post-remediation") result.remediations++;
      if (entry.kind === "inspection-error") result.errors++;
      if (entry.kind === "remediation-verified") result.verified++;
      if (entry.kind === "remediation-failed") result.failed++;
      if (entry.kind === "remediation-unverified") result.unverified++;
    }
  } catch {
    // A damaged audit file must not prevent the plugin or TUI from starting.
    result.truncated = true;
  }
  if (cacheKey && sig1 !== "error" && sig2 !== "error") {
    statusFileCache.delete(cacheKey);
    statusFileCache.set(cacheKey, {
      sig1,
      sig2,
      inspectedSkippedDisk,
      redactions,
      telemetryLevel: settings.level,
      status: { ...result },
    });
    while (statusFileCache.size > 64) {
      const oldest = statusFileCache.keys().next().value;
      if (oldest === undefined) break;
      statusFileCache.delete(oldest);
    }
  }
  return result;
}

/** Reset displayed counters without deleting or rewriting the security event trail. */
export function resetGuardianStatistics(directory?: string): boolean {
  return recordGuardianEvent({ kind: "statistics-reset" }, directory);
}

/** Bounded, redacted activity. Never return arbitrary fields from the log. */
export function readGuardianActivity(directory?: string, limit = 12): GuardianEvent[] {
  const count = Number.isFinite(limit) ? Math.max(1, Math.min(30, Math.floor(limit))) : 12;
  const file = guardianEventPath(directory);
  const output: GuardianEvent[] = [];
  for (const candidate of [file + ".1", file]) {
    let fd: number | undefined;
    try {
      fd = fs.openSync(candidate, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || (typeof process.getuid === "function" && stat.uid !== process.getuid()) ||
          (process.platform !== "win32" && (stat.mode & 0o077) !== 0)) continue;
      const start = Math.max(0, stat.size - GUARDIAN_MAX_LOG_BYTES);
      const buffer = Buffer.alloc(stat.size - start);
      const size = fs.readSync(fd, buffer, 0, buffer.length, start);
      let raw = buffer.toString("utf8", 0, size);
      if (start > 0) {
        const nl = raw.indexOf("\n");
        raw = nl >= 0 ? raw.slice(nl + 1) : "";
      }
      for (const line of raw.split("\n")) {
        if (!line) continue;
        let event: GuardianEvent;
        try { event = JSON.parse(line) as GuardianEvent; } catch { continue; }
        if (!event || typeof event.at !== "string" || !ISO_EVENT_TIME.test(event.at) ||
            !Object.hasOwn(ACTIONS, event.kind)) continue;
        const safe: GuardianEvent = { at: event.at, kind: event.kind };
        if (typeof event.tool === "string" && SAFE_TOOLS.has(event.tool)) safe.tool = event.tool;
        if (Array.isArray(event.rules)) {
          safe.rules = event.rules.filter((id): id is string =>
            typeof id === "string" && SAFE_RULE_IDS.has(id)).slice(0, 5);
        }
        output.push(safe);
        if (output.length > count) output.shift();
      }
    } catch {
      // Activity display must not leak paths or interrupt the host.
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
  }
  return output.reverse();
}
