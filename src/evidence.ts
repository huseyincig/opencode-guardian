import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import type {
  EvidenceKind,
  EvidenceRecord,
  EvidenceStatus,
  MessagePart,
  SessionMessage,
  TurnEvidence,
} from "./types.js";
import { extractLikelyShellMutation } from "./tool-input.js";
import { activeBacktickSubstitutions, activeCommandSubstitutions, hasFindDeletion, literalShellScripts, shellCommandVariants, splitShellStages } from "./shell-risk.js";
export { isOpaqueShellExecution } from "./shell-risk.js";

function stringify(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined || value === null) return "";
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

function stableStringify(value: unknown): string {
  const seen = new WeakSet<object>();

  const normalize = (input: unknown): unknown => {
    if (input === null || typeof input !== "object") return input;
    if (seen.has(input)) return "[Circular]";
    seen.add(input);

    if (Array.isArray(input)) return input.map(normalize);
    return Object.fromEntries(
      Object.entries(input as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, entry]) => [key, normalize(entry)])
    );
  };

  try {
    return JSON.stringify(normalize(value));
  } catch {
    return String(value);
  }
}

function commandFromPart(part: MessagePart): string {
  const input = part.state?.input;
  if (!input) return "";

  for (const key of ["command", "cmd", "script"]) {
    const value = input[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

function toolNameFromPart(part: MessagePart): string {
  if (typeof part.tool === "string") return part.tool;
  if (typeof part.name === "string") return part.name;
  return "tool";
}

function parseExitCode(part: MessagePart, outputText: string): number | undefined {
  const metadata = part.state?.metadata;
  const direct =
    metadata?.exit ??
    metadata?.exitCode ??
    metadata?.code ??
    part.state?.exitCode;
  if (typeof direct === "number" && Number.isFinite(direct)) return direct;
  if (typeof direct === "string" && direct.trim() !== "") {
    const parsed = Number(direct);
    if (Number.isFinite(parsed)) return parsed;
  }

  const bracket = /\[exit code:\s*(-?\d+)\]/i.exec(outputText);
  if (bracket) return Number(bracket[1]);

  const plain = /(?:^|\n)exit(?:\s+code)?\s*[:=]\s*(-?\d+)\b/i.exec(outputText);
  if (plain) return Number(plain[1]);

  return undefined;
}

function statusFromPart(part: MessagePart, outputText: string): {
  status: EvidenceStatus;
  exitCode?: number;
  errorText: string;
} {
  const state = part.state;
  if (!state) return { status: "unknown", errorText: "" };

  const errorText = stringify(state.error).trim();
  const exitCode = parseExitCode(part, outputText);

  if (state.status === "error") {
    return {
      status: "failure",
      ...(exitCode !== undefined ? { exitCode } : {}),
      errorText: errorText || outputText,
    };
  }

  if (exitCode !== undefined) {
    return {
      status: exitCode === 0 ? "success" : "failure",
      exitCode,
      errorText: exitCode === 0 ? "" : errorText || outputText,
    };
  }

  if (state.status === "completed") {
    // Trust the host's completed state unless an explicit non-zero exit code or
    // error status says otherwise. Output text can legitimately contain words
    // such as "error" while a grep/audit/test command still succeeds.
    return { status: "success", errorText: "" };
  }

  return { status: "unknown", errorText };
}

function normalizeCommand(command: string): string {
  return command
    .replace(/\s+/g, " ")
    .replace(/\s+2>&1\b/g, "")
    .replace(/\s+--verbose\b/g, "")
    .trim();
}

export function normalizeErrorFingerprint(errorText: string): string {
  return errorText
    .toLowerCase()
    .replace(/\x1b\[[0-9;]*m/g, "")
    .replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi, "<uuid>")
    .replace(/\b0x[0-9a-f]+\b/gi, "<hex>")
    .replace(/\b[0-9a-f]{12,}\b/gi, "<id>")
    .replace(/\b\d{4}-\d{2}-\d{2}[t\s][0-9:.+-z]+\b/gi, "<time>")
    .replace(/:\d{2,5}\b/g, ":<n>")
    // Keep short semantic numbers such as HTTP 404 vs 500 or exit 1 vs 2.
    // Normalize only longer volatile IDs/PIDs/counts to avoid merging distinct
    // root causes into one circuit-breaker fingerprint.
    .replace(/\b\d{4,}\b/g, "<n>")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 240);
}

function classifyCommand(command: string, toolName: string): EvidenceKind[] {
  const c = normalizeCommand(command).toLowerCase();
  const t = toolName.toLowerCase();
  const kinds = new Set<EvidenceKind>();

  if (
    /(?:^|\s)(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test\b/.test(c) ||
    /(?:^|\s)(?:pytest|py\.test|python(?:3)?\s+-m\s+(?:pytest|unittest)|go\s+test|cargo\s+(?:test|nextest\s+run)|node\s+--test|jest|vitest|dotnet\s+test|phpunit|make\s+test)\b/.test(c) ||
    /(?:^|\s)(?:mvn|mvnw)\b[^\n;&|]*(?:\btest\b|\bverify\b)/.test(c) ||
    /(?:^|\s)(?:gradle|gradlew)\b[^\n;&|]*\btest\b/.test(c)
  ) {
    kinds.add("test");
  }

  if (
    /(?:^|\s)(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?build\b/.test(c) ||
    /(?:^|\s)(?:cargo\s+build|go\s+build|dotnet\s+build|make\s+build)\b/.test(c) ||
    /(?:^|\s)(?:mvn|mvnw)\b[^\n;&|]*(?:\bpackage\b|\binstall\b)/.test(c) ||
    /(?:^|\s)(?:gradle|gradlew)\b[^\n;&|]*\bbuild\b/.test(c)
  ) {
    kinds.add("build");
  }

  if (
    /(?:^|\s)(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?typecheck\b/.test(c) ||
    /(?:^|\s)(?:tsc\b[^\n;&|]*--noemit|mypy|pyright)\b/.test(c)
  ) {
    kinds.add("typecheck");
  }

  if (
    /(?:^|\s)(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?lint\b/.test(c) ||
    /(?:^|\s)(?:eslint|ruff|flake8|golangci-lint|cargo\s+clippy)\b/.test(c)
  ) {
    kinds.add("lint");
  }

  if (
    /(?:^|\s)(?:npm|pnpm|yarn)\s+audit\b/.test(c) ||
    /(?:^|\s)(?:pip-audit|cargo\s+audit|govulncheck|bundle\s+audit)\b/.test(c)
  ) {
    kinds.add("audit");
  }

  if (/\bgit\s+push\b/.test(c) || /(?:push|update_ref|updateref)/.test(t)) {
    kinds.add("git-push");
  }

  if (/\bgit\s+status\b/.test(c)) kinds.add("git-status");

  if (
    /\bgit\s+(?:show|diff|blame|merge-base|rev-parse)\b[^\n;&|]*(?:main|master|origin\/|head\^|head~|[0-9a-f]{7,40})/i.test(command) ||
    /\bgit\s+(?:checkout|switch)\s+(?:--detach\s+)?(?:main|master|origin\/[^\s]+)/i.test(command) ||
    /\bgit\s+worktree\b/i.test(command) ||
    /\b(?:baseline|before-change|pre-change)\b/i.test(command)
  ) {
    kinds.add("baseline");
  }

  if (
    /(?:^|\s)(?:npm|pnpm|yarn|bun)\s+(?:install|add)\b/.test(c) ||
    /(?:^|\s)(?:pip(?:3)?\s+install|python(?:3)?\s+-m\s+pip\s+install|cargo\s+add|go\s+get)\b/.test(c)
  ) {
    kinds.add("install");
  }

  if (isDestructiveCommand(command)) kinds.add("destructive-operation");

  if (kinds.size === 0) kinds.add("generic");
  return [...kinds];
}

export function isVerificationFailureMask(command: string): boolean {
  return /(?:\|\|\s*(?:true\b|:(?=\s|$)|exit\s+0\b)|;\s*exit\s+0\b)/i.test(
    command
  );
}

function isRecursiveForceRemove(command: string): boolean {
  const candidates = command.match(/^\s*(?:sudo\s+)?rm\s+[^\n;&|]+/gi) ?? [];
  return candidates.some((candidate) => {
    const flags = candidate.match(/(?:^|\s)-[a-z]+\b|--(?:recursive|force)\b/gi) ?? [];
    const recursive = flags.some((flag) => /--recursive|^-[a-z]*r/i.test(flag.trim()));
    const forced = flags.some((flag) => /--force|^-[a-z]*f/i.test(flag.trim()));
    return recursive && forced;
  });
}

// Git global -C/-c options are legal before every subcommand.
const GIT_RESET_INVOCATION =
  /^\s*(?:sudo\s+)?git(?:\s+(?:-C|-c)\s+(?:"[^"]*"|'[^']*'|[^\s;&|\n]+))*\s+reset\b[^\n;&|]*--hard\b/i;
const GIT_FORCE_PUSH_INVOCATION =
  /^\s*(?:sudo\s+)?git(?:\s+(?:-C|-c)\s+(?:"[^"]*"|'[^']*'|[^\s;&|\n]+))*\s+push\b[^\n;&|]*(?:--force(?:-with-lease)?(?:=[^\s;&|]+)?|\s-f(?:\s|$))/i;

const GIT_CLEAN_INVOCATION =
  /\bgit(?:\s+(?:-C|-c)\s+(?:"[^"]*"|'[^']*'|[^\s;&|\n]+))*\s+clean\b/i;

export function gitCleanInvocation(command: string): string | undefined {
  return GIT_CLEAN_INVOCATION.exec(command)?.[0];
}

function isDestructiveGitClean(command: string): boolean {
  // Each shell segment is checked independently: an initial dry-run does not
  // make a later destructive clean safe, and a dry-run alone is not destructive.
  return splitShellStages(command).flat().some((segment) => {
    if (!/^\s*(?:sudo\s+)?git\b/i.test(segment)) return false;
    const invocation = GIT_CLEAN_INVOCATION.exec(segment);
    if (!invocation) return false;

    const argumentsText = segment.slice(invocation.index + invocation[0].length);
    const flags = [
      ...argumentsText.matchAll(/(?:^|\s)(--[a-z-]+|-[a-z]+)(?=\s|$)/gi),
    ].flatMap((match) => match[1] ? [match[1].toLowerCase()] : []);

    const isDryRun = flags.some(
      (flag) => flag === "--dry-run" || /^-[a-z]*n/.test(flag)
    );
    const hasForce = flags.some(
      (flag) => flag === "--force" || /^-[a-z]*f/.test(flag)
    );
    return hasForce && !isDryRun;
  });
}

// Recognize common literal filesystem formatting commands without flagging
// quoted examples or inspection-only --help/--version invocations.
function isFilesystemFormatCommand(command: string): boolean {
  const match = /^\s*(?:sudo\s+)?(?:\/(?:usr\/)?sbin\/)?mkfs(?:\.[a-z0-9_-]+)?(?=\s|$)/i.exec(command);
  if (!match) return false;
  return !/^\s*(?:--help|--version|-h|-V)(?:\s|$)/i.test(command.slice(match[0].length));
}

// A known literal Bash function fork bomb, including a named function.
// This is deliberately not a general shell evaluation or fork-bomb detector.
const LITERAL_FORK_BOMB =
  /^\s*([:a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1(?=\s*(?:;|&&|$))/i;

function isLegacyDestructiveCommand(command: string): boolean {
  return (
    GIT_RESET_INVOCATION.test(command) ||
    isDestructiveGitClean(command) ||
    GIT_FORCE_PUSH_INVOCATION.test(command) ||
    isFilesystemFormatCommand(command) ||
    isRecursiveForceRemove(command) ||
    /\b(?:drop\s+(?:database|schema|table)|truncate\s+table)\b/i.test(command) ||
    /\bterraform\s+destroy\b/i.test(command) ||
    /\bkubectl\s+delete\s+(?:namespace|ns)\b/i.test(command) ||
    /\bdocker\s+system\s+prune\b[^\n;&|]*(?:-a\b|--all\b)/i.test(command) ||
    /\bnpm\s+unpublish\b/i.test(command) ||
    /\bgh\s+repo\s+delete\b/i.test(command)
  );
}

/**
 * Detect literal destructive shell actions, including common shell rewrites.
 * Post-execution classification cannot serve as a pre-execution safety gate.
 */
export function isDestructiveCommand(command: string, depth = 0): boolean {
  if (LITERAL_FORK_BOMB.test(command)) return true;
  if (shellCommandVariants(command).some(
    (candidate) => isLegacyDestructiveCommand(candidate) || hasFindDeletion(candidate)
  )) return true;
  if (depth >= 4) return false;
  return [
    ...activeCommandSubstitutions(command),
    ...activeBacktickSubstitutions(command),
    ...literalShellScripts(command),
  ].some((nested) => isDestructiveCommand(nested, depth + 1));
}

/** Recognize actual literal rm invocations, not quoted examples or help output.
 * Separate from recursive-force classification to preserve existing evidence kinds. */
export function isSimpleFileRemoval(command: string, depth = 0): boolean {
  if (shellCommandVariants(command).some((candidate) => {
    const match = /^\s*(?:sudo\s+)?rm\s+(.+)$/i.exec(candidate);
    if (!match) return false;
    const argumentText = match[1];
    if (!argumentText) return false;
    const args = argumentText.trim().split(/\s+/);
    if (args.some((arg) => arg === "--help" || arg === "--version")) return false;
    return args.some((arg) => arg !== "--" && !arg.startsWith("-"));
  })) return true;
  if (depth >= 4) return false;
  return [
    ...activeCommandSubstitutions(command),
    ...activeBacktickSubstitutions(command),
    ...literalShellScripts(command),
  ].some((nested) => isSimpleFileRemoval(nested, depth + 1));
}

/** Include recognized hidden deletions when ordering review/test evidence. */
function isLikelyShellFileDeletion(command: string, depth = 0): boolean {
  if (shellCommandVariants(command).some((candidate) =>
    /^\s*(?:sudo\s+)?(?:rm|unlink|trash)(?=\s|$)(?!\s+--(?:help|version)\b)/i.test(candidate) ||
    GIT_RESET_INVOCATION.test(candidate) ||
    isDestructiveGitClean(candidate) ||
    hasFindDeletion(candidate)
  )) return true;
  if (depth >= 4) return false;
  return [
    ...activeCommandSubstitutions(command),
    ...activeBacktickSubstitutions(command),
    ...literalShellScripts(command),
  ].some((nested) => isLikelyShellFileDeletion(nested, depth + 1));
}

function hasFileMutation(part: MessagePart): boolean {
  const input = part.state?.input;
  if (!input) return false;

  const action = typeof input.action === "string" ? input.action.toLowerCase() : "";
  if (action === "delete" || action === "remove") return true;

  const command = commandFromPart(part);
  if (isLikelyShellFileDeletion(command)) return true;

  if (
    ["content", "new_string", "newString", "patch", "patchText"].some(
      (key) => typeof input[key] === "string" && (input[key] as string).length > 0
    )
  ) {
    return true;
  }

  return Boolean(extractLikelyShellMutation(input));
}

function recordFromPart(part: MessagePart, sequence: number): EvidenceRecord[] {
  if (part.type !== "tool" || !part.state) return [];

  const command = commandFromPart(part);
  const toolName = toolNameFromPart(part);
  const outputText = stringify(part.state.output ?? part.state.metadata?.output).trim();
  const outcome = statusFromPart(part, outputText);
  const baseSignature = `${toolName}:${stableStringify(part.state.input ?? {})}`;
  const records: EvidenceRecord[] = [];

  const kinds = classifyCommand(command, toolName);
  const verificationKinds = new Set<EvidenceKind>([
    "test",
    "build",
    "typecheck",
    "lint",
    "audit",
  ]);
  const verificationKindCount = kinds.filter((kind) =>
    verificationKinds.has(kind)
  ).length;
  const nonSequentialCompound =
    verificationKindCount > 1 && /;|\|\|/.test(command);
  const pipedWithoutPipefail =
    /(?:^|[^|])\|(?!\|)/.test(command) &&
    !/\bset\s+-[a-z]*o\s+pipefail\b/i.test(command);

  for (const kind of kinds) {
    const commandStatus =
      command &&
      outcome.status === "success" &&
      outcome.exitCode === undefined
        ? "unknown"
        : outcome.status;
    const isVerification = verificationKinds.has(kind);
    const maskedVerification =
      Boolean(command) &&
      isVerification &&
      isVerificationFailureMask(command);
    const ambiguousVerification =
      isVerification && (nonSequentialCompound || pipedWithoutPipefail);
    const evidenceStatus =
      maskedVerification || ambiguousVerification
        ? "unknown"
        : commandStatus;

    const recordError =
      evidenceStatus === "unknown" && outcome.status === "success"
        ? isVerificationFailureMask(command)
          ? "verification exit status was masked"
          : nonSequentialCompound || pipedWithoutPipefail
            ? "compound/piped command cannot prove each verification succeeded"
            : "command completed without an explicit exit code"
        : outcome.errorText || undefined;
    const errorFingerprint = outcome.status === "failure"
      ? normalizeErrorFingerprint(outcome.errorText || outputText)
      : undefined;
    records.push({
      kind,
      status: evidenceStatus,
      sequence,
      toolName,
      ...(command ? { command } : {}),
      signature: `${baseSignature}:${kind}`,
      ...(outputText ? { output: outputText } : {}),
      ...(recordError !== undefined ? { error: recordError } : {}),
      ...(outcome.exitCode !== undefined ? { exitCode: outcome.exitCode } : {}),
      ...(errorFingerprint !== undefined ? { errorFingerprint } : {}),
      ambiguousOutcome:
        outcome.status === "failure" &&
        verificationKinds.has(kind) &&
        verificationKindCount > 1,
    });
  }

  if (hasFileMutation(part)) {
    const filePath = extractMutatedFilePath(part);
    const mutationErrorFingerprint = outcome.status === "failure"
      ? normalizeErrorFingerprint(outcome.errorText || outputText)
      : undefined;
    records.push({
      kind: "file-mutation",
      status:
        outcome.status === "failure"
          ? "failure"
          : outcome.status === "success"
            ? "success"
            : "unknown",
      sequence,
      toolName,
      ...(command ? { command } : {}),
      signature: `${baseSignature}:mutation`,
      ...(filePath !== undefined ? { filePath } : {}),
      ...(outputText ? { output: outputText } : {}),
      ...(outcome.errorText ? { error: outcome.errorText } : {}),
      ...(outcome.exitCode !== undefined ? { exitCode: outcome.exitCode } : {}),
      ...(mutationErrorFingerprint !== undefined ? { errorFingerprint: mutationErrorFingerprint } : {}),
    });
  }

  return records;
}

const VERIFICATION_KINDS = new Set<EvidenceKind>([
  "test",
  "build",
  "typecheck",
  "lint",
  "audit",
  "git-push",
  "git-status",
  "baseline",
]);

export function extractMutatedFilePath(part: MessagePart): string | undefined {
  const input = part.state?.input;
  if (!input) return undefined;
  const direct =
    (input.path as string) ??
    (input.targetFile as string) ??
    (input.filePath as string) ??
    (input.file as string);
  if (direct && typeof direct === "string" && direct.trim()) return direct.trim();
  const patchRaw = (input.patchText as string) ?? (input.patch as string);
  if (typeof patchRaw === "string") {
    const match = patchRaw.match(/\+\+\+\s+(?:b\/)?([^\s\t\n]+)/);
    const filePath = match?.[1];
    if (filePath && filePath !== "/dev/null") return filePath.trim();
  }
  return undefined;
}

export function calculateProductFingerprint(
  directory?: string,
  files?: Iterable<string>
): string {
  const hash = createHash("sha256");
  const fileList = files ? [...files].filter(Boolean).sort() : [];
  if (!directory || fileList.length === 0) return "empty-state";
  if (fileList.length > 128) return "unverified-state";
  const root = path.resolve(directory);
  let realRoot: string;
  try { realRoot = fs.realpathSync(root); } catch { return "unverified-state"; }
  for (const rel of fileList) {
    const full = path.resolve(root, rel);
    const scoped = path.relative(root, full);
    if (scoped === ".." || scoped.startsWith(".." + path.sep) || path.isAbsolute(scoped)) {
      return "unverified-state";
    }
    try {
      const realFile = fs.realpathSync(full);
      const realRelative = path.relative(realRoot, realFile);
      if (realRelative === ".." || realRelative.startsWith(".." + path.sep) ||
          path.isAbsolute(realRelative)) return "unverified-state";
      const stat = fs.lstatSync(full);
      if (!stat.isFile() || stat.size > 2 * 1024 * 1024) return "unverified-state";
      hash.update(rel);
      hash.update("\0");
      hash.update(createHash("sha256").update(fs.readFileSync(full)).digest());
      hash.update("\0");
    } catch {
      return "unverified-state";
    }
  }
  return hash.digest("hex");
}

/** Captured by a real tool-after event, not reconstructed from message history. */
export interface VerificationSnapshot { fingerprint: string; files: string[]; }

/** Live tool-after observations; never invent a historical disk snapshot at idle. */
export class VerificationSnapshotStore {
  private readonly sessions = new Map<string, {
    paths: Set<string>; snapshots: Map<string, VerificationSnapshot>;
  }>();

  observe(sessionID: string, callID: string, tool: string,
    input: Record<string, unknown>, output: unknown, metadata: Record<string, unknown>,
    directory: string, status = "completed"): void {
    if (!sessionID || !callID) return;
    const part: MessagePart = { type: "tool", tool, callID,
      state: { status, input, output, metadata } };
    const evidence = collectTurnEvidence([
      { info: { id: callID, role: "assistant" }, parts: [part] },
    ]);
    let session = this.sessions.get(sessionID);
    if (!session) {
      session = { paths: new Set<string>(), snapshots: new Map() };
      this.sessions.set(sessionID, session);
    }
    for (const mutation of evidence.fileMutations) {
      if (mutation.status === "success") {
        if (mutation.filePath) session.paths.add(mutation.filePath);
      }
    }
    if (session.paths.size && evidence.successfulVerifications.some((record) =>
      ["test", "build", "typecheck", "lint", "audit", "git-status"].includes(record.kind))) {
      const fingerprint = calculateProductFingerprint(directory, session.paths);
      if (fingerprint !== "unverified-state" && fingerprint !== "empty-state") {
        session.snapshots.set(callID, { fingerprint: `sha256:${fingerprint}`,
          files: [...session.paths] });
      }
    }
    // Bound the call table even in very long sessions.
    if (session.snapshots.size > 512) {
      const oldest = session.snapshots.keys().next().value;
      if (oldest !== undefined) session.snapshots.delete(oldest);
    }
  }

  snapshots(sessionID: string): ReadonlyMap<string, VerificationSnapshot> {
    return this.sessions.get(sessionID)?.snapshots ?? new Map();
  }

  forget(sessionID: string): void { this.sessions.delete(sessionID); }
  clear(): void { this.sessions.clear(); }
}

export function collectTurnEvidence(
  currentTurn: SessionMessage[],
  _directory?: string,
  snapshots?: ReadonlyMap<string, VerificationSnapshot>
): TurnEvidence {
  const records: EvidenceRecord[] = [];
  const mutatedFiles = new Set<string>();
  let sequence = 0;
  let mutationCount = 0;
  let lastMutationSequence = -1;

  for (const message of currentTurn) {
    for (const part of message.parts) {
      const outputText = stringify(part.state?.output ?? part.state?.metadata?.output).trim();
      const outcome = statusFromPart(part, outputText);
      const isMutation = hasFileMutation(part);
      const isSuccessfulMutation = isMutation && outcome.status !== "failure";
      if (isSuccessfulMutation) {
        mutationCount++;
        lastMutationSequence = sequence;
        const filePath = extractMutatedFilePath(part);
        if (filePath) mutatedFiles.add(filePath);
      }
      const partRecords = recordFromPart(part, sequence++);
      for (const record of partRecords) {
        if (VERIFICATION_KINDS.has(record.kind)) {
          const callID = typeof part.callID === "string" ? part.callID : undefined;
          // Historical message replay cannot recreate the disk state at test
          // time. Only a live after-hook may supply an observed fingerprint.
          const snapshot = callID ? snapshots?.get(callID) : undefined;
          record.stateFingerprint = snapshot?.fingerprint ??
            `seq:${lastMutationSequence}:m${mutationCount}`;
          if (snapshot) record.snapshotFiles = [...snapshot.files];
        }
      }
      records.push(...partRecords);
    }
  }

  return {
    records,
    successfulVerifications: records.filter(
      (record) =>
        record.status === "success" && VERIFICATION_KINDS.has(record.kind)
    ),
    failures: records.filter((record) => record.status === "failure"),
    fileMutations: records.filter((record) => record.kind === "file-mutation"),
    mutatedFiles,
  };
}

export function latestEvidence(
  evidence: TurnEvidence | undefined,
  kind: EvidenceKind
): EvidenceRecord | undefined {
  if (!evidence) return undefined;
  return evidence.records
    .filter((record) => record.kind === kind)
    .sort((a, b) => b.sequence - a.sequence)[0];
}

export function hasSuccessfulEvidence(
  evidence: TurnEvidence | undefined,
  kind: EvidenceKind
): boolean {
  return Boolean(
    evidence?.records.some(
      (record) => record.kind === kind && record.status === "success"
    )
  );
}

export function hasSuccessfulVerification(
  evidence: TurnEvidence | undefined
): boolean {
  return Boolean(evidence?.successfulVerifications.length);
}
