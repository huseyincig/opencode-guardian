import fs from "node:fs";
import os from "node:os";
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
import { parseTestSummary, testOutcomeReason } from "./verification-report.js";
import { captureBeforeEdit, finishEditObservation, type BeforeEditState, type EditIntegrityEvidence } from "./edit-integrity.js";
import { extractLikelyShellMutation, extractStructuredEditTexts, extractToolAction, extractToolCommand, isKnownReadOnlyTool, KNOWN_SHELL_TOOLS, splitFilePatches } from "./tool-input.js";
import {
  activeBacktickSubstitutions,
  activeCommandSubstitutions,
  hasFindDeletion,
  literalShellScripts,
  literalWindowsShellScripts,
  shellCommandVariants,
  splitShellStages,
} from "./shell-risk.js";
export { isOpaqueShellExecution } from "./shell-risk.js";

function stringify(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined || value === null) return "";
  if (value instanceof Error) return value.message || String(value);
  if (typeof value === "object") {
    const obj = value as { message?: unknown };
    if (typeof obj.message === "string" && obj.message.length > 0) {
      return obj.message;
    }
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

function isCommandExecutionToolName(toolName: string): boolean {
  const last = extractToolAction(toolName);
  return (
    last === "" ||
    last === "tool" ||
    last === "execute" ||
    last === "process_start" ||
    KNOWN_SHELL_TOOLS.has(last)
  );
}

function commandFromPart(part: MessagePart): string {
  const input = part.state?.input;
  if (!input) return "";
  const toolName = toolNameFromPart(part);
  if (!isCommandExecutionToolName(toolName)) return "";
  return extractToolCommand(input).trim();
}

function toolNameFromPart(part: MessagePart): string {
  if (typeof part.tool === "string") return part.tool;
  if (typeof part.name === "string") return part.name;
  return "tool";
}

function parseExitCode(part: MessagePart): number | undefined {
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
  return undefined;
}

function isSelfInterruptingRestartCommand(command: string): boolean {
  if (!command) return false;
  return executableShellStages(command).some((stage) =>
    /^(?:opencode(?:\.exe)?\s+(?:service|server|daemon)\s+restart\b|systemctl\s+(?:--user\s+)?restart\s+opencode\b|launchctl\s+kickstart\b[^\n;&|]*opencode\b|brew\s+services\s+restart\s+opencode\b)/i.test(stage)
  );
}

function isAbortedOrInterruptedTool(
  part: MessagePart,
  outputText: string,
  errorText: string,
  exitCode?: number
): boolean {
  const state = part.state;
  if (!state) return false;

  if (
    state.metadata?.cancelled === true ||
    state.metadata?.canceled === true ||
    state.metadata?.aborted === true
  ) {
    return true;
  }

  const err = state.error;
  if (err && typeof err === "object" && !Array.isArray(err)) {
    const errType = (err as Record<string, unknown>).type;
    if (
      typeof errType === "string" &&
      ["aborted", "cancelled", "canceled"].includes(errType.toLowerCase())
    ) {
      return true;
    }
  }

  const combined = errorText || outputText;
  if (
    /^(?:error:\s*)?(?:(?:tool|command|operation|execution)\s+)?(?:cancelled by user|canceled by user|user cancel(?:led|ed))\b/i.test(combined) ||
    /^(?:error:\s*)?(?:tool execution interrupted|step interrupted)\b/i.test(combined)
  ) {
    return true;
  }

  // Self-interrupting service restarts (e.g. `opencode service restart`)
  // structurally terminate the server connection handling their own tool call.
  const command = commandFromPart(part);
  if (isSelfInterruptingRestartCommand(command)) {
    const structurallyInterrupted =
      exitCode === 130 ||
      exitCode === 137 ||
      exitCode === 143 ||
      /(?:aborted|interrupted|killed by signal|econnreset|socket hang up|connection closed|terminated)/i.test(combined);
    if (structurallyInterrupted) {
      return true;
    }
  }

  return false;
}

function statusFromPart(part: MessagePart, outputText: string): {
  status: EvidenceStatus;
  exitCode?: number;
  errorText: string;
  aborted?: boolean;
} {
  const state = part.state;
  if (!state) return { status: "unknown", errorText: "" };

  const errorText = stringify(state.error).trim();
  let exitCode = parseExitCode(part);

  // OpenCode v2.2.7+ shell results explicitly end with "Exit code: N" in the output
  // (optionally wrapped in </shell>). Do NOT use multiline `m` flag so stdout text
  // printing "Exit code: 0" mid-output can never shadow the real trailing exit code.
  if (exitCode === undefined && outputText) {
    const exitMatch = /(?:^|\n)Exit code:\s*(\d+)\s*(?:\n?<\/shell>\s*)?$/i.exec(outputText);
    if (exitMatch && exitMatch[1]) {
      const parsed = Number(exitMatch[1]);
      if (Number.isFinite(parsed)) exitCode = parsed;
    }
  }

  // Aborted / interrupted tool executions (e.g. OpenCode v2.4.x
  // `{ type: "aborted", message: "Tool execution interrupted" }` from server
  // restarts like `opencode service restart` or user cancellation) are neither
  // successful verification nor concrete unresolved command failures.
  if (isAbortedOrInterruptedTool(part, outputText, errorText, exitCode)) {
    return {
      status: "unknown",
      ...(exitCode !== undefined ? { exitCode } : {}),
      errorText: errorText || outputText,
      aborted: true,
    };
  }

  if (state.status === "error" || state.metadata?.error === true) {
    return {
      status: "failure",
      ...(exitCode !== undefined ? { exitCode } : {}),
      errorText: errorText || outputText,
    };
  }

  // OpenCode v2.3.1+ backgrounded shell commands and v2.4.0+ backgrounded
  // Code Mode (execute) scripts return status: "completed" with
  // metadata.status === "running", shellID, or jobID without an exit code.
  // Never treat a running background job as finished.
  const hasRunningJobID =
    typeof state.metadata?.jobID === "string" &&
    exitCode === undefined &&
    state.metadata?.status !== "completed" &&
    state.metadata?.state !== "completed";
  const isMovedToBackground =
    /(?:^|\n)(?:Command|Execution)\s+moved to the background\b/i.test(outputText) ||
    /(?:^|\n)The (?:command|execution) did not finish within its timeout\b[\s\S]*\bmoved to the background\b/i.test(outputText) ||
    /\bmoved to the background\s*\(job\b/i.test(outputText);
  if (
    state.status === "running" ||
    state.status === "pending" ||
    state.metadata?.status === "running" ||
    state.metadata?.state === "running" ||
    (typeof state.metadata?.shellID === "string" && exitCode === undefined) ||
    hasRunningJobID ||
    isMovedToBackground
  ) {
    return { status: "unknown", errorText: "" };
  }

  if (exitCode !== undefined) {
    return {
      status: exitCode === 0 ? "success" : "failure",
      exitCode,
      errorText: exitCode === 0 ? "" : errorText || outputText,
    };
  }

  // OpenCode v2.2.7+ commands killed by a signal or timed out
  if (/(?:^|\n)Command (?:killed by signal|timed out)\b/i.test(outputText)) {
    return { status: "failure", errorText: outputText };
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

function executableShellStages(command: string): string[] {
  return splitShellStages(command)
    .flat()
    .map((stage) => normalizeCommand(stage).toLowerCase())
    .map((stage) =>
      stage
        .replace(/^\s*sudo(?:\s+-\S+)*\s+/i, "")
        .replace(/^\s*env(?:\s+(?:-\S+|[a-z_][a-z0-9_]*=\S+))*\s+/i, "")
        .replace(/^(?:[a-z_][a-z0-9_]*=\S+\s+)*/i, "")
        .replace(/^(?:npx(?:\s+--no-install)?|pnpm\s+exec|npm\s+exec\s+--)\s+/i, "")
        .trim()
    )
    .filter(Boolean);
}

function classifyCommand(command: string, toolName: string): EvidenceKind[] {
  const stages = executableShellStages(command);
  const toolAction = extractToolAction(toolName);
  const kinds = new Set<EvidenceKind>();
  const anyStage = (pattern: RegExp): boolean =>
    stages.some((stage) => {
      pattern.lastIndex = 0;
      return pattern.test(stage);
    });
  const exploratoryVerification =
    /(?:^|\s)(?:--help|--version|--listtests|--list-tests|--collect-only|--list|--dry-run|--showconfig|--show-config)(?=\s|$)/i;
  const anyVerificationStage = (pattern: RegExp): boolean =>
    stages.some((stage) => {
      if (exploratoryVerification.test(stage)) return false;
      pattern.lastIndex = 0;
      return pattern.test(stage);
    });

  if (
    anyVerificationStage(/^(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test\b/) ||
    anyVerificationStage(/^(?:pytest|py\.test|python(?:3)?\s+-m\s+(?:pytest|unittest)|go\s+test|cargo\s+(?:test|nextest\s+run)|node\s+--test|jest|vitest|dotnet\s+test|phpunit|make\s+test)\b/) ||
    anyVerificationStage(/^(?:\.\/)?(?:mvn|mvnw)\b[^\n;&|]*(?:\btest\b|\bverify\b)/) ||
    anyVerificationStage(/^(?:\.\/)?(?:gradle|gradlew)\b[^\n;&|]*\btest\b/)
  ) {
    kinds.add("test");
  }

  if (
    anyVerificationStage(/^(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?build\b/) ||
    anyVerificationStage(/^(?:cargo\s+build|go\s+build|dotnet\s+build|make\s+build)\b/) ||
    anyVerificationStage(/^(?:\.\/)?(?:mvn|mvnw)\b[^\n;&|]*(?:\bpackage\b|\binstall\b)/) ||
    anyVerificationStage(/^(?:\.\/)?(?:gradle|gradlew)\b[^\n;&|]*\bbuild\b/)
  ) {
    kinds.add("build");
  }

  if (
    anyVerificationStage(/^(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?typecheck\b/) ||
    anyVerificationStage(/^(?:tsc\b[^\n;&|]*--noemit|mypy|pyright)\b/)
  ) {
    kinds.add("typecheck");
  }

  if (
    anyVerificationStage(/^(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?lint\b/) ||
    anyVerificationStage(/^(?:eslint|ruff|flake8|golangci-lint|cargo\s+clippy)\b/)
  ) {
    kinds.add("lint");
  }

  if (
    anyVerificationStage(/^(?:npm|pnpm|yarn)\s+audit\b/) ||
    anyVerificationStage(/^(?:pip-audit|cargo\s+audit|govulncheck|bundle\s+audit)\b/)
  ) {
    kinds.add("audit");
  }

  if (
    anyStage(/^git(?:\s+(?:-C|-c)\s+(?:"[^"]*"|'[^']*'|\S+))*\s+push\b/i) ||
    /^(?:git[_-]?)?(?:push|update[_-]?ref)$/.test(toolAction)
  ) {
    kinds.add("git-push");
  }

  if (anyStage(/^git(?:\s+(?:-C|-c)\s+(?:"[^"]*"|'[^']*'|\S+))*\s+status\b/i)) {
    kinds.add("git-status");
  }

  if (
    anyStage(/^git\s+(?:show|diff|blame|merge-base|rev-parse)\b[^\n;&|]*(?:main|master|origin\/|head\^|head~|[0-9a-f]{7,40})/i) ||
    anyStage(/^git\s+(?:checkout|switch)\s+(?:--detach\s+)?(?:main|master|origin\/[^\s]+)/i) ||
    anyStage(/^git\s+worktree\b/i)
  ) {
    kinds.add("baseline");
  }

  if (
    anyStage(/^(?:npm|pnpm|yarn|bun)\s+(?:install|add)\b/) ||
    anyStage(/^(?:pip(?:3)?\s+install|python(?:3)?\s+-m\s+pip\s+install|cargo\s+add|go\s+get)\b/)
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
    /^\s*(?:del|erase|rd|rmdir|remove-item|format)(?=\s|$)/i.test(command) ||
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
    ...literalWindowsShellScripts(command),
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

function splitTopLevelShellSegments(
  command: string
): Array<{ text: string; followedBy?: string }> {
  const segments: Array<{ text: string; followedBy?: string }> = [];
  let current = "";
  let quote: "'" | '"' | null = null;
  let escaped = false;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!;
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\" && quote !== "'") {
      current += ch;
      escaped = true;
      continue;
    }
    if (quote) {
      current += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') {
      current += ch;
      quote = ch;
      continue;
    }
    if (ch === ";" || ch === "\n") {
      segments.push({ text: current.trim(), followedBy: ch });
      current = "";
      continue;
    }
    if (ch === "|" && command[i + 1] === "|") {
      segments.push({ text: current.trim(), followedBy: "||" });
      current = "";
      i++;
      continue;
    }
    if (ch === "&" && command[i + 1] === "&") {
      segments.push({ text: current.trim(), followedBy: "&&" });
      current = "";
      i++;
      continue;
    }
    // Single background '&' (exclude redirections like 2>&1, >&2, <&0, &>, &>>).
    if (ch === "&") {
      const prev = command[i - 1];
      const next = command[i + 1];
      const isRedirection = prev === ">" || prev === "<" || next === ">";
      if (!isRedirection) {
        segments.push({ text: current.trim(), followedBy: "&" });
        current = "";
        continue;
      }
    }
    current += ch;
  }
  if (current.trim()) segments.push({ text: current.trim() });
  return segments;
}

function hasUnquotedSinglePipe(text: string): boolean {
  let quote: "'" | '"' | null = null;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (escaped) { escaped = false; continue; }
    if (ch === "\\" && quote !== "'") { escaped = true; continue; }
    if (quote) { if (ch === quote) quote = null; continue; }
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (ch === "|") {
      if (text[i + 1] === "|") { i++; continue; }
      return true;
    }
  }
  return false;
}

function hasTrailingSeparatorAfterVerification(
  command: string,
  toolName: string,
  verificationKinds: ReadonlySet<EvidenceKind>
): boolean {
  if (!command || !/[;\n&]|\|\|/.test(command)) return false;
  const segments = splitTopLevelShellSegments(command);
  let sawVerificationInAndChain = false;
  for (let idx = 0; idx < segments.length; idx++) {
    const seg = segments[idx]!;
    const sep = seg.followedBy;
    const isVerificationSeg =
      seg.text.length > 0 &&
      classifyCommand(seg.text, toolName).some((k) => verificationKinds.has(k));
    if (isVerificationSeg) {
      sawVerificationInAndChain = true;
    }
    if (sep === "&&") {
      continue;
    }
    if (sawVerificationInAndChain && (sep === ";" || sep === "||" || sep === "\n" || sep === "&")) {
      const hasTrailing =
        sep === "&" || segments.slice(idx + 1).some((nextSeg) => nextSeg.text.length > 0);
      if (hasTrailing) {
        return true;
      }
    }
    sawVerificationInAndChain = false;
  }
  return false;
}

function hasPipedVerificationWithoutPipefail(
  command: string,
  toolName: string,
  verificationKinds: ReadonlySet<EvidenceKind>
): boolean {
  if (!command || !hasUnquotedSinglePipe(command)) return false;
  const segments = splitTopLevelShellSegments(command);
  let pipefailScope: "none" | "unconditional" | "and-chain" = "none";
  let prevSep: string | undefined;
  for (const seg of segments) {
    const trimmed = seg.text.trim();
    if (!trimmed) {
      if (seg.followedBy && seg.followedBy !== "&&" && pipefailScope === "and-chain") {
        pipefailScope = "none";
      }
      prevSep = seg.followedBy;
      continue;
    }
    const isPiped = hasUnquotedSinglePipe(trimmed);
    if (!isPiped && /^set\b/i.test(trimmed)) {
      if (
        /(?:^|\s)-[a-z]*o\s+pipefail\b/i.test(trimmed) &&
        seg.followedBy !== "&" &&
        seg.followedBy !== "||"
      ) {
        if (prevSep === undefined || prevSep === ";" || prevSep === "\n") {
          pipefailScope = "unconditional";
        } else if (prevSep === "&&" && seg.followedBy === "&&") {
          pipefailScope = "and-chain";
        }
      }
      if (/(?:^|\s)\+[a-z]*o\s+pipefail\b/i.test(trimmed)) {
        pipefailScope = "none";
      }
    }
    if (isPiped) {
      const segKinds = classifyCommand(trimmed, toolName);
      if (segKinds.some((k) => verificationKinds.has(k)) && pipefailScope === "none") {
        return true;
      }
    }
    if (seg.followedBy && seg.followedBy !== "&&" && pipefailScope === "and-chain") {
      pipefailScope = "none";
    }
    prevSep = seg.followedBy;
  }
  return false;
}

function analyzeCommandWorkingDirectory(
  input: Record<string, unknown> | undefined,
  command: string,
  toolName: string,
  verificationKinds: ReadonlySet<EvidenceKind>,
  projectDirectory?: string
): { finalCwd?: string; hasForeignVerificationCwd: boolean } {
  const rawCwd =
    (typeof input?.cwd === "string" && input.cwd.trim() ? input.cwd.trim() : undefined) ??
    (typeof input?.workdir === "string" && input.workdir.trim() ? input.workdir.trim() : undefined) ??
    (typeof input?.workingDirectory === "string" && input.workingDirectory.trim() ? input.workingDirectory.trim() : undefined);
  const expandTilde = (p: string): string => {
    if (p === "~") return os.homedir();
    if (p.startsWith("~/") || p.startsWith("~\\")) {
      return path.join(os.homedir(), p.slice(2));
    }
    return p;
  };
  let resolved = rawCwd
    ? (projectDirectory ? path.resolve(projectDirectory, expandTilde(rawCwd)) : path.resolve(expandTilde(rawCwd)))
    : undefined;
  let hasForeignVerificationCwd = false;
  let sawVerificationSegment = false;
  const cwdStack: Array<string | undefined> = [];
  if (command) {
    const segments = splitTopLevelShellSegments(command);
    for (const seg of segments) {
      const rawTrimmed = seg.text.trim();
      if (!rawTrimmed) continue;
      // Handle leading subshell `(` and brace group `{` wrappers so `(cd /tmp && npm test)`
      // tracks `cd /tmp` inside the subshell and restores outer cwd when `)` closes.
      let inner = rawTrimmed;
      while (inner.startsWith("(") || inner.startsWith("{")) {
        if (inner.startsWith("(")) {
          cwdStack.push(resolved);
          inner = inner.slice(1).trimStart();
        } else {
          inner = inner.slice(1).trimStart();
        }
      }
      const netUnmatchedCloseParens = (text: string): number => {
        let quote: "'" | '"' | null = null;
        let escaped = false;
        let balance = 0;
        let unmatched = 0;
        for (let i = 0; i < text.length; i++) {
          const ch = text[i]!;
          if (escaped) { escaped = false; continue; }
          if (ch === "\\" && quote !== "'") { escaped = true; continue; }
          if (quote) { if (ch === quote) quote = null; continue; }
          if (ch === "'" || ch === '"') { quote = ch; continue; }
          if (ch === "(") balance++;
          else if (ch === ")") {
            if (balance > 0) balance--;
            else unmatched++;
          }
        }
        return unmatched;
      };
      let closeSubshells = netUnmatchedCloseParens(inner);
      let toStrip = closeSubshells;
      while (toStrip > 0 && inner.endsWith(")")) {
        inner = inner.slice(0, -1).trimEnd();
        toStrip--;
      }
      while (inner.endsWith("}")) {
        inner = inner.slice(0, -1).trimEnd();
      }
      if (inner) {
        if (/^cd(?:\s|$)/i.test(inner)) {
          if (/^cd\s*$/i.test(inner)) {
            resolved = os.homedir();
          } else {
            const cdMatch = /^cd(?:\s+(?:-[LP]+|--))*\s+(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))\s*$/i.exec(inner);
            const target = cdMatch ? (cdMatch[1] ?? cdMatch[2] ?? cdMatch[3]) : undefined;
            if (target && target !== "-") {
              const expanded = expandTilde(target);
              const base = resolved ?? projectDirectory;
              resolved = base ? path.resolve(base, expanded) : path.resolve(expanded);
            }
          }
        } else {
          const segKinds = classifyCommand(inner, toolName);
          if (segKinds.some((k) => verificationKinds.has(k))) {
            sawVerificationSegment = true;
            if (projectDirectory && resolved && !isPathInsideDirectory(resolved, projectDirectory)) {
              hasForeignVerificationCwd = true;
            }
          }
        }
      }
      while (closeSubshells > 0 && cwdStack.length > 0) {
        resolved = cwdStack.pop();
        closeSubshells--;
      }
    }
  }
  if (!sawVerificationSegment && projectDirectory && resolved && !isPathInsideDirectory(resolved, projectDirectory)) {
    hasForeignVerificationCwd = true;
  }
  return { ...(resolved ? { finalCwd: resolved } : {}), hasForeignVerificationCwd };
}

function isPathInsideDirectory(targetDir: string, rootDir: string): boolean {
  try {
    const realRoot = fs.existsSync(rootDir) ? fs.realpathSync(path.resolve(rootDir)) : path.resolve(rootDir);
    const realTarget = fs.existsSync(targetDir) ? fs.realpathSync(path.resolve(targetDir)) : path.resolve(targetDir);
    const rel = path.relative(realRoot, realTarget);
    return rel === "" || (!rel.startsWith(".." + path.sep) && rel !== ".." && !path.isAbsolute(rel));
  } catch {
    return false;
  }
}

function hasFileMutation(part: MessagePart): boolean {
  const input = part.state?.input;
  if (!input) return false;

  const toolName = toolNameFromPart(part);
  if (toolName && isKnownReadOnlyTool(toolName)) {
    return false;
  }

  const action = typeof input.action === "string" ? input.action.toLowerCase() : "";
  if (action === "delete" || action === "remove" || action === "move" || action === "copy") return true;

  const command = commandFromPart(part);
  if (isLikelyShellFileDeletion(command)) return true;
  if (extractStructuredEditTexts(input).length > 0) return true;

  if (
    [
      "content",
      "CodeContent",
      "text",
      "file_text",
      "new_string",
      "newString",
      "new_str",
      "ReplacementContent",
      "patch",
      "patchText",
    ].some(
      (key) => typeof input[key] === "string" &&
        (["content", "CodeContent", "text", "file_text", "new_string", "newString", "new_str", "ReplacementContent"].includes(key) || (input[key] as string).length > 0)
    )
  ) {
    return true;
  }

  return Boolean(extractLikelyShellMutation(input));
}

function recordFromPart(part: MessagePart, sequence: number, directory?: string): EvidenceRecord[] {
  if (part.type !== "tool" || !part.state) return [];

  const command = commandFromPart(part);
  const toolName = toolNameFromPart(part);
  const outputText = stringify(part.state.output ?? part.state.metadata?.output).trim();
  const outcome = statusFromPart(part, outputText);
  const baseSignature = `${toolName}:${stableStringify(part.state.input ?? {})}`;
  const records: EvidenceRecord[] = [];
  const verificationKinds = new Set<EvidenceKind>([
    "test",
    "build",
    "typecheck",
    "lint",
    "audit",
  ]);
  const cwdAnalysis = analyzeCommandWorkingDirectory(
    part.state.input,
    command,
    toolName,
    verificationKinds,
    directory
  );
  const executionCwd = cwdAnalysis.finalCwd;
  const foreignCwd = cwdAnalysis.hasForeignVerificationCwd;

  const kinds = classifyCommand(command, toolName);
  const verificationKindCount = kinds.filter((kind) =>
    verificationKinds.has(kind)
  ).length;
  const hasNonAndSeparator =
    Boolean(command) &&
    splitTopLevelShellSegments(command).some(
      (seg) =>
        seg.followedBy === ";" ||
        seg.followedBy === "\n" ||
        seg.followedBy === "&" ||
        seg.followedBy === "||"
    );
  const nonSequentialCompound =
    (verificationKindCount > 1 && hasNonAndSeparator) ||
    hasTrailingSeparatorAfterVerification(command, toolName, verificationKinds);
  const pipedWithoutPipefail =
    hasPipedVerificationWithoutPipefail(command, toolName, verificationKinds);

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
    const testSummary = kind === "test" ? parseTestSummary(outputText) : undefined;
    const testReason = kind === "test" ? testOutcomeReason(command, outcome.exitCode, testSummary) : undefined;
    const cancelled =
      outcome.aborted === true ||
      ((outcome.exitCode === 130 || part.state.status === "error") &&
        /^(?:error:\s*)?(?:(?:tool|command|operation|execution)\s+)?(?:cancelled by user|canceled by user|user cancel(?:led|ed))\b/i.test(outcome.errorText || outputText)) ||
      part.state.metadata?.cancelled === true ||
      part.state.metadata?.canceled === true;
    const evidenceStatus =
      maskedVerification || ambiguousVerification || (isVerification && foreignCwd)
        ? "unknown"
        : commandStatus === "success" && (testReason || cancelled)
          ? "unknown"
        : commandStatus;

    const recordError =
      evidenceStatus === "unknown" && outcome.status === "success"
        ? isVerification && foreignCwd
          ? "verification executed outside project directory"
          : isVerificationFailureMask(command)
            ? "verification exit status was masked"
            : nonSequentialCompound || pipedWithoutPipefail
              ? "compound/piped command cannot prove each verification succeeded"
              : "command completed without an explicit exit code"
        : outcome.errorText || undefined;
    const errorFingerprint = outcome.status === "failure"
      ? normalizeErrorFingerprint(outcome.errorText || outputText)
      : undefined;
    const genericTargetFile =
      kind === "generic" && part.state.input
        ? (typeof part.state.input.filePath === "string" && part.state.input.filePath.trim()
            ? part.state.input.filePath.trim()
            : typeof part.state.input.path === "string" && part.state.input.path.trim()
              ? part.state.input.path.trim()
              : typeof part.state.input.TargetFile === "string" && part.state.input.TargetFile.trim()
                ? part.state.input.TargetFile.trim()
                : typeof part.state.input.targetFile === "string" && part.state.input.targetFile.trim()
                  ? part.state.input.targetFile.trim()
                  : typeof part.state.input.file === "string" && part.state.input.file.trim()
                    ? part.state.input.file.trim()
                    : undefined)
        : undefined;
    records.push({
      kind,
      status: evidenceStatus,
      sequence,
      toolName,
      ...(genericTargetFile ? { filePath: genericTargetFile } : {}),
      ...(command ? { command } : {}),
      ...(executionCwd ? { cwd: executionCwd } : {}),
      signature: `${baseSignature}:${kind}`,
      outcomeReason: maskedVerification || ambiguousVerification ? "masked" :
        cancelled ? "cancelled" : testReason ?? (evidenceStatus === "success" ? "success" : evidenceStatus === "failure" ? "execution-failure" : "unknown"),
      ...(testSummary ? { testSummary } : {}),
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
    const paths = extractMutatedFilePaths(part);
    const mutationErrorFingerprint = outcome.status === "failure"
      ? normalizeErrorFingerprint(outcome.errorText || outputText)
      : undefined;
    const mutationStatus: EvidenceStatus =
      outcome.status === "failure"
        ? "failure"
        : command && outcome.status === "success" && outcome.exitCode === undefined
          ? "unknown"
          : outcome.status === "success"
            ? "success"
            : "unknown";
    for (const filePath of paths.length ? paths : [undefined]) records.push({
      kind: "file-mutation",
      status: mutationStatus,
      sequence,
      toolName,
      ...(command ? { command } : {}),
      signature: `${baseSignature}:mutation${paths.length > 1 ? ":" + filePath : ""}`,
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

export function extractMutatedFilePaths(part: MessagePart): string[] {
  const input = part.state?.input;
  if (!input) return [];
  const paths = new Set<string>();
  const add = (candidate: unknown) => {
    if (typeof candidate === "string" && candidate.trim()) {
      paths.add(candidate.trim());
    }
  };

  add(input.path);
  add(input.targetFile);
  add(input.TargetFile);
  add(input.filePath);
  add(input.file);
  add(input.source);
  add(input.from);
  add(input.destination);
  add(input.to);
  add(input.dest);
  add(input.target);

  const defaultPath = [input.path, input.targetFile, input.TargetFile, input.filePath, input.file]
    .find((value): value is string => typeof value === "string" && value.trim().length > 0);
  for (const edit of extractStructuredEditTexts(input, defaultPath)) add(edit.filePath);

  if (Array.isArray(input.paths)) {
    for (const item of input.paths) add(item);
  }
  if (Array.isArray(input.files)) {
    for (const item of input.files) add(item);
  }

  const patchRaw = (input.patchText as string) ?? (input.patch as string);
  if (typeof patchRaw === "string") {
    for (const section of splitFilePatches(patchRaw)) {
      add(section.previousPath);
      add(section.filePath);
    }
  }

  return [...paths];
}

export function extractMutatedFilePath(part: MessagePart): string | undefined {
  return extractMutatedFilePaths(part)[0];
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

    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(full);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        return "unverified-state";
      }

      // Missing is a real product state after delete/move. Prove that the
      // nearest existing parent still resolves inside the project root before
      // hashing absence; otherwise a symlinked parent could escape scope.
      let probe = path.dirname(full);
      while (!fs.existsSync(probe)) {
        const parent = path.dirname(probe);
        if (parent === probe) return "unverified-state";
        probe = parent;
      }
      try {
        const realProbe = fs.realpathSync(probe);
        const realRelative = path.relative(realRoot, realProbe);
        if (
          realRelative === ".." ||
          realRelative.startsWith(".." + path.sep) ||
          path.isAbsolute(realRelative)
        ) {
          return "unverified-state";
        }
      } catch {
        return "unverified-state";
      }

      hash.update(rel);
      hash.update("\0missing\0");
      continue;
    }

    if (!stat.isFile() || stat.size > 2 * 1024 * 1024) return "unverified-state";
    let fd: number | undefined;
    try {
      const realFile = fs.realpathSync(full);
      const realRelative = path.relative(realRoot, realFile);
      if (
        realRelative === ".." ||
        realRelative.startsWith(".." + path.sep) ||
        path.isAbsolute(realRelative)
      ) {
        return "unverified-state";
      }
      fd = fs.openSync(
        realFile,
        fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0)
      );
      const fdStat = fs.fstatSync(fd);
      if (!fdStat.isFile() || fdStat.size > 2 * 1024 * 1024) return "unverified-state";
      const buf = Buffer.alloc(fdStat.size + 1);
      const bytesRead = fdStat.size > 0 ? fs.readSync(fd, buf, 0, buf.length, 0) : 0;
      if (bytesRead !== fdStat.size) return "unverified-state";
      hash.update(rel);
      hash.update("\0");
      hash.update(createHash("sha256").update(buf.subarray(0, bytesRead)).digest());
      hash.update("\0");
    } catch {
      return "unverified-state";
    } finally {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch {}
      }
    }
  }
  return hash.digest("hex");
}

/** Captured by a real tool-after event, not reconstructed from message history. */
export interface VerificationSnapshot {
  fingerprint?: string | undefined;
  files: string[];
  editIntegrity?: EditIntegrityEvidence;
  incomplete?: boolean | undefined;
}

const evictedSnapshotMaps = new WeakSet<ReadonlyMap<string, VerificationSnapshot>>();

/**
 * Shared snapshot freshness check used by task-policy, remediation verification,
 * and unverified-claims so disk tampering after verification is detected uniformly.
 */
export function isVerificationSnapshotCurrent(
  record: EvidenceRecord | undefined,
  evidence: TurnEvidence | undefined,
  directory?: string
): boolean {
  if (!record) return false;
  if (record.stateFingerprint === "unverified-state") return false;
  if (record.stateFingerprint?.startsWith("sha256:")) {
    const files = record.snapshotFiles?.length ? record.snapshotFiles : evidence?.mutatedFiles;
    if (!directory || !files || (Array.isArray(files) ? !files.length : !files.size)) return false;
    const fp = calculateProductFingerprint(directory, files);
    if (fp === "unverified-state" || `sha256:${fp}` !== record.stateFingerprint) {
      return false;
    }
  }
  return true;
}

/** Live tool-after observations; never invent a historical disk snapshot at idle. */
export class VerificationSnapshotStore {
  private readonly sessions = new Map<string, {
    paths: Set<string>;
    snapshots: Map<string, VerificationSnapshot>;
    before: Map<string, BeforeEditState>;
    inFlightMutations: Set<string>;
    overflowed: boolean;
    hasPathlessMutation: boolean;
    snapshotsEvicted: boolean;
  }>();
  private static readonly MAX_SESSIONS = 512;
  private static readonly MAX_PATHS = 512;

  private getOrCreateSession(sessionID: string) {
    let session = this.sessions.get(sessionID);
    if (session) {
      this.sessions.delete(sessionID);
      this.sessions.set(sessionID, session);
    } else {
      session = {
        paths: new Set<string>(),
        snapshots: new Map<string, VerificationSnapshot>(),
        before: new Map<string, BeforeEditState>(),
        inFlightMutations: new Set<string>(),
        overflowed: false,
        hasPathlessMutation: false,
        snapshotsEvicted: false,
      };
      this.sessions.set(sessionID, session);
      while (this.sessions.size > VerificationSnapshotStore.MAX_SESSIONS) {
        const oldest = this.sessions.keys().next().value;
        if (oldest === undefined) break;
        this.sessions.delete(oldest);
      }
    }
    return session;
  }

  observeBefore(sessionID: string, callID: string, tool: string, input: Record<string, unknown>, directory: string): void {
    if (!sessionID || !callID) return;
    const session = this.getOrCreateSession(sessionID);
    if (hasFileMutation({ type: "tool", tool, callID, state: { status: "running", input } })) {
      session.inFlightMutations.delete(callID);
      session.inFlightMutations.add(callID);
      while (session.inFlightMutations.size > 64) {
        const oldest = session.inFlightMutations.values().next().value;
        if (oldest === undefined) break;
        session.inFlightMutations.delete(oldest);
      }
    }
    const before = captureBeforeEdit(tool, input, directory);
    if (!before) return;
    session.before.set(callID, before);
    if (session.before.size > 32) {
      const oldest = session.before.keys().next().value;
      if (oldest !== undefined) session.before.delete(oldest);
    }
  }

  observe(sessionID: string, callID: string, tool: string,
    input: Record<string, unknown>, output: unknown, metadata: Record<string, unknown>,
    directory: string, status = "completed"): void {
    if (!sessionID || !callID) return;
    const part: MessagePart = { type: "tool", tool, callID,
      state: { status, input, output, metadata } };
    const evidence = collectTurnEvidence([
      { info: { id: callID, role: "assistant" }, parts: [part] },
    ], directory);
    const session = this.getOrCreateSession(sessionID);
    session.inFlightMutations.delete(callID);
    const before = session.before.get(callID);
    session.before.delete(callID);
    if (before && status === "completed" && evidence.fileMutations.some(r => r.status === "success")) {
      const existing = session.snapshots.get(callID);
      session.snapshots.set(callID, {
        ...(existing?.fingerprint ? { fingerprint: existing.fingerprint } : {}),
        files: existing?.files.length ? existing.files : [before.filePath],
        editIntegrity: finishEditObservation(before),
      });
    }
    for (const mutation of evidence.fileMutations) {
      if (mutation.status !== "failure") {
        if (!mutation.filePath) {
          session.hasPathlessMutation = true;
          continue;
        }
        if (session.paths.has(mutation.filePath)) continue;
        if (session.paths.size < VerificationSnapshotStore.MAX_PATHS) {
          session.paths.add(mutation.filePath);
        } else {
          session.overflowed = true;
        }
      }
    }
    if ((session.paths.size || session.hasPathlessMutation || session.inFlightMutations.size > 0) &&
      evidence.successfulVerifications.some((record) =>
        ["test", "build", "typecheck", "lint", "audit", "git-status"].includes(record.kind))) {
      const existing = session.snapshots.get(callID);
      if (session.overflowed || session.hasPathlessMutation || session.inFlightMutations.size > 0) {
        session.snapshots.set(callID, {
          ...(existing?.editIntegrity ? { editIntegrity: existing.editIntegrity } : {}),
          fingerprint: "unverified-state",
          files: [...session.paths],
          incomplete: true,
        });
      } else {
        const fingerprint = calculateProductFingerprint(directory, session.paths);
        if (fingerprint === "unverified-state") {
          session.snapshots.set(callID, {
            ...(existing?.editIntegrity ? { editIntegrity: existing.editIntegrity } : {}),
            fingerprint: "unverified-state",
            files: [...session.paths],
            incomplete: true,
          });
        } else if (fingerprint !== "empty-state") {
          session.snapshots.set(callID, {
            ...(existing?.editIntegrity ? { editIntegrity: existing.editIntegrity } : {}),
            fingerprint: `sha256:${fingerprint}`,
            files: [...session.paths],
          });
        }
      }
    }
    // Bound the call table even in very long sessions; mark eviction so missing
    // snapshots degrade to unverified-state rather than silent seq fallback.
    if (session.snapshots.size > 512) {
      const oldest = session.snapshots.keys().next().value;
      if (oldest !== undefined) {
        session.snapshots.delete(oldest);
        session.snapshotsEvicted = true;
        evictedSnapshotMaps.add(session.snapshots);
      }
    }
  }

  beginTurn(sessionID: string): void {
    if (!sessionID) return;
    this.sessions.delete(sessionID);
    this.getOrCreateSession(sessionID);
  }

  snapshots(sessionID: string): ReadonlyMap<string, VerificationSnapshot> {
    return this.sessions.get(sessionID)?.snapshots ?? new Map();
  }

  forget(sessionID: string): void { this.sessions.delete(sessionID); }
  clear(): void { this.sessions.clear(); }
}

export function collectTurnEvidence(
  currentTurn: SessionMessage[],
  directory?: string,
  snapshots?: ReadonlyMap<string, VerificationSnapshot>
): TurnEvidence {
  const records: EvidenceRecord[] = [];
  const mutatedFiles = new Set<string>();
  let sequence = 0;
  let mutationCount = 0;
  let lastMutationSequence = -1;

  for (const message of currentTurn) {
    if (message.info.role !== "assistant") continue;
    for (const part of message.parts) {
      const outputText = stringify(part.state?.output ?? part.state?.metadata?.output).trim();
      const outcome = statusFromPart(part, outputText);
      const isMutation = hasFileMutation(part);
      const isSuccessfulMutation = isMutation && outcome.status !== "failure";
      if (isSuccessfulMutation) {
        mutationCount++;
        lastMutationSequence = sequence;
        for (const filePath of extractMutatedFilePaths(part)) {
          mutatedFiles.add(filePath);
        }
      }
      const partRecords = recordFromPart(part, sequence++, directory);
      for (const record of partRecords) {
        const callID = typeof part.callID === "string" ? part.callID : undefined;
        const observedEdit = callID ? snapshots?.get(callID)?.editIntegrity : undefined;
        if (record.kind === "file-mutation" && observedEdit && record.filePath === observedEdit.filePath) {
          record.editIntegrity = observedEdit;
        }
        if (VERIFICATION_KINDS.has(record.kind)) {
          // Historical message replay cannot recreate the disk state at test
          // time. Only a live after-hook may supply an observed fingerprint.
          const snapshot = callID ? snapshots?.get(callID) : undefined;
          const snapshotTrackedKind =
            record.status === "success" &&
            ["test", "build", "typecheck", "lint", "audit", "git-status"].includes(record.kind);
          const evictedMissing = Boolean(
            snapshotTrackedKind && !snapshot && snapshots && evictedSnapshotMaps.has(snapshots)
          );
          record.stateFingerprint = (snapshot?.fingerprint || undefined) ??
            (evictedMissing ? "unverified-state" : `seq:${lastMutationSequence}:m${mutationCount}`);
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
