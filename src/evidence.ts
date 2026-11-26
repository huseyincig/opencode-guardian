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
  stripShellWrappersAndPath,
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

function stripBenignCommandWrappers(stage: string): string {
  let current = stripShellWrappersAndPath(stage, { stripFlock: true });
  for (let i = 0; i < 4; i++) {
    const next = current
      .replace(/^(?:npx(?:\s+--no-install)?|pnpm\s+exec|npm\s+exec\s+--)\s+/i, "")
      .trim();
    const unwrapped = stripShellWrappersAndPath(next, { stripFlock: true });
    if (unwrapped === current) break;
    current = unwrapped;
  }
  return current;
}

function stripHeredocBodiesForStageParsing(command: string): string {
  if (!command.includes("<<")) return command;
  const segments = splitTopLevelShellSegments(command);
  return segments
    .map((seg) => {
      const nl = seg.text.indexOf("\n");
      const text =
        nl >= 0 && /<<-?\s*(?:'[^'\r\n]+'|"[^"\r\n]+"|\\[^\s;&|\r\n]+|[A-Za-z0-9_.-]+)/.test(seg.text.slice(0, nl))
          ? seg.text.slice(0, nl)
          : seg.text;
      return seg.followedBy ? `${text} ${seg.followedBy}` : text;
    })
    .join(" ");
}

function executableShellStages(command: string, depth = 0, preserveCase = false): string[] {
  const sanitized = stripHeredocBodiesForStageParsing(command);
  const rawStages = splitShellStages(sanitized).flat();
  const out: string[] = [];
  for (const raw of rawStages) {
    const normalized = normalizeCommand(raw);
    if (!normalized) continue;
    if (depth < 3) {
      const nestedScripts = [
        ...literalShellScripts(normalized),
        ...literalWindowsShellScripts(normalized),
      ];
      if (nestedScripts.length > 0) {
        for (const script of nestedScripts) {
          out.push(...executableShellStages(script, depth + 1, preserveCase));
        }
        continue;
      }
    }
    const stripped = stripBenignCommandWrappers(normalized);
    if (!stripped) continue;
    out.push(preserveCase ? stripped : stripped.toLowerCase());
  }
  return out.filter(Boolean);
}

const VERIFICATION_STAGE_PATTERNS: readonly RegExp[] = [
  /^(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?(?:test|build|typecheck|lint|audit)(?::[a-z0-9_-]+)?\b/,
  /^(?:pytest|py\.test|python(?:3)?\s+-m\s+(?:pytest|unittest)|go\s+(?:test|build)|cargo\s+(?:test|nextest\s+run|build|clippy|audit)|node(?:\s+(?:--?[a-z0-9-]+(?:=\S+)?|(?:--import|--require|-r|--loader|--conditions|--env-file)\s+\S+))*\s+--test|jest|vitest|ava|mocha|tap|dotnet\s+(?:test|build)|phpunit|make\s+(?:test|build))\b/,
  /^(?:\.\/)?(?:mvn|mvnw)\b[^\n;&|]*(?:\btest\b|\bverify\b|\bpackage\b|\binstall\b)/,
  /^(?:\.\/)?(?:gradle|gradlew)\b[^\n;&|]*(?:\btest\b|\bbuild\b)/,
  /^(?:tsc|mypy|pyright|eslint|oxlint|biome\s+(?:lint|check)|prettier\s+--check|stylelint|shellcheck|ruff|flake8|golangci-lint|pip-audit|govulncheck|bundle\s+audit)\b/,
];

/**
 * Recognize shell exit-code reporting echoes (`echo TC=$?`, `echo EXIT $?`, `echo EXIT ${PIPESTATUS[0]}`).
 * NEVER matches hardcoded literals like `echo TC=0` or fake test summaries.
 */
function parseExitStatusEchoStage(
  stage: string
): { label: string; usesPipestatus: boolean } | undefined {
  const trimmed = stage.trim();
  const m =
    /^echo\s+(?:(?:"([A-Za-z_][A-Za-z0-9_ -]{0,30}?)\s*(?:=|:|\s)\s*(\$\?|\$\{PIPESTATUS\[0\]\})")|([A-Za-z_][A-Za-z0-9_-]{0,24})=(\$\?|\$\{PIPESTATUS\[0\]\})|([A-Za-z_][A-Za-z0-9_-]{0,24})\s+(\$\?|\$\{PIPESTATUS\[0\]\}))$/.exec(
      trimmed
    );
  if (!m) return undefined;
  const label = (m[1] ?? m[3] ?? m[5] ?? "").trim();
  const varExpr = m[2] ?? m[4] ?? m[6] ?? "";
  if (!label || !varExpr) return undefined;
  return { label, usesPipestatus: varExpr.includes("PIPESTATUS") };
}

/**
 * Recognize harmless static section dividers like `echo TEST_DONE`, `echo done`, `echo "---"`.
 * Strictly forbids digits and pass/fail/warn/error/summary tokens so it can never spoof counts or summaries.
 */
function isBenignMarkerEchoStage(stage: string): boolean {
  const trimmed = stage.trim();
  const m = /^echo\s+(?:"([A-Za-z_=:-]{1,32})"|'([A-Za-z_=:-]{1,32})'|([A-Za-z_=:-]{1,32}))$/.exec(trimmed);
  if (!m) return false;
  const token = (m[1] ?? m[2] ?? m[3] ?? "").toLowerCase();
  if (!token) return false;
  if (/\d/.test(token)) return false;
  if (/(?:pass|fail|warn|error|ok|clean|suite|skip|todo|cancel|total|found)/i.test(token)) return false;
  return true;
}

function isBenignSummaryPassthroughStage(stage: string): boolean {
  const lowerStage = stage.toLowerCase();
  if (VERIFICATION_STAGE_PATTERNS.some((pattern) => pattern.test(lowerStage))) {
    return true;
  }
  if (/^(?:set|cd|export|unset)(?:\s|$)/i.test(lowerStage)) {
    return true;
  }
  if (parseExitStatusEchoStage(stage) || isBenignMarkerEchoStage(stage)) {
    return true;
  }
  // Silent heredoc/stdin file writes (`cat > file <<'EOF' ... EOF` / `cat >> file <<'EOF' ... EOF`)
  // redirect stdout to a file and emit 0 bytes to stdout, so they cannot spoof verification summaries.
  if (
    /^cat\s+(?:>>?|1>>?)\s*(?:"[^"]+"|'[^']+'|\S+)\s+<<-?\s*['"\\]?[A-Za-z0-9_.-]+['"]?(?:\s|\n|$)/i.test(stage) ||
    /^cat\s+<<-?\s*['"\\]?[A-Za-z0-9_.-]+['"]?\s+(?:>>?|1>>?)\s*(?:"[^"]+"|'[^']+'|\S+)(?:\s|\n|$)/i.test(stage)
  ) {
    return true;
  }
  // Allow stdin-only tail/head with non-zero counts (never `-n 0` / `-0` which discards all output).
  if (
    !/</.test(lowerStage) &&
    /^(?:tail|head)(?:\s+(?:-(?:n|c)\s+[+-]?\d+|-[a-z]*\d+|-[a-z]+|--(?:lines|bytes|quiet|silent|verbose)(?:=[+-]?\d+)?))*\s*$/i.test(lowerStage) &&
    !/(?:^|\s)(?:-(?:n|c)\s*[+-]?0\b|-[a-z]*0\b|--(?:lines|bytes)=[+-]?0\b)/i.test(lowerStage)
  ) {
    return true;
  }
  // Allow stdin-only tee (copies stdin through to stdout while logging to file; never `<` redirect).
  if (!/</.test(lowerStage) && /^tee(?:\s+-[ai]+)*\s+[^<>\s]+(?:\s+[^<>\s]+)*$/i.test(lowerStage)) {
    return true;
  }
  // Allow non-inverted, non-recursive grep/rg filtering stdin only (case-preserved so
  // `-A/-B/-C/-E` are distinguished from `-e/-f/-r/-R`).
  if (!/</.test(stage) && /^(?:grep|egrep|fgrep|rg)\b/i.test(stage)) {
    const rest = stage.replace(/^(?:grep|egrep|fgrep|rg)\s*/i, "");
    const tokens = rest.match(/"[^"]*"|'[^']*'|\S+/g) ?? [];
    let positional = 0;
    let hasExplicitPattern = false;
    let skipNext = false;
    let endOfOpts = false;
    for (const tok of tokens) {
      if (skipNext) {
        skipNext = false;
        continue;
      }
      if (endOfOpts) {
        positional++;
        continue;
      }
      if (tok === "--") {
        endOfOpts = true;
        continue;
      }
      if (tok === "-e" || tok === "--regexp") {
        hasExplicitPattern = true;
        skipNext = true;
        continue;
      }
      if (tok.startsWith("--regexp=")) {
        hasExplicitPattern = true;
        continue;
      }
      if (tok.startsWith("--directories=") && /^--directories=r/i.test(tok)) {
        return false;
      }
      if (tok === "-d" || tok === "--directories") {
        // `-d recurse` reads directories from disk instead of stdin.
        return false;
      }
      // Handle short flag cluster containing lowercase `-e` BEFORE `-v`/`-f`/`-r`/`-R` so
      // attached patterns like `-eerror` or `-efail` are not misclassified as `-r`/`-f`.
      if (/^-[a-zA-Z]*e/.test(tok) && !tok.startsWith("--")) {
        const ePos = tok.indexOf("e");
        const beforeE = tok.slice(1, ePos);
        if (/[vfrR]/.test(beforeE)) return false;
        hasExplicitPattern = true;
        if (ePos === tok.length - 1) skipNext = true;
        continue;
      }
      if (tok === "-v" || tok === "--invert-match" || /^-[a-zA-Z]*v[a-zA-Z]*$/.test(tok)) {
        return false;
      }
      if (tok === "-f" || tok === "--file" || tok.startsWith("--file=") || /^-[a-zA-Z]*f/.test(tok)) {
        return false;
      }
      if (
        tok === "-r" ||
        tok === "-R" ||
        tok === "--recursive" ||
        tok === "--dereference-recursive" ||
        /^-[a-zA-Z]*[rR]/.test(tok)
      ) {
        return false;
      }
      if (
        /^-[a-zA-Z]*[mABCgtT]$/.test(tok) ||
        /^--(?:max-count|after-context|before-context|context|glob|type)$/.test(tok)
      ) {
        skipNext = true;
        continue;
      }
      if (tok.startsWith("-")) continue;
      positional++;
    }
    return hasExplicitPattern ? positional === 0 : positional <= 1;
  }
  return false;
}

function hasOutputSpoofingStage(command: string, outputText = ""): boolean {
  if (!command) return false;
  // Identify top-level `;`-separated `grep ...; echo <LABEL>=$?` pairs where output proves `<LABEL>=1`
  // (grep matched 0 lines -> 0 bytes of stdout -> cannot spoof any summary).
  const zeroOutputGrepStages = new Set<string>();
  if (outputText) {
    const segs = splitTopLevelShellSegments(command);
    for (let i = 0; i + 1 < segs.length; i++) {
      const seg = segs[i]!;
      const next = segs[i + 1]!;
      if (seg.followedBy !== ";" && seg.followedBy !== "\n") continue;
      if (hasUnquotedSinglePipe(seg.text)) continue;
      const stripped = stripBenignCommandWrappers(normalizeCommand(seg.text));
      if (!/^(?:grep|egrep|fgrep|rg)\b/i.test(stripped)) continue;
      const exitEcho = parseExitStatusEchoStage(next.text.trim());
      if (!exitEcho) continue;
      const lbl = escapeEvidenceRegExp(exitEcho.label);
      if (new RegExp(`^${lbl}[=:\\s]+1$`, "m").test(outputText) && !new RegExp(`^${lbl}[=:\\s]+0$`, "m").test(outputText)) {
        zeroOutputGrepStages.add(stripped);
      }
    }
  }
  const stages = executableShellStages(command, 0, true);
  if (stages.length === 0) return true;
  return stages.some((stage) => !zeroOutputGrepStages.has(stage) && !isBenignSummaryPassthroughStage(stage));
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
    /(?:^|\s)(?:--help|--version|--init|--listtests|--list-tests|--collect-only|--list|--dry-run|--showconfig|--show-config)(?=\s|$)/i;
  const anyVerificationStage = (pattern: RegExp): boolean =>
    stages.some((stage) => {
      if (exploratoryVerification.test(stage)) return false;
      pattern.lastIndex = 0;
      return pattern.test(stage);
    });

  if (
    anyVerificationStage(/^(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test(?::[a-z0-9_-]+)?\b/) ||
    anyVerificationStage(/^(?:pytest|py\.test|python(?:3)?\s+-m\s+(?:pytest|unittest)|go\s+test|cargo\s+(?:test|nextest\s+run)|node(?:\s+(?:--?[a-z0-9-]+(?:=\S+)?|(?:--import|--require|-r|--loader|--conditions|--env-file)\s+\S+))*\s+--test|jest|vitest|ava|mocha|tap|dotnet\s+test|phpunit|make\s+test)\b/) ||
    anyVerificationStage(/^(?:\.\/)?(?:mvn|mvnw)\b[^\n;&|]*(?:\btest\b|\bverify\b)/) ||
    anyVerificationStage(/^(?:\.\/)?(?:gradle|gradlew)\b[^\n;&|]*\btest\b/)
  ) {
    kinds.add("test");
  }

  if (
    anyVerificationStage(/^(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?build(?::[a-z0-9_-]+)?\b/) ||
    anyVerificationStage(/^(?:cargo\s+build|go\s+build|dotnet\s+build|make\s+build)\b/) ||
    anyVerificationStage(/^(?:\.\/)?(?:mvn|mvnw)\b[^\n;&|]*(?:\bpackage\b|\binstall\b)/) ||
    anyVerificationStage(/^(?:\.\/)?(?:gradle|gradlew)\b[^\n;&|]*\bbuild\b/)
  ) {
    kinds.add("build");
  }

  if (
    anyVerificationStage(/^(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?typecheck(?::[a-z0-9_-]+)?\b/) ||
    anyVerificationStage(/^(?:tsc|mypy|pyright)\b/)
  ) {
    kinds.add("typecheck");
  }

  if (
    anyVerificationStage(/^(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?lint(?::[a-z0-9_-]+)?\b/) ||
    anyVerificationStage(/^(?:eslint|oxlint|biome\s+(?:lint|check)|prettier\s+--check|stylelint|shellcheck|ruff|flake8|golangci-lint|cargo\s+clippy)\b/)
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
    anyStage(/^git\s+worktree\b/i) ||
    anyStage(/^git\s+stash(?:\s+(?:push|pop|apply|save)\b|\s*$)/i)
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

const VERIFICATION_KIND_SET = new Set<EvidenceKind>([
  "test",
  "build",
  "typecheck",
  "lint",
  "audit",
]);

function isFailureMaskTargetSegment(segment: string, sep: string | undefined): boolean {
  const stripped = stripShellWrappersAndPath(segment);
  if (sep === "||") {
    return /^(?:true|:(?=\s|$)|exit\s+0(?:\s|$)|pwd(?:\s|$)|echo(?:\s|$)|printf(?:\s|$))/i.test(stripped);
  }
  if (sep === ";" || sep === "\n") {
    return /^(?:true|:(?=\s|$)|exit\s+0(?:\s|$))/i.test(stripped);
  }
  return false;
}

export function isVerificationFailureMask(command: string, depth = 0): boolean {
  if (!command) return false;
  const segments = splitTopLevelShellSegments(command);
  let sawVerificationInChain = false;
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i]!;
    const trimmed = seg.text.trim();
    if (trimmed) {
      if (depth < 3) {
        const nested = [
          ...literalShellScripts(trimmed),
          ...literalWindowsShellScripts(trimmed),
        ];
        if (nested.some((script) => isVerificationFailureMask(script, depth + 1))) {
          return true;
        }
      }
      if (classifyCommand(trimmed, "bash").some((k) => VERIFICATION_KIND_SET.has(k))) {
        sawVerificationInChain = true;
      }
    }
    const sep = seg.followedBy;
    if (sawVerificationInChain && (sep === "||" || sep === ";" || sep === "\n")) {
      const nextSeg = segments[i + 1]?.text.trim() ?? "";
      if (nextSeg && isFailureMaskTargetSegment(nextSeg, sep)) {
        return true;
      }
      if (
        (sep === ";" || sep === "\n") &&
        segments.slice(i + 1).some((after) => isFailureMaskTargetSegment(after.text.trim(), ";"))
      ) {
        return true;
      }
    }
    if (sep !== "&&") {
      sawVerificationInChain = false;
    }
  }
  return false;
}

function isXargsRecursiveForceRemove(command: string): boolean {
  const match = /^xargs(?:\s+(?:-[a-zA-Z]+(?:\s+\S+)?|--[a-z-]+(?:=\S+)?))*\s+(?:\/(?:[A-Za-z0-9._-]+\/)+)?rm\s+([^\n;&|]+)/i.exec(
    command.trim()
  );
  if (!match?.[1]) return false;
  const flags = match[1].match(/(?:^|\s)-[a-z]+\b|--(?:recursive|force)\b/gi) ?? [];
  const recursive = flags.some((flag) => /--recursive|^-[a-z]*r/i.test(flag.trim()));
  const forced = flags.some((flag) => /--force|^-[a-z]*f/i.test(flag.trim()));
  return recursive && forced;
}

function isRecursiveForceRemove(command: string): boolean {
  if (isXargsRecursiveForceRemove(command)) return true;
  const candidates = command.match(/^\s*(?:sudo\s+)?rm\s+[^\n;&|]+/gi) ?? [];
  return candidates.some((candidate) => {
    const flags = candidate.match(/(?:^|\s)-[a-z]+\b|--(?:recursive|force)\b/gi) ?? [];
    const recursive = flags.some((flag) => /--recursive|^-[a-z]*r/i.test(flag.trim()));
    const forced = flags.some((flag) => /--force|^-[a-z]*f/i.test(flag.trim()));
    return recursive && forced;
  });
}

// Git global options (-C/-c/--git-dir/--work-tree/--no-pager/-P/etc.) are legal before every subcommand.
const GIT_GLOBAL_OPTS =
  `(?:\\s+(?:(?:-C|-c|--git-dir|--work-tree|--namespace|--super-prefix)(?:=|\\s+)(?:"[^"]*"|'[^']*'|[^\\s;&|\\n]+)|-C[^\\s;&|\\n]+|-c[^\\s;&|\\n]+|--no-pager|--paginate|-p|-P|--bare|--no-replace-objects|--literal-pathspecs))*`;
const GIT_RESET_INVOCATION = new RegExp(
  `^\\s*(?:sudo\\s+)?git${GIT_GLOBAL_OPTS}\\s+reset\\b[^\\n;&|]*--hard\\b`,
  "i"
);
const GIT_FORCE_PUSH_INVOCATION = new RegExp(
  `^\\s*(?:sudo\\s+)?git${GIT_GLOBAL_OPTS}\\s+push\\b[^\\n;&|]*(?:--force(?:-with-lease)?(?:=[^\\s;&|]+)?|\\s-f(?:\\s|$))`,
  "i"
);
const GIT_CLEAN_INVOCATION = new RegExp(
  `\\bgit${GIT_GLOBAL_OPTS}\\s+clean\\b`,
  "i"
);

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
    if (/^xargs(?:\s+(?:-[a-zA-Z]+(?:\s+\S+)?|--[a-z-]+(?:=\S+)?))*\s+(?:\/(?:[A-Za-z0-9._-]+\/)+)?rm(?:\s|$)/i.test(candidate.trim())) {
      return true;
    }
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
  let quote: "'" | "$'" | '"' | null = null;
  let escaped = false;
  const pendingHeredocs: Array<{ delimiter: string; stripTabs: boolean }> = [];
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
      if ((quote === "$'" && ch === "'") || ch === quote) quote = null;
      continue;
    }
    if (ch === "$" && command[i + 1] === "'") {
      current += "$'";
      quote = "$'";
      i++;
      continue;
    }
    if (ch === "'" || ch === '"') {
      current += ch;
      quote = ch;
      continue;
    }
    // Track unquoted heredocs (`<<EOF`, `<<'EOF'`, `<<"EOF"`, `<<\EOF`, `<<-EOF`; never `<<<` here-string)
    // so newline/semicolon content inside the heredoc body is never split as top-level shell commands.
    if (ch === "<" && command[i + 1] === "<" && command[i + 2] !== "<") {
      const rest = command.slice(i + 2);
      const hd = /^(-?)\s*(?:'([^'\r\n]+)'|"([^"\r\n]+)"|\\([^\s;&|\r\n]+)|([A-Za-z0-9_.-]+))/.exec(rest);
      if (hd) {
        const delim = hd[2] ?? hd[3] ?? hd[4] ?? hd[5] ?? "";
        if (delim) {
          pendingHeredocs.push({ delimiter: delim, stripTabs: hd[1] === "-" });
          current += "<<" + hd[0];
          i += 1 + hd[0].length;
          continue;
        }
      }
    }
    if (ch === "\n" && pendingHeredocs.length > 0) {
      current += "\n";
      let cursor = i + 1;
      while (pendingHeredocs.length > 0 && cursor < command.length) {
        const active = pendingHeredocs[0]!;
        const nextNl = command.indexOf("\n", cursor);
        const lineEnd = nextNl === -1 ? command.length : nextNl;
        const line = command.slice(cursor, lineEnd).replace(/\r$/, "");
        current += command.slice(cursor, nextNl === -1 ? command.length : nextNl + 1);
        cursor = nextNl === -1 ? command.length : nextNl + 1;
        const candidate = active.stripTabs ? line.replace(/^\t+/, "") : line;
        if (candidate === active.delimiter) {
          pendingHeredocs.shift();
        }
      }
      segments.push({ text: current.trim(), followedBy: "\n" });
      current = "";
      i = cursor - 1;
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
    // Single background '&' (exclude redirections like 2>&1, >&2, <&0, &>, &>>, and |& pipe).
    if (ch === "&") {
      const prev = command[i - 1];
      const next = command[i + 1];
      const isRedirection = prev === ">" || prev === "<" || prev === "|" || next === ">";
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
  let quote: "'" | "$'" | '"' | null = null;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (escaped) { escaped = false; continue; }
    if (ch === "\\" && quote !== "'") { escaped = true; continue; }
    if (quote) {
      if ((quote === "$'" && ch === "'") || ch === quote) quote = null;
      continue;
    }
    if (ch === "$" && text[i + 1] === "'") { quote = "$'"; i++; continue; }
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (ch === "|") {
      if (text[i + 1] === "|") { i++; continue; }
      return true;
    }
  }
  return false;
}

function hasNonAndSeparatorRecursive(command: string, depth = 0): boolean {
  if (!command) return false;
  const segments = splitTopLevelShellSegments(command);
  if (
    segments.some(
      (seg) =>
        seg.followedBy === ";" ||
        seg.followedBy === "\n" ||
        seg.followedBy === "&" ||
        seg.followedBy === "||"
    )
  ) {
    return true;
  }
  if (depth >= 3) return false;
  return segments.some((seg) =>
    [...literalShellScripts(seg.text), ...literalWindowsShellScripts(seg.text)].some((script) =>
      hasNonAndSeparatorRecursive(script, depth + 1)
    )
  );
}

function hasTrailingSeparatorAfterVerification(
  command: string,
  toolName: string,
  verificationKinds: ReadonlySet<EvidenceKind>,
  depth = 0
): boolean {
  if (!command) return false;
  const segments = splitTopLevelShellSegments(command);
  let sawVerificationInAndChain = false;
  for (let idx = 0; idx < segments.length; idx++) {
    const seg = segments[idx]!;
    const sep = seg.followedBy;
    if (depth < 3 && seg.text.length > 0) {
      const nested = [
        ...literalShellScripts(seg.text),
        ...literalWindowsShellScripts(seg.text),
      ];
      if (
        nested.some((script) =>
          hasTrailingSeparatorAfterVerification(script, toolName, verificationKinds, depth + 1)
        )
      ) {
        return true;
      }
    }
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

function countLeadingOpenSubshells(text: string): number {
  let count = 0;
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (/\s/.test(ch) || ch === "{") { i++; continue; }
    if (ch === "(") { count++; i++; continue; }
    break;
  }
  return count;
}

function countUnmatchedClosingSubshells(text: string): number {
  let q: "'" | '"' | "$'" | null = null;
  let escaped = false;
  let balance = 0;
  let unmatchedClose = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (escaped) { escaped = false; continue; }
    if (ch === "\\" && q !== "'") { escaped = true; continue; }
    if (q) {
      if ((q === "$'" && ch === "'") || ch === q) q = null;
      continue;
    }
    if (ch === "$" && text[i + 1] === "'") { q = "$'"; i++; continue; }
    if (ch === "'" || ch === '"') { q = ch; continue; }
    if (ch === "(") balance++;
    else if (ch === ")") {
      if (balance > 0) balance--;
      else unmatchedClose++;
    }
  }
  return unmatchedClose;
}

function hasPipedVerificationWithoutPipefail(
  command: string,
  toolName: string,
  verificationKinds: ReadonlySet<EvidenceKind>,
  depth = 0
): boolean {
  if (!command) return false;
  const segments = splitTopLevelShellSegments(command);
  const pipefailScopes: Array<{ depth: number; mode: "unconditional" | "and-chain" }> = [];
  let subshellDepth = 0;
  let prevSep: string | undefined;
  let conditionalDepth = 0;
  for (const seg of segments) {
    const trimmed = seg.text.trim();
    if (!trimmed) {
      if (seg.followedBy && seg.followedBy !== "&&") {
        while (pipefailScopes.length > 0 && pipefailScopes[pipefailScopes.length - 1]!.mode === "and-chain") {
          pipefailScopes.pop();
        }
      }
      prevSep = seg.followedBy;
      continue;
    }
    const openedNow = countLeadingOpenSubshells(trimmed);
    subshellDepth += openedNow;
    const withoutLeadingGroup = trimmed.replace(/^[({\s]+/, "");
    if (/^(?:if|while|until|for|case)\b/.test(withoutLeadingGroup)) {
      conditionalDepth++;
    }
    if (depth < 3) {
      const nested = [
        ...literalShellScripts(trimmed),
        ...literalWindowsShellScripts(trimmed),
      ];
      if (
        nested.some((script) =>
          hasPipedVerificationWithoutPipefail(script, toolName, verificationKinds, depth + 1)
        )
      ) {
        return true;
      }
    }
    const isPiped = hasUnquotedSinglePipe(trimmed);
    const setCandidate = withoutLeadingGroup.replace(/^then\s+|^else\s+|^do\s+/i, "");
    if (!isPiped && /^set\b/i.test(setCandidate)) {
      if (
        conditionalDepth === 0 &&
        /(?:^|\s)-[a-z]*o\s+pipefail\b/i.test(setCandidate) &&
        seg.followedBy !== "&" &&
        seg.followedBy !== "||"
      ) {
        if (prevSep === undefined || prevSep === ";" || prevSep === "\n") {
          pipefailScopes.push({ depth: subshellDepth, mode: "unconditional" });
        } else if (prevSep === "&&" && seg.followedBy === "&&") {
          pipefailScopes.push({ depth: subshellDepth, mode: "and-chain" });
        }
      }
      if (/(?:^|\s)\+[a-z]*o\s+pipefail\b/i.test(setCandidate)) {
        pipefailScopes.length = 0;
      }
    }
    if (isPiped) {
      const segKinds = classifyCommand(trimmed, toolName);
      if (segKinds.some((k) => verificationKinds.has(k)) && pipefailScopes.length === 0) {
        return true;
      }
    }
    const closedNow = countUnmatchedClosingSubshells(withoutLeadingGroup);
    if (closedNow > 0) {
      subshellDepth = Math.max(0, subshellDepth - closedNow);
      while (pipefailScopes.length > 0 && pipefailScopes[pipefailScopes.length - 1]!.depth > subshellDepth) {
        pipefailScopes.pop();
      }
    }
    if (/^(?:fi|done|esac)\b/.test(withoutLeadingGroup) || /\b(?:fi|done|esac)\s*$/.test(trimmed)) {
      if (conditionalDepth > 0) conditionalDepth--;
    }
    if (seg.followedBy && seg.followedBy !== "&&") {
      while (
        pipefailScopes.length > 0 &&
        pipefailScopes[pipefailScopes.length - 1]!.depth === subshellDepth &&
        pipefailScopes[pipefailScopes.length - 1]!.mode === "and-chain"
      ) {
        pipefailScopes.pop();
      }
    }
    prevSep = seg.followedBy;
  }
  return false;
}

function extractEnvChdirTarget(segment: string): string | undefined {
  // Strip outer wrappers BEFORE `env`, while also capturing `sudo -D / --chdir <dir>`.
  let cur = segment.trim().replace(/^[({\s]+/, "");
  let detectedChdir: string | undefined;
  const unquote = (v: string): string =>
    (v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))
      ? v.slice(1, -1)
      : v;
  for (let i = 0; i < 6; i++) {
    if (/^(?:\/(?:[A-Za-z0-9._-]+\/)+)?env(?:\s|$)/.test(cur)) break;
    const sudoHead = /^(?:\/(?:[A-Za-z0-9._-]+\/)+)?sudo\s+([\s\S]+)$/.exec(cur);
    if (sudoHead?.[1]) {
      const sudoTokens = sudoHead[1].match(/"(?:\\.|[^"\\])*"|'[^']*'|\S+/g) ?? [];
      for (let t = 0; t < sudoTokens.length; t++) {
        const tok = sudoTokens[t]!;
        if (tok === "--") break;
        if (tok === "-D" || tok === "--chdir" || /^-[ABEFGHIJKLMNOPQSTUVWXYZabdefijklmnoqsvwxyz]*D$/.test(tok)) {
          const val = sudoTokens[++t];
          if (val) detectedChdir = unquote(val);
          continue;
        }
        if (/^-[ABEFGHIJKLMNOPQSTUVWXYZabdefijklmnoqsvwxyz]*D(.+)$/.test(tok) && !tok.startsWith("--")) {
          const dPos = tok.indexOf("D");
          detectedChdir = unquote(tok.slice(dPos + 1));
          continue;
        }
        if (tok.startsWith("--chdir=")) {
          detectedChdir = unquote(tok.slice("--chdir=".length));
          continue;
        }
        if (/^(?:-[ABEFGHIJKLMNOPQSTUVWXYZabdefijklmnoqsvwxyz]*[ugCprthUcRT]|--user|--group|--host|--prompt|--role|--type|--other-user|--close-from|--login-class|--selinux-role|--selinux-type)$/.test(tok)) {
          t++;
          continue;
        }
        if (tok.startsWith("-")) continue;
        break;
      }
    }
    const next = cur
      .replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S+)\s+)+/, "")
      .replace(/^(?:\/(?:[A-Za-z0-9._-]+\/)+)?[sS][uU][dD][oO](?:\s+(?:(?:-[ABEFGHIJKLMNOPQSTUVWXYZabdefijklmnoqsvwxyz]*[ugCprthDUcRT]|--user|--group|--chdir|--host|--prompt|--role|--type|--other-user|--close-from|--login-class|--selinux-role|--selinux-type)\s+\S+|-[ABEFGHIJKLMNOPQSTUVWXYZabdefijklmnoqsvwxyz]*[ugCprthDUcRT]\S+|-[ABEFGHIJKLMNOPQSTUVWXYZabdefijklmnoqsvwxyz]+|--[a-z-]+(?:=\S+)?))*(?:\s+--)?\s+/, "")
      .replace(/^(?:\/(?:[A-Za-z0-9._-]+\/)+)?timeout(?:\s+(?:(?:-[ks]|--kill-after|--signal)\s+\S+|-[ks]\S+|--?[a-z-]+(?:=\S+)?))*\s+\d+(?:\.\d+)?[smhd]?\s+/i, "")
      .replace(/^(?:\/(?:[A-Za-z0-9._-]+\/)+)?[fF][lL][oO][cC][kK](?:\s+(?:(?:-w|--timeout|-E|--conflict-exit-code)\s+\S+|--(?:timeout|conflict-exit-code)=\S+|-[sxnoueF]+|--(?:shared|exclusive|nonblock|nb|unlock|no-fork|close|verbose)))*\s+(?:"[^"]*"|'[^']*'|\S+)(?:\s+--)?\s+(?!-c\b)/, "")
      .replace(/^(?:\/(?:[A-Za-z0-9._-]+\/)+)?(?:nice(?:\s+(?:-n\s*-?\d+|-\d+))?|nohup|time(?:\s+-\S+)*|setsid(?:\s+--?[a-z-]+)*|stdbuf(?:\s+(?:-[ioe]\s+\S+|-[ioe]\S+))*|ionice(?:\s+(?:-[cn]\s*\S+|-t))*)\s+/i, "")
      .trim();
    if (next === cur) break;
    cur = next;
  }
  const match = /^(?:\/(?:[A-Za-z0-9._-]+\/)+)?env\s+([\s\S]+)$/.exec(cur);
  if (!match?.[1]) return detectedChdir;
  // Parse ONLY `env`'s own options (case-sensitive `-C` / `--chdir`, including combined `-iC`) before the downstream command.
  const tokens = match[1].match(/"(?:\\.|[^"\\])*"|'[^']*'|\S+/g) ?? [];
  let chdir: string | undefined = detectedChdir;
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i]!;
    if (tok === "--" || tok === "-") break;
    if (tok === "-C" || tok === "--chdir" || /^-[i0v]+C$/.test(tok)) {
      const nextTok = tokens[++i];
      if (nextTok) chdir = unquote(nextTok);
      continue;
    }
    if (tok.startsWith("--chdir=")) {
      chdir = unquote(tok.slice("--chdir=".length));
      continue;
    }
    const attachedC = /^-[i0v]*C(.+)$/.exec(tok);
    if (attachedC?.[1]) {
      chdir = unquote(attachedC[1]);
      continue;
    }
    if (tok === "-u" || tok === "--unset" || tok === "-S" || tok === "--split-string" || /^-[i0v]+u$/.test(tok)) {
      i++;
      continue;
    }
    if (tok.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(tok)) {
      continue;
    }
    // First downstream command token reached — stop scanning env options!
    break;
  }
  return chdir;
}

function analyzeCommandWorkingDirectory(
  input: Record<string, unknown> | undefined,
  command: string,
  toolName: string,
  verificationKinds: ReadonlySet<EvidenceKind>,
  projectDirectory?: string,
  inheritedCwd?: string,
  depth = 0
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
    : inheritedCwd;
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
        const innerNoBuiltin = inner.replace(/^builtin\s+/i, "").trim();
        if (/^(?:cd|pushd)(?:\s|$)/i.test(innerNoBuiltin)) {
          const cdWithoutRedirs = innerNoBuiltin
            .replace(/(?:\s+(?:\d*>>?|\d*<&|\d*>&|&>>?)\s*\S+|\s+\d*>&\d+)+\s*$/g, "")
            .trim();
          if (/^cd\s*$/i.test(cdWithoutRedirs)) {
            resolved = os.homedir();
          } else {
            const cdMatch = /^(?:cd|pushd)(?:\s+(?:-[LPn]+|--))*\s+(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))\s*$/i.exec(cdWithoutRedirs);
            const target = cdMatch ? (cdMatch[1] ?? cdMatch[2] ?? cdMatch[3]) : undefined;
            if (target && target !== "-") {
              if (/^pushd\b/i.test(cdWithoutRedirs)) {
                cwdStack.push(resolved);
              }
              const expanded = expandTilde(target);
              const base = resolved ?? projectDirectory;
              resolved = base ? path.resolve(base, expanded) : path.resolve(expanded);
            }
          }
        } else if (/^popd(?:\s|$)/i.test(innerNoBuiltin)) {
          if (cwdStack.length > 0) {
            resolved = cwdStack.pop();
          }
        } else {
          const envChdir = extractEnvChdirTarget(inner);
          const effectiveSegCwd = envChdir
            ? (() => {
                const expanded = expandTilde(envChdir);
                const base = resolved ?? projectDirectory;
                return base ? path.resolve(base, expanded) : path.resolve(expanded);
              })()
            : resolved;
          const nestedScripts =
            depth < 3
              ? [...literalShellScripts(inner), ...literalWindowsShellScripts(inner)]
              : [];
          if (nestedScripts.length > 0) {
            for (const script of nestedScripts) {
              const nestedCwd = analyzeCommandWorkingDirectory(
                undefined,
                script,
                toolName,
                verificationKinds,
                projectDirectory,
                effectiveSegCwd,
                depth + 1
              );
              if (nestedCwd.hasForeignVerificationCwd) {
                hasForeignVerificationCwd = true;
              }
              if (classifyCommand(script, toolName).some((k) => verificationKinds.has(k))) {
                sawVerificationSegment = true;
              }
            }
          } else {
            const segKinds = classifyCommand(inner, toolName);
            if (segKinds.some((k) => verificationKinds.has(k))) {
              sawVerificationSegment = true;
              if (
                projectDirectory &&
                effectiveSegCwd &&
                !isPathInsideDirectory(effectiveSegCwd, projectDirectory)
              ) {
                hasForeignVerificationCwd = true;
              }
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
      "appendContent",
      "prependContent",
      "ReplacementContent",
      "patch",
      "patchText",
    ].some(
      (key) => typeof input[key] === "string" &&
        (["content", "CodeContent", "text", "file_text", "new_string", "newString", "new_str", "appendContent", "prependContent", "ReplacementContent"].includes(key) || (input[key] as string).length > 0)
    )
  ) {
    return true;
  }

  return Boolean(extractLikelyShellMutation(input));
}

function hasMultipleNonAndSegmentsOfKind(
  command: string,
  toolName: string,
  kind: EvidenceKind,
  depth = 0
): boolean {
  if (!command) return false;
  const segments = splitTopLevelShellSegments(command);
  let nonAndCount = 0;
  let sawOrOrBg = false;
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i]!;
    if (seg.followedBy === "||" || seg.followedBy === "&") {
      sawOrOrBg = true;
    }
    if (classifyCommand(seg.text, toolName).includes(kind)) {
      nonAndCount++;
    }
    if (depth < 3) {
      const nested = [
        ...literalShellScripts(seg.text),
        ...literalWindowsShellScripts(seg.text),
      ];
      if (nested.some((script) => hasMultipleNonAndSegmentsOfKind(script, toolName, kind, depth + 1))) {
        return true;
      }
    }
  }
  if (sawOrOrBg) return true;
  if (nonAndCount > 1 && segments.some((s) => s.followedBy === ";" || s.followedBy === "\n")) {
    return true;
  }
  return false;
}

function escapeEvidenceRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function hasUpstreamPipelineFailureNote(outputText: string): boolean {
  return /^note:\s+`[^`]+`\s+\(segment\s+\d+\s+of\s+\d+\)\s+exited\s+[1-9]\d*;/m.test(outputText);
}

/**
 * Evaluate per-segment confirmation for a verification kind inside a compound/piped command:
 * 1. Explicit live shell exit-code echo (`echo TC=$?`, `echo BUILD $?`, `echo EXIT ${PIPESTATUS[0]}`):
 *    confirms `"success"` on `<LABEL>=0` (or `"failure"` on `<LABEL>=<nonzero>`).
 * 2. Clean `tail -N` (N >= 5, or default 10) / `tee` pipe for `typecheck` or `build` with zero compiler/build error lines
 *    and no upstream pipeline failure note.
 */
function inspectCompoundSegmentVerification(
  command: string,
  toolName: string,
  kind: EvidenceKind,
  outputText: string,
  exitCode: number | undefined,
  testReason: string | undefined
): "success" | "failure" | undefined {
  if (!command || exitCode !== 0) return undefined;
  if (hasMultipleNonAndSegmentsOfKind(command, toolName, kind)) return undefined;
  const segments = splitTopLevelShellSegments(command);
  const matchingIdx: number[] = [];
  for (let i = 0; i < segments.length; i++) {
    if (classifyCommand(segments[i]!.text, toolName).includes(kind)) {
      matchingIdx.push(i);
    }
  }
  if (matchingIdx.length !== 1) return undefined;
  const segIdx = matchingIdx[0]!;
  const seg = segments[segIdx]!;
  const nextSeg = segments[segIdx + 1];
  const segPiped = hasUnquotedSinglePipe(seg.text);

  // 1. Live shell exit-code capture immediately following the verification segment (`; echo TAG=$?`).
  if (nextSeg && (seg.followedBy === ";" || seg.followedBy === "\n")) {
    const exitEcho = parseExitStatusEchoStage(nextSeg.text.trim());
    if (exitEcho && (!segPiped || exitEcho.usesPipestatus)) {
      const escapedLabel = escapeEvidenceRegExp(exitEcho.label);
      // Reject if any other echo/printf segment in the command mentions the same label (prevents `echo TC=0` spoofing).
      const otherMentionsLabel = segments.some(
        (s, idx) =>
          idx !== segIdx + 1 &&
          /^(?:echo|printf)\b/i.test(stripBenignCommandWrappers(normalizeCommand(s.text))) &&
          new RegExp(`\\b${escapedLabel}\\b`).test(s.text)
      );
      if (!otherMentionsLabel) {
        const nonZeroRe = new RegExp(`^${escapedLabel}\\s*(?:=|:|\\s)\\s*[1-9]\\d*$`, "m");
        if (nonZeroRe.test(outputText)) {
          return "failure";
        }
        const zeroRe = new RegExp(`^${escapedLabel}\\s*(?:=|:|\\s)\\s*0$`, "m");
        if (zeroRe.test(outputText) && (kind !== "test" || !testReason)) {
          return "success";
        }
      }
    }
  }

  // 2. Clean tail (>= 2 lines) or tee passthrough for typecheck/build/lint (which print errors at the tail on failure).
  if ((kind === "typecheck" || kind === "build" || kind === "lint") && segPiped && !hasUpstreamPipelineFailureNote(outputText)) {
    const pipeline = splitShellStages(seg.text)[0] ?? [];
    if (pipeline.length >= 2) {
      const filters = pipeline.slice(1).map((s) => stripBenignCommandWrappers(normalizeCommand(s)).toLowerCase());
      const safeTailOrTee = filters.every((f) => {
        if (/</.test(f)) return false;
        if (/^tee(?:\s+-[ai]+)*\s+[^<>\s]+(?:\s+[^<>\s]+)*$/i.test(f)) return true;
        if (!/^tail(?:\s|$)/i.test(f)) return false;
        if (!/^tail(?:\s+(?:-n\s+[+-]?\d+|-[a-z]*\d+|-[a-z]+|--(?:lines|quiet|silent|verbose)(?:=[+-]?\d+)?))*\s*$/i.test(f)) {
          return false;
        }
        const numMatch = /(?:-n\s*|--lines=|-)(\d+)\b/.exec(f);
        const count = numMatch?.[1] ? Number(numMatch[1]) : 10;
        return Number.isFinite(count) && count >= 2;
      });
      const hasBuildOrTsError =
        /(?:^|\n)\s*(?:.*error TS\d+:|Found [1-9]\d* errors?\.|Found [1-9]\d* warnings? and \d+ errors?\.|Found \d+ warnings? and [1-9]\d* errors?\.|✖\s+\d+\s+problems?|npm (?:ERR!|error)\b|Build failed|Compilation failed|Command failed|SyntaxError:|TypeError:|ReferenceError:|ERR_MODULE_NOT_FOUND|✖\s+failing tests)/i.test(
          outputText
        );
      if (safeTailOrTee && !hasBuildOrTsError && !hasOutputSpoofingStage(command, outputText)) {
        return "success";
      }
    }
  }

  return undefined;
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
    Boolean(command) && hasNonAndSeparatorRecursive(command);
  const nonSequentialCompound =
    (verificationKindCount > 1 && hasNonAndSeparator) ||
    hasTrailingSeparatorAfterVerification(command, toolName, verificationKinds);
  const pipedWithoutPipefail =
    hasPipedVerificationWithoutPipefail(command, toolName, verificationKinds);

  const topSegments = command ? splitTopLevelShellSegments(command) : [];
  const lastShellMutationSegIdx = (() => {
    let idx = -1;
    for (let i = 0; i < topSegments.length; i++) {
      const segText = topSegments[i]!.text;
      if (!segText) continue;
      if (isLikelyShellFileDeletion(segText) || Boolean(extractLikelyShellMutation({ command: segText }))) {
        idx = i;
      }
    }
    return idx;
  })();

  for (const kind of kinds) {
    const firstVerificationSegIdx =
      lastShellMutationSegIdx >= 0 && verificationKinds.has(kind)
        ? topSegments.findIndex((seg) => classifyCommand(seg.text, toolName).includes(kind))
        : -1;
    const runsAfterIntraCommandMutation =
      lastShellMutationSegIdx >= 0 && firstVerificationSegIdx > lastShellMutationSegIdx;
    const recordSequence = runsAfterIntraCommandMutation ? sequence + 0.5 : sequence;
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
    const testSummary = kind === "test" ? parseTestSummary(outputText) : undefined;
    const testReason = kind === "test" ? testOutcomeReason(command, outcome.exitCode, testSummary) : undefined;
    const upstreamPipeFailed = hasUpstreamPipelineFailureNote(outputText);
    const segmentConfirmation =
      isVerification && !maskedVerification && !foreignCwd
        ? inspectCompoundSegmentVerification(command, toolName, kind, outputText, outcome.exitCode, testReason)
        : undefined;
    const confirmedByStructuredSummary =
      isVerification &&
      commandStatus === "success" &&
      outcome.exitCode === 0 &&
      !maskedVerification &&
      !foreignCwd &&
      !upstreamPipeFailed &&
      !hasOutputSpoofingStage(command, outputText) &&
      (
        (kind === "test" &&
          Boolean(testSummary) &&
          (testSummary?.total ?? 0) > 0 &&
          (testSummary?.passed ?? 0) > 0 &&
          (testSummary?.failed ?? 0) === 0 &&
          (testSummary?.cancelled ?? 0) === 0 &&
          !testReason) ||
        (kind === "lint" &&
          executableShellStages(command).some((stage) => /^oxlint\b/.test(stage)) &&
          /^Found 0 warnings and 0 errors\.$/m.test(outputText) &&
          !/^Found (?!0 warnings and 0 errors\.)\d+ warnings? and \d+ errors?\.$/m.test(outputText))
      );
    const confirmedVerification =
      segmentConfirmation === "success" ||
      (confirmedByStructuredSummary && !hasMultipleNonAndSegmentsOfKind(command, toolName, kind));
    const ambiguousVerification =
      isVerification &&
      (nonSequentialCompound || pipedWithoutPipefail) &&
      !confirmedVerification;
    const cancelled =
      outcome.aborted === true ||
      ((outcome.exitCode === 130 || part.state.status === "error") &&
        /^(?:error:\s*)?(?:(?:tool|command|operation|execution)\s+)?(?:cancelled by user|canceled by user|user cancel(?:led|ed))\b/i.test(outcome.errorText || outputText)) ||
      part.state.metadata?.cancelled === true ||
      part.state.metadata?.canceled === true;
    const evidenceStatus =
      segmentConfirmation === "failure"
        ? "failure"
        : maskedVerification || ambiguousVerification || (isVerification && foreignCwd)
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
      sequence: recordSequence,
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
  for (const rawRel of fileList) {
    const rel = rawRel.replace(/\\/g, "/");
    const full = path.resolve(root, rel);
    const scopedRoot = path.relative(root, full);
    const scopedReal = path.relative(realRoot, full);
    const insideLexicalRoot =
      scopedRoot !== ".." && !scopedRoot.startsWith(".." + path.sep) && !path.isAbsolute(scopedRoot);
    const insideRealRoot =
      scopedReal !== ".." && !scopedReal.startsWith(".." + path.sep) && !path.isAbsolute(scopedReal);
    if (!insideLexicalRoot && !insideRealRoot) {
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
