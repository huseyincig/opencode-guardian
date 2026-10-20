import type {
  GuardRule,
  RuleFinding,
  RuleResult,
  TurnInspectionContext,
} from "../types.js";
import { gitCleanInvocation, isDestructiveCommand, isOpaqueShellExecution, isSimpleFileRemoval } from "../evidence.js";
import { hasFindDeletion, literalShellScripts, splitShellStages } from "../shell-risk.js";
import { authorizationText, latestHumanInstruction } from "../task-constraints.js";
import { extractToolCommand } from "../tool-input.js";
import {
  isAuthorizedGitClean,
  isDeleteTargetRequested,
  isExplicitlyAllowedSudo,
  isImperativeExecutionRequest,
  isSqlDestructionRequested,
  isWholeWorkspaceDeleteRequested,
  SQL_TARGET_CONTEXT_REGEX,
} from "../locale-intents.js";

function latestHumanRequest(context: TurnInspectionContext): string {
  return authorizationText(latestHumanInstruction(context)).toLowerCase();
}

/** Only inspect literal git invocations, not echoed examples or comments. */
function guardBypass(command: string, depth = 0): { flag: string; action: string; confidence: "high" | "medium" } | undefined {
  if (depth > 2) return undefined;
  for (const stage of splitShellStages(command.slice(0, 64_000)).flat()) {
    // Remove comments without erasing # inside a quoted commit message.
    let quoted: string | undefined;
    let end = stage.length;
    for (let i = 0; i < stage.length; i++) {
      const char = stage[i];
      if (char === "\\" && quoted !== "'") { i++; continue; }
      if ((char === '"' || char === "'") && (!quoted || quoted === char)) {
        quoted = quoted ? undefined : char;
      } else if (!quoted && char === "#" && (i === 0 || /\s/.test(stage[i - 1] ?? ""))) { end = i; break; }
    }
    const tokens = simpleShellTokens(stage.slice(0, end));
    while (/^[A-Za-z_]\w*=/.test(tokens[0] ?? "")) tokens.shift();
    if (tokens[0] === "env") {
      tokens.shift();
      while (tokens.length) {
        if (/^[A-Za-z_]\w*=/.test(tokens[0] ?? "") || ["-i", "--ignore-environment", "--"].includes(tokens[0] ?? "")) tokens.shift();
        else if (["-u", "--unset"].includes(tokens[0] ?? "")) tokens.splice(0, 2);
        else break;
      }
    }
    if (!/^(?:[^\s]*\/)?git(?:\.exe)?$/i.test(tokens[0] ?? "")) continue;
    let i = 1;
    let hooks = false;
    while (tokens[i]?.startsWith("-")) {
      const option = tokens[i++];
      if (option === "-C" || option === "-c" || option === "--git-dir" || option === "--work-tree") {
        const value = tokens[i++] ?? "";
        if (option === "-c" && /^core\.hookspath=/i.test(value)) hooks = true;
      } else if (/^-ccore\.hookspath=/i.test(option ?? "")) hooks = true;
    }
    const action = tokens[i++] ?? "";
    if (hooks && ["commit", "push", "merge", "rebase", "am"].includes(action)) {
      return { flag: "core.hooksPath", action, confidence: "medium" };
    }
    const args = tokens.slice(i);
    if (action === "config" && !args.some((arg) => /^--(?:get|list|show|unset|remove)/.test(arg))) {
      const key = args.findIndex((arg) => /^core\.hookspath$/i.test(arg));
      if (key >= 0 && args[key + 1] !== undefined) return { flag: "core.hooksPath", action, confidence: "medium" };
    }
    if (["commit", "push", "merge", "rebase", "am"].includes(action)) {
      for (let n = 0; n < args.length; n++) {
        // Commit messages are data even when they contain an option literal.
        if (["-m", "--message", "-F", "--file"].includes(args[n] ?? "")) { n++; continue; }
        if (args[n] === "--") break;
        if (args[n] === "--no-verify" || action === "commit" && args[n] === "-n") {
          return { flag: args[n] ?? "--no-verify", action, confidence: "high" };
        }
      }
    }
  }
  for (const script of literalShellScripts(command.slice(0, 64_000))) {
    const bypass = guardBypass(script, depth + 1);
    if (bypass) return bypass;
  }
  return undefined;
}

function bypassAuthorized(request: string, command: string, bypass: { flag: string; action: string }): boolean {
  if (!request || /\b(?:not|don't|never|without|avoid)\b|(?:kullanma|yapma)/iu.test(request)) return false;
  if (!request.includes(bypass.flag.toLowerCase()) &&
      !(bypass.flag === "-n" && request.includes("--no-verify"))) return false;
  if (!new RegExp(`\\b${bypass.action}\\b`, "i").test(request)) return false;
  if (!gitScopeAuthorized(request, command)) return false;
  const requestedScope = /\bgit\s+-C\s+(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))/i.exec(request);
  if (requestedScope) {
    const actualScope = /\bgit\s+-C\s+(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))/i.exec(command);
    if (!actualScope || normalizeLiteralTarget(requestedScope[1] ?? requestedScope[2] ?? requestedScope[3] ?? "") !==
        normalizeLiteralTarget(actualScope[1] ?? actualScope[2] ?? actualScope[3] ?? "")) return false;
  }
  if (bypass.action === "push" && !gitActionTargetAuthorized(request, command, "push")) return false;
  return isImperativeExecutionRequest(request) ||
    /^(?:please\s+)?(?:commit|push|merge|rebase|configure|disable)\b/i.test(request) ||
    request.trim() === command.trim().toLowerCase();
}

/** An explicit ref/remote in the request cannot authorize a different one. */
function gitActionTargetAuthorized(request: string, command: string, action: "push" | "reset"): boolean {
  if (action === "reset") {
    const requested = /\b(?:reset(?:\s+--hard)?|hard\s+reset)\s+(?:to\s+)?([a-z0-9_/-]+(?:[~^]\d*)?)(?=\s|[.,;]|$)/i.exec(request)?.[1];
    if (!requested || /^(?:the|this|current|my|our|repo|repository|ile|yap|yapın|using|with)$/i.test(requested)) return true;
    const actual = /\breset\s+(?:--hard\s+)?([^\s;&|]+)/i.exec(command)?.[1];
    return actual?.toLowerCase() === requested.toLowerCase();
  }
  const tail = /\b(?:force\s+push|push\s+--force(?:-with-lease)?|push\s+(?:with\s+)?--no-verify|zorla\s+push)\s+([^;\n]+)/i.exec(request)?.[1];
  if (!tail || /^(?:the|this|current|my|our|repo|repository|changes|branch)\b/i.test(tail)) return true;
  const requestedText = tail.replace(/^(?:(?:only|to)\s+)+/i, "")
    .split(/\s+(?:and|then|ve|sonra)\s+/i)[0]?.replace(/[.!?]+$/, "") ?? "";
  const requested = simpleShellTokens(requestedText).filter((token) => !token.startsWith("-")).slice(0, 16);
  if (!requested.length) return true;
  const match = /\bpush\b([^;&|\n]*)/i.exec(command);
  const actual = simpleShellTokens(match?.[1] ?? "").filter((token) => !token.startsWith("-"));
  return requested.length === actual.length &&
    requested.every((target, index) => actual[index]?.toLowerCase() === target.toLowerCase());
}

function explicitlyAllowedSudo(request: string): boolean {
  return isExplicitlyAllowedSudo(request);
}

/** Require literal target matches before treating a scoped deletion as authorized. */
function matchesRequestedTargets(request: string, command: string): boolean {
  if (/[;&|\n\x60$<>]/.test(command)) return false;
  const words = command.trim().toLowerCase().split(/\s+/);
  if (words[0] === "sudo") {
    if (!explicitlyAllowedSudo(request)) return false;
    words.shift();
  }
  words.shift();
  const targets = words.filter((part) => !part.startsWith("-"));
  if (targets.length === 0) return false;

  return targets.every((target) => {
    if (!/^[a-z0-9_.\/-]+$/i.test(target)) return false;
    const variants = [target, target.replace(/^\.\//, "")];
    return variants.some((literal) => {
      let pos = request.indexOf(literal);
      while (pos !== -1) {
        const before = request[pos - 1];
        const afterAt = pos + literal.length;
        const after = request[afterAt];
        const beforeOK = before === undefined || !/[a-z0-9_./-]/i.test(before);
        const afterOK = after === undefined || !/[a-z0-9_./-]/i.test(after) ||
          (after === "." && afterAt + 1 === request.length);
        if (beforeOK && afterOK) return true;
        pos = request.indexOf(literal, pos + 1);
      }
      return false;
    });
  });
}

function normalizeLiteralTarget(target: string): string {
  return target
    .trim()
    .replace(/^["'`]|["'`]$/g, "")
    .replace(/^\.\//, "")
    .toLowerCase();
}

function literalTargetPositions(request: string, target: string): number[] {
  const literal = normalizeLiteralTarget(target);
  if (!literal) return [];

  const positions: number[] = [];
  let pos = request.indexOf(literal);
  while (pos !== -1) {
    const before = request[pos - 1];
    const afterAt = pos + literal.length;
    const after = request[afterAt];
    const boundary = /[a-z0-9_./@:-]/i;
    const beforeOK = before === undefined || !boundary.test(before);
    const sentencePeriod =
      after === "." &&
      (request[afterAt + 1] === undefined || /\s/.test(request[afterAt + 1] ?? ""));
    const afterOK =
      after === undefined || !boundary.test(after) || sentencePeriod;
    if (beforeOK && afterOK) positions.push(pos);
    pos = request.indexOf(literal, pos + 1);
  }
  return positions;
}

function targetNearContext(
  request: string,
  target: string,
  context: RegExp
): boolean {
  const literal = normalizeLiteralTarget(target);
  if (!literal) return false;

  return literalTargetPositions(request, literal).some((pos) => {
    const start = Math.max(0, pos - 100);
    const end = Math.min(request.length, pos + literal.length + 100);
    context.lastIndex = 0;
    return context.test(request.slice(start, end));
  });
}

function gitScopeAuthorized(request: string, command: string): boolean {
  const scope = /(?:^|\s)-C\s+(?:"([^"]+)"|'([^']+)'|([^\s;&|\n]+))/i.exec(
    command
  );
  const target = scope?.[1] ?? scope?.[2] ?? scope?.[3];
  if (!target || target === "." || target === "./") return true;
  return literalTargetPositions(request, target).length > 0;
}

function commandTarget(
  command: string,
  pattern: RegExp
): string | undefined {
  pattern.lastIndex = 0;
  const match = pattern.exec(command);
  const target = match?.slice(1).find((value) => Boolean(value));
  return target ? normalizeLiteralTarget(target) : undefined;
}

function simpleShellTokens(text: string): string[] {
  const tokens: string[] = [];
  const tokenPattern = /"([^"]*)"|'([^']*)'|([^\s]+)/g;
  let match = tokenPattern.exec(text);
  while (match) {
    const token = match[1] ?? match[2] ?? match[3];
    if (token) tokens.push(token);
    match = tokenPattern.exec(text);
  }
  return tokens;
}

function commandTargetsAfter(command: string, prefix: RegExp): string[] {
  prefix.lastIndex = 0;
  const match = prefix.exec(command);
  if (!match) return [];

  const start = (match.index ?? 0) + match[0].length;
  const tail = command.slice(start).split(/(?:&&|\|\||;|\n)/, 1)[0] ?? "";
  const targets: string[] = [];
  for (const token of simpleShellTokens(tail)) {
    if (token.startsWith("-")) break;
    const target = normalizeLiteralTarget(token);
    if (target) targets.push(target);
  }
  return targets;
}

function terraformTargets(text: string): string[] {
  const targets: string[] = [];
  const pattern = /(?:^|\s)-target(?:=|\s+)(?:"([^"]+)"|'([^']+)'|([^\s]+))/gi;
  let match = pattern.exec(text);
  while (match) {
    const raw = match[1] ?? match[2] ?? match[3] ?? "";
    const target = normalizeLiteralTarget(raw).replace(/[.!?,]+$/, "");
    if (target) targets.push(target);
    match = pattern.exec(text);
  }
  return targets;
}

function sqlDestructiveTargets(command: string): string[] {
  const targets: string[] = [];
  const pattern =
    /\b(?:drop\s+(?:database|schema|table)|truncate\s+table)\s+(?:if\s+exists\s+)?["'`]?([a-z0-9_.-]+)["'`]?/gi;
  let match = pattern.exec(command);
  while (match) {
    const target = match[1] ? normalizeLiteralTarget(match[1]) : "";
    if (target) targets.push(target);
    match = pattern.exec(command);
  }
  return targets;
}

/** A question about deletion is not permission to perform it.
 * Permit direct "can/could you delete" requests; treat explanations,
 * safety questions and Turkish advice questions as discussion. */
function isDeletionDiscussion(request: string): boolean {
  const text = request.trim();
  const directRequest = /^(?:can|could|would|will)\s+you\s+(?:please\s+)?(?:delete|remove|wipe)\b/i.test(text);
  if (directRequest) return false;
  return /^(?:what|why|how|should|may|is|are|do|does|did|would|could|can)\b/i.test(text) ||
    /^(?:tell|show|explain)\s+me\s+(?:how|why|what)\b/i.test(text) ||
    /\b(?:nasıl|neden)\b[^\n]*\b(?:sil|silerim|silinir|silmeli|silsem|sileyim)\b/iu.test(text) ||
    /\b(?:silmeli\s+miyim|silmeli\s+mıyım|silsem\s+mi|sileyim\s+mi)\b/iu.test(text);
}

function explicitlyAuthorized(request: string, command: string): boolean {
  if (!request || isDeletionDiscussion(request)) return false;

  const negative =
    /\b(?:do\s+not|don't|dont|never|avoid|without)\s+(?:delete|remove|destroy|drop|wipe|reset|force\s+push|clean|unpublish)\b|\b(?:silme|silmeyin|silmeden|kaldırma|kaldırmayın|yok\s+etme|sıfırlama|resetleme|zorla\s+push\s+yapma)\b/iu;
  if (negative.test(request)) return false;

  // Exact, literal find deletion may be authorized; broad "delete" wording
  // cannot authorize a different target or a rewritten shell command.
  if (hasFindDeletion(command)) return request.trim() === command.trim().toLowerCase();

  if (/\bgit(?:\s+(?:-C|-c)\s+(?:"[^"]*"|'[^']*'|[^\s;&|\n]+))*\s+push\b/i.test(command)) {
    return (
      gitScopeAuthorized(request, command) &&
      gitActionTargetAuthorized(request, command, "push") &&
      /\b(?:force\s+push|zorla\s+push|--force|force-with-lease)\b/iu.test(
        request
      )
    );
  }

  if (/\bgit(?:\s+(?:-C|-c)\s+(?:"[^"]*"|'[^']*'|[^\s;&|\n]+))*\s+reset\b[^\n;&|]*--hard\b/i.test(command)) {
    return (
      gitScopeAuthorized(request, command) &&
      gitActionTargetAuthorized(request, command, "reset") &&
      /\b(?:hard\s+reset|reset(?:le|leyin)?|sıfırla|sıfırlayın)\b/iu.test(
        request
      )
    );
  }

  const cleanInvocation = gitCleanInvocation(command);
  if (cleanInvocation) {
    // A scoped git invocation (-C / -c) must appear explicitly in the
    // user's request. Permission for the current repo is not permission to
    // clean an unrelated directory.
    const scoped = /\bgit\s+-/.test(cleanInvocation);
    if (scoped && !request.includes(cleanInvocation.toLowerCase())) {
      return false;
    }
    const cleanRequest = scoped
      ? request.replace(cleanInvocation.toLowerCase(), "git clean")
      : request;

    // The host already executed this tool by the time Guardian inspects it.
    // Unknown shell expansions and chained commands must not be recorded as
    // explicitly authorized; the default rule severity remains advisory.
    if (
      /[;&|\n`]/.test(command) ||
      /\$(?:\(|\{|[A-Za-z_])|<\(|>\(/.test(command) ||
      !gitCleanInvocation(cleanRequest) ||
      !isAuthorizedGitClean(cleanRequest, command)
    ) {
      return false;
    }
    return true;
  }

  if (/(?:^|[;&|]\s*)(?:sudo\s+)?rm\b/i.test(command)) {
    if (/[;&|\n\x60$<>]/.test(command)) return false;
    if (/^\s*sudo\s+/i.test(command) && !explicitlyAllowedSudo(request)) return false;
    const direct = request.trim() === command.trim().toLowerCase();
    const imperative = isImperativeExecutionRequest(request) &&
      !/\b(?:not|instead\s+of|rather\s+than|never|avoid)\b/iu.test(request) &&
      request.includes(command.trim().toLowerCase());
    if (direct || (imperative && matchesRequestedTargets(request, command))) return true;
    const deleteRequested = isDeleteTargetRequested(request);
    if (!deleteRequested) return false;

    const broadTarget =
      /(?:^|\s)(?:\.{1,2}\/?|\/|~\/?|\*|\.\/\*|\.\.\/\*)\s*(?:$|[;&|])/i.test(
        command
      );
    if (!broadTarget) return matchesRequestedTargets(request, command);
    const targets = command.trim().toLowerCase().split(/\s+/).filter((token) =>
      token !== "sudo" && token !== "rm" && !token.startsWith("-")
    );
    if (targets.length !== 1) return false;

    return isWholeWorkspaceDeleteRequested(request);
  }

  if (/\b(?:drop\s+(?:database|schema|table)|truncate\s+table)\b/i.test(command)) {
    const targets = sqlDestructiveTargets(command);
    return (
      targets.length > 0 &&
      isSqlDestructionRequested(request) &&
      targets.every((target) =>
        targetNearContext(
          request,
          target,
          SQL_TARGET_CONTEXT_REGEX
        )
      )
    );
  }

  if (/\bterraform\s+destroy\b/i.test(command)) {
    const actionAuthorized =
      /\b(?:terraform\s+destroy|destroy\s+(?:the\s+)?(?:stack|infra|infrastructure)|altyapıyı\s+(?:sil|yok\s+et))\b/iu.test(
        request
      );
    if (!actionAuthorized) return false;

    const requestedTargets = terraformTargets(request);
    if (requestedTargets.length === 0) return true;

    const commandTargets = terraformTargets(command);
    return (
      commandTargets.length > 0 &&
      commandTargets.every((target) => requestedTargets.includes(target))
    );
  }

  if (/\bkubectl\s+delete\s+(?:namespace|ns)\b/i.test(command)) {
    const targets = commandTargetsAfter(
      command,
      /\bkubectl\s+delete\s+(?:namespace|ns)\b/i
    );
    return (
      targets.length > 0 &&
      /\b(?:delete|remove|sil|kaldır)\b[\s\S]*\b(?:namespaces?|ns|namespace'i|namespace'ı)\b/iu.test(
        request
      ) &&
      targets.every((target) =>
        targetNearContext(
          request,
          target,
          /\b(?:delete|remove|sil|kaldır|namespaces?|ns)\b/iu
        )
      )
    );
  }

  if (/\bnpm\s+unpublish\b/i.test(command)) {
    const target = commandTarget(
      command,
      /\bnpm\s+unpublish\s+(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))/i
    );
    const normalizedTarget = target ?? "";
    return Boolean(
      normalizedTarget &&
      /\b(?:unpublish|yayından\s+kaldır)\b/iu.test(request) &&
      targetNearContext(
        request,
        normalizedTarget,
        /\b(?:unpublish|yayından\s+kaldır|package|paket)\b/iu
      )
    );
  }

  if (/\bgh\s+repo\s+delete\b/i.test(command)) {
    const target = commandTarget(
      command,
      /\bgh\s+repo\s+delete\s+(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))/i
    );
    const normalizedTarget = target ?? "";
    return Boolean(
      normalizedTarget &&
      /\b(?:delete|remove|sil|kaldır)\b[\s\S]*\b(?:repo|repository|depo)\b/iu.test(
        request
      ) &&
      targetNearContext(
        request,
        normalizedTarget,
        /\b(?:delete|remove|sil|kaldır|repo|repository|depo)\b/iu
      )
    );
  }

  if (/\bdocker\s+system\s+prune\b/i.test(command)) {
    return /\b(?:docker\s+(?:system\s+)?prune|docker\s+temizle)\b/iu.test(
      request
    );
  }

  return false;
}

export const destructiveOperationsRule: GuardRule = {
  id: "safety/destructive-operations",
  description:
    "Flags destructive shell/repository/infrastructure operations unless the user explicitly requested that destructive action.",
  inspect: (context: TurnInspectionContext): RuleResult => {
    const findings: RuleFinding[] = [];
    const request = latestHumanRequest(context);

    for (const message of context.currentTurn) {
      if (message.info.role !== "assistant") continue;
      for (const part of message.parts) {
        if (part.type !== "tool" || !part.state?.input) continue;
        const input = part.state.input;
        const command = extractToolCommand(input);
        if (!command) continue;
        const bypass = guardBypass(command);
        if (bypass && !bypassAuthorized(request, command, bypass)) {
          findings.push({
            ruleId: "safety/destructive-operations", pattern: "guard bypass",
            messageSnippet: command.replace(/\s+/g, " ").slice(0, 240),
            description: `Observed ${bypass.flag} guard override without explicit human authorization for this operation.`,
            confidence: bypass.confidence,
          });
        }
        const destructive = isDestructiveCommand(command);
        const opaque = isOpaqueShellExecution(command);
        const simpleRemoval = isSimpleFileRemoval(command);
        if (!destructive && !opaque && !simpleRemoval) continue;
        if ((destructive || simpleRemoval) && !opaque && explicitlyAuthorized(request, command)) continue;

        findings.push({
          ruleId: "safety/destructive-operations",
          pattern: destructive || simpleRemoval ? "destructive command" : "opaque shell execution",
          messageSnippet: command.replace(/\s+/g, " ").slice(0, 240),
          description: destructive || simpleRemoval
            ? "A destructive operation was detected without matching explicit authorization in the current turn."
            : "A decoded script was passed to a shell; its effects cannot be determined from the visible command.",
          confidence: destructive || simpleRemoval ? "high" : "medium",
        });
      }
    }

    if (findings.length === 0) {
      return {
        ruleId: "safety/destructive-operations",
        decision: "pass",
        findings: [],
      };
    }

    const list = findings
      .map((finding) => `  - ${finding.messageSnippet}`)
      .join("\n");

    return {
      ruleId: "safety/destructive-operations",
      decision: "block",
      findings,
      remediationPrompt:
        `Destructive or opaque shell activity needs review:\n${list}\n\n` +
        `Do not perform destructive repository, filesystem, package-registry, database, or infrastructure actions without explicit authorization. A decoded shell payload cannot be certified safe from the visible command; inspect it before running, use a constrained environment, or request confirmation.`,
      handoff: {
        required: true,
        kind: "approval",
        autoSelect: "forbidden",
      },
    };
  },
};
