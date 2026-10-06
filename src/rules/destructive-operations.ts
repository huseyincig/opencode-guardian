import type {
  GuardRule,
  RuleFinding,
  RuleResult,
  TurnInspectionContext,
} from "../types.js";
import { gitCleanInvocation, isDestructiveCommand, isOpaqueShellExecution, isSimpleFileRemoval } from "../evidence.js";
import { hasFindDeletion } from "../shell-risk.js";

function latestHumanRequest(context: TurnInspectionContext): string {
  const user = context.currentTurn.findLast(
    (message) =>
      message.info.role === "user" &&
      !message.parts.some((part) => part.synthetic === true)
  );
  if (!user) return "";
  return user.parts
    .filter((part) => part.type === "text" && typeof part.text === "string")
    .map((part) => part.text)
    .join("\n")
    .toLowerCase();
}

function explicitlyAllowedSudo(request: string): boolean {
  const forbidden = /\b(?:without|no|never|avoid|do\s+not|don\x27t|dont)\s+(?:(?:using|use|running|run)\s+)?sudo\b/i.test(request) ||
    /\bsudo\b[^.!?\n]{0,40}\b(?:kullanma|kullanmayın|yapma|olmadan)\b/iu.test(request);
  return /\bsudo\b/i.test(request) && !forbidden;
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
      /\b(?:force\s+push|zorla\s+push|--force|force-with-lease)\b/iu.test(
        request
      )
    );
  }

  if (/\bgit(?:\s+(?:-C|-c)\s+(?:"[^"]*"|'[^']*'|[^\s;&|\n]+))*\s+reset\b[^\n;&|]*--hard\b/i.test(command)) {
    return (
      gitScopeAuthorized(request, command) &&
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
      /\b(?:do\s+not|don't|dont|never|avoid|without)\s+(?:(?:run|running|execute|executing|use|using)\s+)?git\s+clean\b/i.test(cleanRequest) ||
      /\b(?:instead\s+of|rather\s+than)\s+(?:(?:running|using)\s+)?git\s+clean\b/i.test(cleanRequest) ||
      /\bgit\s+clean\b[^.!?\n]{0,60}\b(?:yapma|yapmayın|kullanma|kullanmayın|uygulama|uygulamayın|çalıştırma|çalıştırmayın|çalıştırmamalısın|istemiyorum|yerine)\b/iu.test(cleanRequest) ||
      !(
        /\b(?:run|execute|use|apply)\s+(?:the\s+)?git\s+clean\b/i.test(cleanRequest) ||
        /\bgit\s+clean\b[^.!?\n]{0,80}\b(?:yap|yapın|uygula|uygulayın|çalıştır|çalıştırın|kullan|kullanın)\b/iu.test(cleanRequest) ||
        request.trim() === command.trim().toLowerCase()
      )
    ) {
      return false;
    }

    const ignoredFiles = /(?:^|\s)-[a-z]*[xX][a-z]*(?=\s|$)|--(?:exclude-standard|ignored)(?=\s|$)/.test(
      command
    );
    return (
      !ignoredFiles ||
      /(?:^|\s)-[a-z]*[xX][a-z]*(?=\s|$)|\b(?:ignored\s+files?|gitignored\s+files?|yok\s+sayılan\s+dosyalar|ignore\s+edilen\s+dosyalar)\b/iu.test(
        request
      )
    );
  }

  if (/(?:^|[;&|]\s*)(?:sudo\s+)?rm\b/i.test(command)) {
    if (/[;&|\n\x60$<>]/.test(command)) return false;
    if (/^\s*sudo\s+/i.test(command) && !explicitlyAllowedSudo(request)) return false;
    const direct = request.trim() === command.trim().toLowerCase();
    const imperative = /^\s*(?:please\s+)?(?:run|execute|çalıştır|çalıştırın)\b/iu.test(request) &&
      !/\b(?:not|instead\s+of|rather\s+than|never|avoid)\b/iu.test(request) &&
      request.includes(command.trim().toLowerCase());
    if (direct || (imperative && matchesRequestedTargets(request, command))) return true;
    const deleteRequested =
      /\b(?:delete|remove|wipe|sil|silin|sileyim|kaldır|kaldırın)\b/iu.test(
        request
      );
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

    return (
      /\brm\s+-rf\s+\.\/?(?:\s|$)/i.test(request) ||
      /\b(?:delete|remove|wipe|destroy)\s+(?:the\s+)?(?:entire|whole)\s+(?:project|repo|repository|directory|folder|workspace)\b/iu.test(request) ||
      /\b(?:entire|whole)\s+(?:project|repo|repository|directory|folder|workspace)\b[^.!?]*\b(?:delete|remove|wipe|destroy)\b/iu.test(request) ||
      /\b(?:tüm|bütün|komple)\s+(?:projeyi|depoyu|klasörü|dizini|çalışma\s+alanını)\s+(?:sil|silin|sıfırla|sıfırlayın)\b/iu.test(request) ||
      /\b(?:projenin|deponun|klasörün|dizinin)\s+tamamını\s+(?:sil|silin)\b/iu.test(request)
    );
  }

  if (/\b(?:drop\s+(?:database|schema|table)|truncate\s+table)\b/i.test(command)) {
    const targets = sqlDestructiveTargets(command);
    return (
      targets.length > 0 &&
      /\b(?:drop|truncate|delete|remove|sil|kaldır)\b/iu.test(request) &&
      targets.every((target) =>
        targetNearContext(
          request,
          target,
          /\b(?:drop|truncate|delete|remove|sil|kaldır|tables?|databases?|schemas?|tablolar?|veritabanı|şema)\b/iu
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
        const command =
          typeof input.command === "string"
            ? input.command
            : typeof input.cmd === "string"
              ? input.cmd
              : typeof input.script === "string"
                ? input.script
                : "";

        if (!command) continue;
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
    };
  },
};
