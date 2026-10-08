import type { EvidenceRecord, SessionMessage, TurnEvidence } from "./types.js";
import {
  deniedVerification,
  extractAdvisoryTaskSignals,
  isExploratoryPrompt,
  sanitizeUserInstruction,
} from "./locale-intents.js";
export { isExploratoryPrompt } from "./locale-intents.js";

/** Explicit user requirements only. No LLM classification or inferred goals. */
export interface TaskContract {
  turnKey: string;
  explicitAction: boolean;
  iterativeReview: boolean;
  requiresSourceReview: boolean;
  requiredVerifications: Array<"test" | "build" | "typecheck" | "lint" | "audit">;
  requiresExplicitCompletion: boolean;
  /** Optional locale of explicit multilingual signals. Not a universal language detector. */
  signalLocale?: string;
}

function userText(message: SessionMessage): string {
  return message.parts
    .filter(
      (part) =>
        part.type === "text" &&
        typeof part.text === "string" &&
        part.synthetic !== true &&
        part.ignored !== true
    )
    .map((part) => part.text ?? "")
    .join("\n");
}

export function currentHumanMessage(
  messages: readonly SessionMessage[]
): SessionMessage | undefined {
  return messages.findLast(
    (message) =>
      message.info.role === "user" &&
      userText(message).trim().length > 0
  );
}

/** Optional, human-authored typed protocol when free-form intent is unclear. */
export interface ExplicitTaskDirective {
  mode: "iterative-review" | "one-pass";
  review: "source" | "checks";
  verify: TaskContract["requiredVerifications"];
}

/** Only an exact first-line directive is accepted; examples in code do not count. */
export function parseExplicitTaskDirective(text: string): ExplicitTaskDirective | undefined {
  const firstLine = text.split(/\r?\n/, 1)[0]?.trim() ?? "";
  const prefix = "@guardian-task ";
  if (!firstLine.startsWith(prefix) || firstLine.length > 800) return undefined;
  try {
    const value: unknown = JSON.parse(firstLine.slice(prefix.length));
    if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
    const item = value as Record<string, unknown>;
    if (Object.keys(item).some((key) => !["mode", "review", "verify"].includes(key))) {
      return undefined;
    }
    if (item.mode !== "iterative-review" && item.mode !== "one-pass") return undefined;
    if (item.review !== "source" && item.review !== "checks") return undefined;
    if (!Array.isArray(item.verify) || item.verify.length > 5 ||
        item.verify.some((kind) => !["test", "build", "typecheck", "lint", "audit"].includes(kind))) {
      return undefined;
    }
    return {
      mode: item.mode,
      review: item.review,
      verify: [...new Set(item.verify)] as ExplicitTaskDirective["verify"],
    };
  } catch {
    return undefined;
  }
}

export function extractTaskContract(
  messages: readonly SessionMessage[]
): TaskContract | undefined {
  const human = currentHumanMessage(messages);
  if (!human) return undefined;
  const text = userText(human).trim();
  if (!text) return undefined;

  // 1. Explicit machine-readable directive takes highest precedence
  const directive = parseExplicitTaskDirective(text);
  const body = sanitizeUserInstruction(text.startsWith("@guardian-task ")
    ? text.slice(text.indexOf("\n") < 0 ? text.length : text.indexOf("\n") + 1).trim()
    : text);

  // 2. Advisory locale / semantic signals (compatibility layer)
  const advisory = extractAdvisoryTaskSignals(body);
  const exploratory = isExploratoryPrompt(body) || advisory.exploratory;
  const negatedLoop = advisory.negatedLoop;

  const iterativeReview =
    !exploratory &&
    !negatedLoop &&
    (directive
      ? directive.mode === "iterative-review"
      : advisory.iterativeReview);

  const requestedVerifications = exploratory
    ? []
    : directive
      ? directive.verify
      : advisory.requiredVerifications;

  // A natural-language prohibition cannot be overridden by a machine-readable header.
  const requiredVerifications = requestedVerifications.filter((kind) =>
    !deniedVerification(body, kind)
  );

  const signalLocale = directive ? "structured" : advisory.signalLocale;

  return {
    turnKey: human.info.id ?? "no-human-user",
    explicitAction: Boolean(directive) ||
      ((!exploratory && advisory.explicitAction) || iterativeReview),
    iterativeReview,
    requiresSourceReview: iterativeReview &&
      (directive ? directive.review === "source" : advisory.requiresSourceReview),
    requiredVerifications,
    requiresExplicitCompletion: iterativeReview || requiredVerifications.length > 0,
    ...(signalLocale ? { signalLocale } : {}),
  };
}

export function taskGuidance(contract: TaskContract): string | undefined {
  if (!contract.explicitAction && !contract.requiresExplicitCompletion) return undefined;
  const instructions = [
    "[OpenCode Guardian task contract]",
    "Treat the latest explicit human instructions as the active task. Do not override them with earlier user decisions or assumptions.",
  ];
  if (contract.iterativeReview) {
    instructions.push(
      "The user explicitly requested repeated review/debugging. After fixing a finding, perform another review pass of the requested scope; do not claim completion after the first fix. Stop when a subsequent full pass finds no new issues, or report a concrete blocker and remaining work. Do not repeat identical failed actions without progress."
    );
  }
  if (contract.requiresSourceReview) {
    instructions.push(
      "This request calls for another source inspection after changes; a passing test command alone is not evidence of a new source review."
    );
  }
  if (contract.requiredVerifications.length > 0) {
    instructions.push(
      `The user explicitly requested verification: ${contract.requiredVerifications.join(", ")}. Run it after the last relevant change, or state clearly what could not be run and why. Do not claim a passing result without tool evidence.`
    );
  }
  return instructions.join("\n");
}

export function latestMutationSequence(evidence: TurnEvidence): number {
  return evidence.fileMutations
    .filter((record) => record.status !== "failure")
    .reduce((latest, record) => Math.max(latest, record.sequence), -1);
}

export function isSourceReviewEvidence(record: EvidenceRecord): boolean {
  if (record.status !== "success" || record.kind !== "generic") return false;
  const output = record.output?.trim();
  if (!output) return false;

  const tool = record.toolName.toLowerCase();
  const command = record.command ?? "";

  // Read/view tools commonly use names such as read_file and file.view.
  // Reject obvious error envelopes even when a provider incorrectly reports
  // the outer tool invocation as successful.
  const directRead = /(?:^|[.:_-])(?:read|view)(?:$|[.:_-])/.test(tool);
  if (directRead) {
    return !/^\s*(?:error|failed|failure|exception)\b/i.test(output) &&
      !/^\s*\{\s*"error"\s*:/i.test(output);
  }

  // Name-only searches, glob/find output and git diff --stat are not
  // evidence of inspecting file contents. Require an actual source snippet.
  const codeMatch = /^(?:(?:[A-Za-z]:)?[^\n:]+:)?\d+:(?!\d+:[ \t]*$)(?:\d+:)?\s*\S/m.test(output);
  const searchTool = /(?:^|[.:_-])(?:grep|search)(?:$|[.:_-])/.test(tool);
  // Recognize executed shell commands, not words inside echo arguments or
  // a pipeline into cat/head that might return only filenames or statistics.
  const shellSearch = /(?:^|(?:&&|\|\||;|\n)\s*)\s*(?:rg|grep)(?=\s|$)/m.test(command);
  if (searchTool || shellSearch) return codeMatch;

  const directShellRead =
    /(?:^|(?:&&|\|\||;|\n)\s*)\s*(?:cat|head|tail)(?=\s|$)/m.test(command) ||
    /(?:^|(?:&&|\|\||;|\n)\s*)\s*sed\s+-n(?=\s|$)/m.test(command) ||
    /(?:^|(?:&&|\|\||;|\n)\s*)\s*git\s+show\s+[^\s;&|]+:[^\s;&|]+(?=\s|$|[;&|])/m.test(command);
  if (directShellRead) return true;
  return /(?:^|(?:&&|\|\||;|\n)\s*)\s*git\s+(?:diff|show)(?=\s|$)/m.test(command) &&
    /^[+-](?![+-])\s*\S/m.test(output);
}

export function hasPostMutationReview(
  evidence: TurnEvidence,
  sourceReviewRequired = false
): boolean {
  const lastMutation = latestMutationSequence(evidence);
  if (lastMutation < 0) return false;
  return evidence.records.some((record) => {
    if (record.sequence <= lastMutation || record.status !== "success") return false;
    if (!sourceReviewRequired && ["test", "build", "typecheck", "lint", "audit"].includes(record.kind)) {
      return true;
    }
    return isSourceReviewEvidence(record);
  });
}
