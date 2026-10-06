/**
 * OpenCode Coordination Handoff Protocol (v1)
 * Enables decoupled, autonomous collaboration between OpenCode Guardian and Smart Questions.
 */
import { createHash } from "node:crypto";
import type { RuleResult } from "./types.js";

export const OPENCODE_HANDOFF_HEADER = "[OPENCODE_HANDOFF:v1]";

export type HandoffKind = "clarification" | "choice" | "approval";
export type HandoffAutoSelect = "allowed" | "forbidden";

export interface OpenCodeHandoff {
  version: "v1";
  source: "guardian";
  action: "question_required";
  kind: HandoffKind;
  autoSelect: HandoffAutoSelect;
  handoffId: string;
}

export const COORDINATION_SYMBOL = Symbol.for("opencode.coordination.v1");

export interface OpenCodeCoordinationRegistry {
  guardian?: {
    version: number;
    supportsHandoff: boolean;
  };
  smartQuestions?: {
    version: number;
    mainAgentOnly?: boolean;
    supportsAutoSelect?: boolean;
  };
}

/**
 * Format an OpenCode handoff descriptor to the versioned text protocol block.
 */
export function formatOpenCodeHandoff(
  handoff: Omit<OpenCodeHandoff, "version" | "source">
): string {
  return [
    OPENCODE_HANDOFF_HEADER,
    "source=guardian",
    `action=${handoff.action}`,
    `kind=${handoff.kind}`,
    `auto_select=${handoff.autoSelect}`,
    `handoff_id=${handoff.handoffId}`,
  ].join("\n");
}

/**
 * Parse an OpenCode handoff block from remediation or message text.
 */
export function parseOpenCodeHandoff(text: string): OpenCodeHandoff | null {
  const match = /\[OPENCODE_HANDOFF:v1\]\s*([\s\S]*?)(?:\n\n|\r\n\r\n|$)/.exec(text);
  if (!match || !match[1]) return null;

  const lines = match[1].split(/\r?\n/);
  const map = new Map<string, string>();
  for (const line of lines) {
    const eq = line.indexOf("=");
    if (eq > 0) {
      map.set(line.slice(0, eq).trim().toLowerCase(), line.slice(eq + 1).trim());
    }
  }

  const source = map.get("source");
  const action = map.get("action");
  const kind = map.get("kind") as HandoffKind | undefined;
  const autoSelect = map.get("auto_select") as HandoffAutoSelect | undefined;
  const handoffId = map.get("handoff_id");

  if (source !== "guardian" || action !== "question_required" || !handoffId) {
    return null;
  }
  if (kind !== "clarification" && kind !== "choice" && kind !== "approval") {
    return null;
  }
  if (autoSelect !== "allowed" && autoSelect !== "forbidden") {
    return null;
  }

  return {
    version: "v1",
    source: "guardian",
    action: "question_required",
    kind,
    autoSelect,
    handoffId,
  };
}

/**
 * Analyze blocking rule results and produce an appropriate question handoff if user input/choice is required.
 */
export function createHandoffForBlockingResults(
  results: readonly RuleResult[],
  sessionID: string,
  turnKey: string
): OpenCodeHandoff | null {
  const ruleIds = results.map((r) => r.ruleId);
  const prompts = results
    .map((r) => r.remediationPrompt ?? "")
    .filter(Boolean)
    .join("\n");

  let kind: HandoffKind | null = null;
  let autoSelect: HandoffAutoSelect = "allowed";

  // 1. Destructive operations: strict human approval required, auto-selection is forbidden.
  if (ruleIds.includes("safety/destructive-operations")) {
    kind = "approval";
    autoSelect = "forbidden";
  } else if (ruleIds.includes("runtime/circuit-breaker")) {
    // 2. Circuit breaker loop: clarify strategy or missing information with user.
    kind = "clarification";
    autoSelect = "allowed";
  } else if (ruleIds.includes("task/instruction-fidelity")) {
    // 3. Instruction conflict or user choice required.
    kind = "choice";
    autoSelect = "allowed";
  } else if (/(?:request confirmation|explicit confirmation|onay iste|kullanıcı onayı)/i.test(prompts)) {
    kind = "approval";
    autoSelect = "forbidden";
  } else if (/(?:choice|choose|which approach|seçim|hangisini)/i.test(prompts)) {
    kind = "choice";
    autoSelect = "allowed";
  } else if (/(?:ask the user|kullanıcıya sor|clarify with the user)/i.test(prompts)) {
    kind = "clarification";
    autoSelect = "allowed";
  }

  if (!kind) return null;

  const handoffHash = createHash("sha256")
    .update(`${sessionID}:${turnKey}:${ruleIds.join(",")}`)
    .digest("hex")
    .slice(0, 10);
  const handoffId = `gq_${handoffHash}`;

  return {
    version: "v1",
    source: "guardian",
    action: "question_required",
    kind,
    autoSelect,
    handoffId,
  };
}

/**
 * Register Guardian capability in the global OpenCode coordination registry.
 */
export function registerGuardianCapability(): void {
  const globalObj = globalThis as unknown as {
    [COORDINATION_SYMBOL]?: OpenCodeCoordinationRegistry;
  };
  const root = (globalObj[COORDINATION_SYMBOL] ??= {});
  root.guardian = {
    version: 1,
    supportsHandoff: true,
  };
}

/**
 * Check if Smart Questions is registered in the in-process capability registry.
 */
export function getSmartQuestionsCapability():
  | OpenCodeCoordinationRegistry["smartQuestions"]
  | undefined {
  const globalObj = globalThis as unknown as {
    [COORDINATION_SYMBOL]?: OpenCodeCoordinationRegistry;
  };
  return globalObj[COORDINATION_SYMBOL]?.smartQuestions;
}
