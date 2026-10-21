import type { GuardRule, RuleFinding, RuleResult } from "../types.js";
import { hasResearchOnlyConstraint, latestHumanInstruction } from "../task-constraints.js";
import { collectTurnEvidence } from "../evidence.js";
import { sanitizeProseForInspection } from "../prose.js";
import { detectInstructionFidelitySignals } from "../locale-intents.js";

/** High-confidence conflicts with the current explicit action only. */
export const instructionFidelityRule: GuardRule = {
  id: "task/instruction-fidelity",
  description: "Detects historical refusals and redundant confirmation handoffs that conflict with the current explicit task.",
  inspect(context): RuleResult {
    const instruction = latestHumanInstruction(context);
    const evidence = context.evidence ?? collectTurnEvidence(context.currentTurn);
    if (hasResearchOnlyConstraint(instruction)) {
      const mutations = evidence.records.filter((record) =>
        record.status !== "failure" &&
        ["file-mutation", "install", "git-push"].includes(record.kind));
      if (mutations.length > 0) {
        return {
          ruleId: this.id, decision: "block",
          findings: mutations.slice(0, 20).map((record) => ({
            ruleId: this.id,
            pattern: "research-only scope violation",
            messageSnippet: (record.command ?? record.filePath ?? record.toolName).slice(0, 240),
            description: "Observed mutation conflicts with the latest human research-only/no-edits instruction.",
            confidence: record.status === "success" ? "high" as const : "medium" as const,
          })),
          remediationPrompt:
            "Instruction fidelity violation (research-only):\n\n" +
            "ACTION REQUIRED:\n" +
            "1. Respect the current research-only/no-edits constraint.\n" +
            "2. Report the observed mutation and continue with read-only investigation.\n" +
            "3. Do not perform more changes or automatically undo user work.",
        };
      }
    }
    const assistant = context.currentTurn
      .findLast((message) => message.info.role === "assistant")?.parts
      .filter((part) => part.type === "text" && typeof part.text === "string")
      .map((part) => part.text ?? "")
      .join("\n") ?? "";
    const prose = sanitizeProseForInspection(assistant);

    const observableWork = context.evidence?.records.some(
      (record) =>
        record.status === "success" &&
        [
          "file-mutation",
          "install",
          "test",
          "build",
          "typecheck",
          "lint",
          "audit",
          "git-push",
        ].includes(record.kind)
    ) ?? false;

    const signals = detectInstructionFidelitySignals(instruction, prose, observableWork);
    if (!signals.hasViolation) {
      return { ruleId: this.id, decision: "pass", findings: [] };
    }

    if (signals.type === "redundant-handoff") {
      const finding: RuleFinding = {
        ruleId: this.id,
        pattern: "redundant confirmation after explicit action",
        messageSnippet: prose.slice(0, 200),
        description: "The user already gave an explicit action instruction, but the assistant handed the decision back without observable work or a concrete blocker.",
        confidence: "high",
      };
      return {
        ruleId: this.id,
        decision: "block",
        findings: [finding],
        remediationPrompt:
          "Instruction fidelity violation (redundant confirmation):\n\n" +
          "ACTION REQUIRED:\n" +
          "1. The current user already authorized the requested action. Continue the work instead of asking for redundant confirmation.\n" +
          "2. Ask only when a concrete missing permission, credential, required input, or genuinely unresolved technical choice prevents safe progress.",
      };
    }

    const finding: RuleFinding = {
      ruleId: this.id,
      pattern: signals.internationalLocale
        ? `past decision overrides current instruction (${signals.internationalLocale})`
        : "past decision overrides current instruction",
      messageSnippet: prose.slice(0, 200),
      description: "The assistant explicitly declined the current requested action on the basis of an earlier user decision. The latest explicit instruction must be considered; an actual conflict should be explained rather than silently changing scope.",
      confidence: "high",
    };
    return {
      ruleId: this.id,
      decision: "block",
      findings: [finding],
      remediationPrompt:
        "Instruction fidelity violation (stale deferral):\n\n" +
        "ACTION REQUIRED:\n" +
        "1. Re-evaluate the current explicit user request. Do not treat an earlier pause or deferral as a permanent prohibition.\n" +
        "2. Perform the requested work if otherwise permitted.\n" +
        "3. If a genuine conflict prevents it, identify the conflicting instruction precisely and ask the user rather than silently declining.",
    };
  },
};
