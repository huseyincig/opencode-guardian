import type { GuardRule, RuleFinding, RuleResult, TurnInspectionContext } from "../types.js";
import { sanitizeProseForInspection } from "../prose.js";
import { classifyAgentReport } from "../locale-intents.js";
import { extractTaskContract } from "../task-contract.js";
import { evaluateTaskPolicy } from "../task-policy.js";

function latestAssistantProse(context: TurnInspectionContext): string {
  const last = context.currentTurn.findLast((message) => message.info.role === "assistant");
  if (!last) return "";
  return sanitizeProseForInspection(
    last.parts
      .filter((part) => part.type === "text" && typeof part.text === "string")
      .map((part) => part.text ?? "")
      .join("\n")
  );
}

/**
 * Completion is checked against concrete, ordered tool evidence rather than
 * treating a well-written final message as proof. Ambiguous evidence remains
 * advisory, and a documented blocker never triggers an automatic loop.
 *
 * Core completion logic is language-neutral: decisions rely on runtime tool
 * outcomes, mutation sequence numbers, and lifecycle state.
 */
export const taskCompletionRule: GuardRule = {
  id: "task/completion-gate",
  description: "Checks explicit iterative-review and verification requirements before accepting completion.",
  inspect(context): RuleResult {
    const contract = extractTaskContract(context.currentTurn);
    const evidence = context.evidence;
    const prose = latestAssistantProse(context);
    const findings: RuleFinding[] = [];
    const blocking: RuleFinding[] = [];
    if (!contract?.requiresExplicitCompletion || !evidence || !prose) {
      return { ruleId: this.id, decision: "pass", findings };
    }

    const report = classifyAgentReport(prose);
    const hasToolFailure = evidence.records.some((record) => record.status === "failure");

    // Transparent incomplete work, real blockers, and observable tool failures
    // are passed to the user unless the assistant contradicts itself by claiming completion.
    const hasBlocker = report.hasClearBlocker || (hasToolFailure && !report.isClosing);
    if (!report.isClosing && hasBlocker) {
      return { ruleId: this.id, decision: "pass", findings };
    }

    const policy = evaluateTaskPolicy(contract, evidence);
    if (policy.review === "missing") {
      const finding: RuleFinding = {
        ruleId: this.id,
        pattern: "iteration ended after a change without a new review",
        messageSnippet: prose.slice(0, 160),
        description: contract.requiresSourceReview
          ? "The user explicitly required another source review after fixing a finding, but no successful post-change source inspection was observed."
          : "The user explicitly required another review after fixing a finding, but no successful post-change review or verification was observed.",
        confidence: "high",
        evidence: ["successful change detected", "no subsequent successful required review/check"],
      };
      findings.push(finding);
      blocking.push(finding);
    }

    for (const verification of policy.verifications) {
      if (verification.status === "passed") continue;
      // Concrete tool failure means the requested check failed.
      const isFailedCheck = verification.status === "failed" && !hasBlocker;
      const isContradictory = report.isClosing || isFailedCheck;
      if (!isContradictory) {
        findings.push({
          ruleId: this.id,
          pattern: `${verification.kind} verification not confirmed`,
          messageSnippet: prose.slice(0, 160),
          description: `The user requested ${verification.kind} verification, but a successful result after the last change is not visible.`,
          confidence: "medium",
        });
        continue;
      }

      const finding: RuleFinding = {
        ruleId: this.id,
        pattern: `${verification.kind} verification not confirmed`,
        messageSnippet: prose.slice(0, 160),
        description:
          verification.status === "failed"
            ? `The task is reported as complete although the latest requested ${verification.kind} check failed.`
            : report.hasClearBlocker
              ? `The task is reported as complete while contradictory unfinished/blocker statements were made and ${verification.kind} check was not confirmed.`
              : `The user requested ${verification.kind} verification, but a successful result after the last change is not visible.`,
        confidence: (verification.status === "failed" || report.hasClearBlocker) ? "high" : "medium",
      };
      findings.push(finding);
      if (verification.status === "failed" || report.hasClearBlocker) {
        blocking.push(finding);
      }
    }

    return {
      ruleId: this.id,
      decision: blocking.length ? "block" : "pass",
      findings,
      ...(blocking.length ? {
        remediationPrompt: "The current user explicitly requested continued work. Perform another substantive review after the latest change, and run any explicitly requested checks before claiming completion. If blocked, explain the concrete blocker and remaining work instead of repeating a failing command.",
      } : {}),
    };
  },
};
