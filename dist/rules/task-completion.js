import { sanitizeProseForInspection } from "../prose.js";
import { classifyAgentReport } from "../locale-intents.js";
import { extractTaskContract } from "../task-contract.js";
import { evaluateTaskPolicy } from "../task-policy.js";
import { isWriteCapableAgent } from "../agent-capability.js";
function latestAssistantProse(context) {
    const last = context.currentTurn.findLast((message) => message.info.role === "assistant");
    if (!last)
        return "";
    return sanitizeProseForInspection(last.parts
        .filter((part) => part.type === "text" && typeof part.text === "string")
        .map((part) => part.text ?? "")
        .join("\n"));
}
/**
 * Completion is checked against concrete, ordered tool evidence rather than
 * treating a well-written final message as proof. Ambiguous evidence remains
 * advisory, and a documented blocker never triggers an automatic loop.
 *
 * Core completion logic is language-neutral: decisions rely on runtime tool
 * outcomes, mutation sequence numbers, and lifecycle state.
 */
export const taskCompletionRule = {
    id: "task/completion-gate",
    description: "Checks explicit iterative-review and verification requirements before accepting completion.",
    inspect(context) {
        const contract = extractTaskContract(context.currentTurn);
        const evidence = context.evidence;
        const prose = latestAssistantProse(context);
        const findings = [];
        const blocking = [];
        if (!evidence || !prose) {
            return { ruleId: this.id, decision: "pass", findings };
        }
        const writeCapable = isWriteCapableAgent(context);
        const report = classifyAgentReport(prose);
        const hasToolFailure = evidence.records.some((record) => record.status === "failure");
        // For non-modifying agents (read-only, approval-required, or unknown subagents):
        // reporting transparent incomplete work, a blocker, or a tool failure without
        // claiming completion passes to the parent/user rather than initiating an un-executable
        // self-remediation loop.
        if (!writeCapable && !report.isClosing && (report.hasClearBlocker || hasToolFailure)) {
            return { ruleId: this.id, decision: "pass", findings };
        }
        // For write-capable agents: a clear blocker only passes without remediation when
        // there are no unresolved tool failures and the agent did not claim completion.
        // Concrete tool failures on write-capable agents NEVER bypass completion evaluation.
        if (writeCapable && !hasToolFailure && !report.isClosing && report.hasClearBlocker) {
            return { ruleId: this.id, decision: "pass", findings };
        }
        const policy = contract?.requiresExplicitCompletion
            ? evaluateTaskPolicy(contract, evidence)
            : undefined;
        if (policy?.review === "missing") {
            const finding = {
                ruleId: this.id,
                pattern: "iteration ended after a change without a new review",
                messageSnippet: prose.slice(0, 160),
                description: contract?.requiresSourceReview
                    ? "The user explicitly required another source review after fixing a finding, but no successful post-change source inspection was observed."
                    : "The user explicitly required another review after fixing a finding, but no successful post-change review or verification was observed.",
                confidence: "high",
                evidence: ["successful change detected", "no subsequent successful required review/check"],
            };
            findings.push(finding);
            blocking.push(finding);
        }
        for (const verification of policy?.verifications ?? []) {
            if (verification.status === "passed")
                continue;
            // Concrete tool failure means the requested check failed.
            const isFailedCheck = verification.status === "failed";
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
            const finding = {
                ruleId: this.id,
                pattern: `${verification.kind} verification not confirmed`,
                messageSnippet: prose.slice(0, 160),
                description: verification.status === "failed"
                    ? (report.isClosing
                        ? `The task is reported as complete although the latest requested ${verification.kind} check failed.`
                        : `The requested ${verification.kind} verification failed with unresolved errors.`)
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
        if (writeCapable) {
            const unresolvedFailures = evidence.failures.filter((failure) => {
                const hasLaterSuccess = evidence.records.some((later) => later.sequence > failure.sequence &&
                    later.status === "success" &&
                    (later.kind === failure.kind || later.toolName === failure.toolName));
                return !hasLaterSuccess;
            });
            for (const failure of unresolvedFailures) {
                const alreadyCovered = policy?.verifications.some((v) => v.kind === failure.kind && v.status === "failed") ?? false;
                if (!alreadyCovered) {
                    const finding = {
                        ruleId: this.id,
                        pattern: `unresolved ${failure.kind} failure`,
                        messageSnippet: failure.errorFingerprint || failure.error || failure.command || prose.slice(0, 160),
                        description: `A concrete ${failure.kind} execution failed and was not resolved before stopping.`,
                        confidence: "high",
                        fingerprint: failure.errorFingerprint ??
                            `${failure.kind}:${failure.signature}`,
                    };
                    findings.push(finding);
                    blocking.push(finding);
                }
            }
        }
        return {
            ruleId: this.id,
            decision: blocking.length ? "block" : "pass",
            findings,
            ...(blocking.length ? {
                remediationPrompt: contract?.requiresExplicitCompletion
                    ? "The current user explicitly requested continued work. Perform another substantive review after the latest change, and run any explicitly requested checks before claiming completion. If blocked, explain the concrete blocker and remaining work instead of repeating a failing command."
                    : "A concrete execution failed and remains unresolved. Investigate the failure and correct it before stopping. If progress is genuinely blocked by missing permission, credentials, or required user input, report that concrete blocker instead of claiming completion or repeating the same failing action.",
            } : {}),
        };
    },
};
