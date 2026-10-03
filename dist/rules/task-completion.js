import { sanitizeProseForInspection } from "../prose.js";
import { classifyInternationalAgentReport } from "../locale-intents.js";
import { extractTaskContract, } from "../task-contract.js";
import { evaluateTaskPolicy } from "../task-policy.js";
function latestAssistantProse(context) {
    const last = context.currentTurn.findLast((message) => message.info.role === "assistant");
    if (!last)
        return "";
    return sanitizeProseForInspection(last.parts
        .filter((part) => part.type === "text" && typeof part.text === "string")
        .map((part) => part.text ?? "")
        .join("\n"));
}
const CLOSING = /\b(?:completed?|finished|all\s+done|task\s+done|that's\s+it|no\s+(?:more|further)\s+(?:issues?|errors?|bugs?)|nothing\s+(?:else|left)\s+to\s+fix)\b|\b(?:tamamlandı|tamamladım|iş\s+bitti|denetim\s+bitti|inceleme\s+tamamlandı|hata\s+kalmadı|sorun\s+kalmadı|başka\s+hata\s+yok)\b/iu;
const CLEAR_BLOCKER = /\b(?:blocked|cannot\s+(?:proceed|continue|verify|run)|unable\s+to\s+(?:proceed|continue|verify|run)|need\s+(?:your\s+)?(?:permission|access|input)|not\s+(?:yet\s+)?(?:complete|done|finished)|unfinished)\b|\b(?:engellendi|ilerleyemiyorum|doğrulayamıyorum|çalıştıramıyorum|tamamlanmadı|izin\s+gerekiyor|erişim\s+gerekiyor|devam\s+edemiyorum)\b/iu;
/**
 * Completion is checked against concrete, ordered tool evidence rather than
 * treating a well-written final message as proof. Ambiguous evidence remains
 * advisory, and a documented blocker never triggers an automatic loop.
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
        if (!contract?.requiresExplicitCompletion || !evidence || !prose) {
            return { ruleId: this.id, decision: "pass", findings };
        }
        // Transparent incomplete work and real blockers should be reported to the
        // user instead of being turned into synthetic retries. However, claiming
        // completion while simultaneously admitting incomplete work or blockers
        // is a contradictory evasion that cannot bypass completion evaluation.
        const internationalReport = classifyInternationalAgentReport(prose);
        const hasClearBlocker = CLEAR_BLOCKER.test(prose) || internationalReport === "blocked";
        const proseWithoutBlockers = hasClearBlocker ? prose.replace(CLEAR_BLOCKER, " ") : prose;
        const isClosing = CLOSING.test(proseWithoutBlockers) || internationalReport === "completed";
        if (!isClosing && hasClearBlocker) {
            return { ruleId: this.id, decision: "pass", findings };
        }
        const policy = evaluateTaskPolicy(contract, evidence);
        if (policy.review === "missing") {
            const finding = {
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
        if (isClosing) {
            for (const verification of policy.verifications) {
                if (verification.status === "passed")
                    continue;
                const isContradictory = hasClearBlocker || verification.status === "failed";
                const finding = {
                    ruleId: this.id,
                    pattern: `${verification.kind} verification not confirmed`,
                    messageSnippet: prose.slice(0, 160),
                    description: verification.status === "failed"
                        ? `The task is reported as complete although the latest requested ${verification.kind} check failed.`
                        : hasClearBlocker
                            ? `The task is reported as complete while contradictory unfinished/blocker statements were made and ${verification.kind} check was not confirmed.`
                            : `The user requested ${verification.kind} verification, but a successful result after the last change is not visible.`,
                    confidence: isContradictory ? "high" : "medium",
                };
                findings.push(finding);
                if (isContradictory)
                    blocking.push(finding);
            }
        }
        return {
            ruleId: this.id,
            decision: blocking.length ? "block" : "pass",
            findings,
            remediationPrompt: blocking.length
                ? "The current user explicitly requested continued work. Perform another substantive review after the latest change, and run any explicitly requested checks before claiming completion. If blocked, explain the concrete blocker and remaining work instead of repeating a failing command."
                : undefined,
        };
    },
};
