import { sanitizeProseForInspection } from "../prose.js";
import { classifyAgentReport } from "../locale-intents.js";
import { extractTaskContract } from "../task-contract.js";
import { evaluateTaskPolicy } from "../task-policy.js";
import { isWriteCapableAgent } from "../agent-capability.js";
import { splitShellStages } from "../shell-risk.js";
function latestAssistantProse(context) {
    const last = context.currentTurn.findLast((message) => message.info.role === "assistant");
    if (!last)
        return "";
    return sanitizeProseForInspection(last.parts
        .filter((part) => part.type === "text" && typeof part.text === "string")
        .map((part) => part.text ?? "")
        .join("\n\n"), { preserveParagraphs: true });
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
        const contract = extractTaskContract(context.currentTurn, context.sessionID);
        const evidence = context.evidence;
        const prose = latestAssistantProse(context);
        const findings = [];
        const blocking = [];
        if (!evidence) {
            return { ruleId: this.id, decision: "pass", findings };
        }
        const writeCapable = isWriteCapableAgent(context);
        const report = classifyAgentReport(prose);
        const hasToolFailure = evidence.records.some((record) => record.status === "failure");
        // Explicit in-progress report: work is actively underway, never block completion prematurely.
        if (report.isInProgress && !report.isClosing) {
            return { ruleId: this.id, decision: "pass", findings };
        }
        // Subagents reporting intermediate progress or turns without claiming completion
        // communicate with their parent orchestrator and must not be trapped in an unprompted
        // completion-gate remediation loop.
        if (context.isSubagent && !report.isClosing) {
            return { ruleId: this.id, decision: "pass", findings };
        }
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
            ? evaluateTaskPolicy(contract, evidence, context.directory)
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
            const verificationFingerprint = verification.evidence?.errorFingerprint ??
                verification.evidence?.signature ??
                `${verification.kind}:${verification.status}`;
            const finding = {
                ruleId: this.id,
                pattern: `${verification.kind} verification not confirmed`,
                messageSnippet: verification.evidence?.errorFingerprint ??
                    verification.evidence?.error ??
                    verification.evidence?.command ??
                    prose.slice(0, 160),
                description: verification.status === "failed"
                    ? (report.isClosing
                        ? `The task is reported as complete although the latest requested ${verification.kind} check failed.`
                        : `The requested ${verification.kind} verification failed with unresolved errors.`)
                    : report.hasClearBlocker
                        ? `The task is reported as complete while contradictory unfinished/blocker statements were made and ${verification.kind} check was not confirmed.`
                        : `The user requested ${verification.kind} verification, but a successful result after the last change is not visible.`,
                confidence: (verification.status === "failed" || report.hasClearBlocker) ? "high" : "medium",
                fingerprint: `verification:${verification.kind}:${verificationFingerprint}`,
            };
            findings.push(finding);
            if (verification.status === "failed" || report.hasClearBlocker) {
                blocking.push(finding);
            }
        }
        if (writeCapable) {
            const commandIdentity = (value) => (value ?? "")
                .toLowerCase()
                .replace(/^(?:cd\s+(?:"[^"]*"|'[^']*'|\S+)\s*&&\s*)+/, "")
                .replace(/\s+2>&1\b/g, "")
                .replace(/\s+--verbose\b/g, "")
                .replace(/\s+-v\b/g, "")
                .replace(/\s+/g, " ")
                .trim();
            const isBenignReadOnlyProbeFailure = (failure) => {
                if (failure.kind !== "generic" && failure.kind !== "git-status")
                    return false;
                const cmd = (failure.command ?? "").trim();
                const errOut = `${failure.error ?? ""}\n${failure.output ?? ""}`;
                if (cmd) {
                    const pipelines = splitShellStages(cmd);
                    const isSingleUnpipedStage = pipelines.length === 1 && (pipelines[0]?.length ?? 0) === 1;
                    const isZeroMatchSearch = failure.kind === "generic" &&
                        isSingleUnpipedStage &&
                        failure.exitCode === 1 &&
                        /^(?:(?:sudo\s+)?(?:\/(?:[A-Za-z0-9._-]+\/)+)?(?:rg|grep|egrep|fgrep|git\s+grep|diff|cmp|test|\[))(?:\s|$)/i.test(cmd) &&
                        !/(?:no such file or directory|permission denied|invalid option|unrecognized option|command not found|fatal:|error:)/i.test(errOut);
                    if (isZeroMatchSearch)
                        return true;
                    // Compound read-only inspection probes ending in `ls -d <deleted>` / `stat` / `test -e` / `grep`
                    // where EVERY stage is strictly read-only (no mutations) and exit code is 1 or 2 (not-found / zero-match).
                    const allStages = pipelines.flat().map((s) => s.trim()).filter(Boolean);
                    const allReadOnlyProbeStages = allStages.length > 0 &&
                        (failure.exitCode === 1 || failure.exitCode === 2) &&
                        !/(?:permission denied|invalid option|unrecognized option|command not found|syntax error|fatal:)/i.test(errOut) &&
                        allStages.every((s) => {
                            const withoutNullStderr = s.replace(/\s+2>\s*\/dev\/null\b/g, "");
                            return (!/[<>]/.test(withoutNullStderr) &&
                                /^(?:cd|pwd|ls|stat|test|\[|rg|grep|egrep|fgrep|diff|cmp|echo|printf|head|tail|wc|git\s+(?:status|diff|log|show|grep|ls-files|check-ignore|rev-parse))(?:\s|$)/i.test(withoutNullStderr));
                        }) &&
                        allStages.some((s) => /^(?:ls|stat|test|\[|rg|grep|egrep|fgrep|git\s+(?:grep|check-ignore))(?:\s|$)/i.test(s));
                    if (allReadOnlyProbeStages)
                        return true;
                }
                if (failure.kind !== "generic")
                    return false;
                const toolLower = failure.toolName.toLowerCase();
                const isReadTool = /^(?:read|read_file|view_file|file_read|read_text_file|glob|find|grep|search|list|ls|stat)$/.test(toolLower);
                if (isReadTool &&
                    /(?:enoent|no such file|file not found|does not exist|cannot find)/i.test(errOut)) {
                    return true;
                }
                return false;
            };
            const normalizeVerificationRunner = (raw) => commandIdentity(raw)
                .replace(/^(?:npx(?:\s+--no-install)?|pnpm\s+exec|yarn\s+exec|bunx|npm\s+exec\s+--)\s+/i, "")
                .replace(/^(npm|pnpm|yarn|bun)\s+run\s+(test|lint|typecheck|build)(?=\s|$)/i, "$1 $2")
                .replace(/^vitest\s+run(?=\s|$)/i, "vitest");
            const isBroaderOrSameVerificationCommand = (failCmd, laterCmd, kind) => {
                if (!["test", "lint", "typecheck", "build"].includes(kind))
                    return false;
                const failNorm = normalizeVerificationRunner(failCmd);
                const laterNorm = normalizeVerificationRunner(laterCmd);
                if (failNorm === laterNorm)
                    return true;
                const runnerPrefixes = [
                    /^(?:npm|pnpm|yarn|bun)\s+(?:test|lint|typecheck|build)(?=\s|$)/,
                    /^(?:pytest|py\.test|vitest|jest|cargo\s+(?:test|clippy|build)|go\s+(?:test|build)|node\s+--test|tsc|eslint|oxlint|biome\s+(?:lint|check)|ruff|mypy|pyright)(?=\s|$)/,
                ];
                for (const prefixRe of runnerPrefixes) {
                    const failPrefix = prefixRe.exec(failNorm)?.[0];
                    const laterPrefix = prefixRe.exec(laterNorm)?.[0];
                    if (!failPrefix || !laterPrefix || failPrefix !== laterPrefix)
                        continue;
                    const laterRest = laterNorm.slice(laterPrefix.length).trim();
                    // Full suite / broad invocation (no focused file filter, or broad `.` / `./...` / `--noEmit`)
                    if (laterRest === "" ||
                        laterRest === "." ||
                        laterRest === "./..." ||
                        laterRest === "--noemit" ||
                        laterRest === "--all") {
                        return true;
                    }
                }
                return false;
            };
            const resolvesFailure = (failure, later) => {
                if (later.sequence <= failure.sequence || later.status !== "success")
                    return false;
                if (failure.kind === "file-mutation") {
                    return Boolean(later.kind === "file-mutation" &&
                        failure.filePath &&
                        later.filePath &&
                        failure.filePath === later.filePath);
                }
                if (failure.kind === "generic" && !failure.command) {
                    const siblingMutations = evidence.fileMutations.filter((m) => m.sequence === failure.sequence && m.filePath);
                    if (siblingMutations.length > 0) {
                        return siblingMutations.every((m) => evidence.fileMutations.some((succ) => succ.sequence > failure.sequence &&
                            succ.status === "success" &&
                            succ.filePath === m.filePath));
                    }
                }
                if (later.kind !== failure.kind)
                    return false;
                if (failure.command || later.command) {
                    if ((failure.cwd || later.cwd) && failure.cwd !== later.cwd) {
                        return false;
                    }
                    return Boolean(failure.command &&
                        later.command &&
                        (commandIdentity(failure.command) === commandIdentity(later.command) ||
                            isBroaderOrSameVerificationCommand(failure.command, later.command, failure.kind)));
                }
                // Non-shell structured tool retry (e.g. `subagent`, `todowrite`, `hi_task`, `aft_callers` failed
                // schema/validation/ambiguity check and then succeeded on a subsequent call with fixed arguments).
                if (!failure.command && !later.command && failure.toolName && later.toolName === failure.toolName) {
                    if (failure.filePath && later.filePath) {
                        return failure.filePath === later.filePath;
                    }
                    if (!failure.filePath) {
                        return true;
                    }
                }
                // Shell parameter-validation rejection before command execution (e.g. invalid `timeoutMs` or missing tool arg)
                // resolved when a subsequent call to the same shell tool succeeds.
                const failureText = `${failure.error ?? ""}\n${failure.output ?? ""}`;
                if (failure.kind === "generic" &&
                    later.toolName === failure.toolName &&
                    /(?:invalid arguments for tool|timeoutms must be between|missing required (?:key|field|parameter|argument))/i.test(failureText)) {
                    return true;
                }
                return later.signature === failure.signature;
            };
            const isPolicyRefusalOrRedirectFailure = (failure) => {
                const errOut = `${failure.error ?? ""}\n${failure.output ?? ""}`;
                // Host/plugin policy blocking shell grep/rg in favor of indexed search tools: resolved once
                // a later non-shell search/read/grep/glob/code-nav tool succeeds.
                if (/do not search code by running (?:grep|rg)|use the (?:grep|glob|search) tool instead/i.test(errOut) &&
                    evidence.records.some((later) => later.sequence > failure.sequence &&
                        later.status === "success" &&
                        !later.command &&
                        /(?:grep|glob|search|read|find|callers|outline|symbol|zoom|aft)/i.test(later.toolName))) {
                    return true;
                }
                // Host/plugin scope or coordinator write refusal (cannot be fixed by retrying the forbidden write).
                if (/(?:coordinator and cannot write|cannot write [^\n]* directly;\s*delegate|path not in task scope|outside (?:task|write) scope|edit denied[^\n]*scope)/i.test(errOut)) {
                    return true;
                }
                return false;
            };
            const unresolvedFailures = evidence.failures.filter((failure) => {
                if (isBenignReadOnlyProbeFailure(failure))
                    return false;
                if (isPolicyRefusalOrRedirectFailure(failure))
                    return false;
                const hasLaterSuccess = evidence.records.some((later) => resolvesFailure(failure, later));
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
                    ? "Unfinished task review detected:\n\n" +
                        "ACTION REQUIRED:\n" +
                        "1. The current user explicitly requested continued work.\n" +
                        "2. Perform another substantive review after the latest change, and run any explicitly requested checks before claiming completion.\n" +
                        "3. If blocked, explain the concrete blocker and remaining work instead of repeating a failing command."
                    : "Unresolved command failure detected:\n\n" +
                        "ACTION REQUIRED:\n" +
                        "1. A concrete execution failed and remains unresolved.\n" +
                        "2. Investigate the failure and correct it before stopping.\n" +
                        "3. If progress is genuinely blocked by missing permission, credentials, or required user input, report that concrete blocker instead of claiming completion or repeating the same failing action.",
            } : {}),
        };
    },
};
