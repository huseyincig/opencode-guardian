import { calculateProductFingerprint, latestEvidence } from "../evidence.js";
import { sanitizeProseForInspection } from "../prose.js";
import { getClaimPatterns, isUncertaintyClaim } from "../locale-intents.js";
const CLAIM_PATTERNS = getClaimPatterns();
function sentenceAround(text, index) {
    const left = Math.max(text.lastIndexOf(".", index - 1), text.lastIndexOf("\n", index - 1), text.lastIndexOf("!", index - 1), text.lastIndexOf("?", index - 1));
    const candidates = [
        text.indexOf(".", index),
        text.indexOf("\n", index),
        text.indexOf("!", index),
        text.indexOf("?", index),
    ].filter((value) => value >= 0);
    const right = candidates.length > 0 ? Math.min(...candidates) : text.length;
    return text.slice(left + 1, right + 1).replace(/\s+/g, " ").trim();
}
function latestMutationSequence(evidence) {
    const relevant = evidence?.fileMutations.filter((record) => record.status !== "failure") ?? [];
    if (relevant.length === 0)
        return -1;
    return Math.max(...relevant.map((record) => record.sequence));
}
function staleAfterMutation(evidence, record, directory) {
    if (!record)
        return false;
    if (latestMutationSequence(evidence) > record.sequence) {
        return true;
    }
    if (record.stateFingerprint?.startsWith("sha256:")) {
        const files = record.snapshotFiles?.length ? record.snapshotFiles : evidence?.mutatedFiles;
        if (!directory || !files || (Array.isArray(files) ? !files.length : !files.size))
            return true;
        const fp = calculateProductFingerprint(directory, files);
        if (fp === "unverified-state" || `sha256:${fp}` !== record.stateFingerprint) {
            return true;
        }
    }
    return false;
}
function lastRelevantVerification(evidence, directory) {
    if (!evidence)
        return undefined;
    const relevant = new Set(["test", "build", "typecheck", "lint"]);
    const record = evidence.records
        .filter((candidate) => relevant.has(candidate.kind))
        .sort((a, b) => b.sequence - a.sequence)[0];
    return staleAfterMutation(evidence, record, directory) ? undefined : record;
}
function gitStatusSemanticEvidence(record) {
    if (!record)
        return undefined;
    if (record.status === "failure")
        return record;
    if (record.status !== "success")
        return undefined;
    const output = (record.output ?? "").trim();
    if (/nothing to commit, working tree clean/i.test(output)) {
        return { ...record, status: "success" };
    }
    if (record.command &&
        /(?:--short|-s\b|--porcelain(?:=\S+)?)/.test(record.command)) {
        const lines = output
            .split(/\r?\n/)
            .map((line) => line.trimEnd())
            .filter(Boolean);
        const nonBranch = lines.filter((line) => !line.startsWith("## "));
        return {
            ...record,
            status: nonBranch.length === 0 ? "success" : "failure",
        };
    }
    if (/(?:^|\n)\s*(?:modified:|deleted:|new file:|untracked files:|changes not staged for commit:|changes to be committed:)/i.test(output)) {
        return { ...record, status: "failure" };
    }
    return undefined;
}
function evidenceForClaim(pattern, evidence, directory) {
    if (pattern.mode === "verification") {
        const verification = lastRelevantVerification(evidence, directory);
        // A generic "bug fixed" statement cannot safely be contradicted by an
        // unrelated failing lint/test/build. Successful verification supports it;
        // otherwise keep the finding advisory unless strict mode is configured.
        return verification?.status === "success" ? verification : undefined;
    }
    if (!pattern.kind)
        return undefined;
    const record = latestEvidence(evidence, pattern.kind);
    if (record?.ambiguousOutcome) {
        return { ...record, status: "unknown" };
    }
    if (pattern.kind === "git-status") {
        if (staleAfterMutation(evidence, record, directory))
            return undefined;
        return gitStatusSemanticEvidence(record);
    }
    if (["test", "build", "typecheck", "lint", "audit", "git-push"].includes(pattern.kind) &&
        staleAfterMutation(evidence, record, directory)) {
        return undefined;
    }
    return record;
}
function evidenceSummary(record) {
    const subject = record.command ?? record.toolName;
    const exit = record.exitCode === undefined ? "" : ` (exit ${record.exitCode})`;
    return `${record.kind}: ${record.status} via ${subject}${exit}`;
}
export const noUnverifiedClaimsRule = {
    id: "integrity/no-unverified-claims",
    description: "Correlates concrete success/completion claims with tool evidence and blocks claims that directly contradict the observed result.",
    inspect: (context) => {
        const findings = [];
        const contradictions = [];
        const strict = context.ruleConfig.blockUnverified === true;
        for (const message of context.currentTurn) {
            if (message.info.role !== "assistant")
                continue;
            for (const part of message.parts) {
                if (part.type !== "text" || typeof part.text !== "string")
                    continue;
                const text = sanitizeProseForInspection(part.text);
                if (!text)
                    continue;
                for (const claim of CLAIM_PATTERNS) {
                    claim.regex.lastIndex = 0;
                    const match = claim.regex.exec(text);
                    if (!match)
                        continue;
                    const sentence = sentenceAround(text, match.index);
                    if (isUncertaintyClaim(sentence))
                        continue;
                    const evidence = evidenceForClaim(claim, context.evidence, context.directory);
                    if (evidence?.status === "success")
                        continue;
                    const finding = {
                        ruleId: "integrity/no-unverified-claims",
                        pattern: claim.name,
                        messageSnippet: sentence || match[0],
                        description: evidence?.status === "failure"
                            ? `Claim contradicts the latest ${evidence.kind} result`
                            : `Claim has no matching verification evidence in this turn`,
                        evidence: evidence ? [evidenceSummary(evidence)] : [],
                        confidence: evidence?.status === "failure" ? "high" : "medium",
                    };
                    findings.push(finding);
                    if (evidence?.status === "failure")
                        contradictions.push(finding);
                }
            }
        }
        if (findings.length === 0) {
            return {
                ruleId: "integrity/no-unverified-claims",
                decision: "pass",
                findings: [],
            };
        }
        if (contradictions.length === 0 && !strict) {
            return {
                ruleId: "integrity/no-unverified-claims",
                decision: "pass",
                findings,
            };
        }
        const blocking = contradictions.length > 0 ? contradictions : findings;
        const list = blocking
            .map((finding) => {
            const evidence = finding.evidence?.length
                ? ` Evidence: ${finding.evidence.join("; ")}`
                : " No matching verification was observed.";
            return `  - ${finding.messageSnippet} — ${finding.description}.${evidence}`;
        })
            .join("\n");
        return {
            ruleId: "integrity/no-unverified-claims",
            decision: "block",
            findings,
            remediationPrompt: `Unsupported or contradictory completion claim detected:\n${list}\n\n` +
                `State only what the available tool evidence supports. If verification was not possible, say that explicitly instead of presenting it as completed or passing.`,
        };
    },
};
