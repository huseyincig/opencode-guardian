import type {
  EvidenceKind,
  EvidenceRecord,
  GuardRule,
  RuleFinding,
  RuleResult,
  TurnEvidence,
  TurnInspectionContext,
} from "../types.js";
import { calculateProductFingerprint, latestEvidence } from "../evidence.js";
import { sanitizeProseForInspection } from "../prose.js";
import { extractTaskContract } from "../task-contract.js";

import { getClaimPatterns, isUncertaintyClaim, type AdvisoryClaimPattern } from "../locale-intents.js";

type ClaimPattern = AdvisoryClaimPattern;

const CLAIM_PATTERNS: ClaimPattern[] = getClaimPatterns();

function sentenceAround(text: string, index: number): string {
  const left = Math.max(
    text.lastIndexOf(".", index - 1),
    text.lastIndexOf("\n", index - 1),
    text.lastIndexOf("!", index - 1),
    text.lastIndexOf("?", index - 1)
  );
  const candidates = [
    text.indexOf(".", index),
    text.indexOf("\n", index),
    text.indexOf("!", index),
    text.indexOf("?", index),
  ].filter((value) => value >= 0);
  const right = candidates.length > 0 ? Math.min(...candidates) : text.length;
  return text.slice(left + 1, right + 1).replace(/\s+/g, " ").trim();
}

function latestMutationSequence(
  evidence: TurnEvidence | undefined
): number {
  const relevant = evidence?.fileMutations.filter(
    (record) => record.status !== "failure"
  ) ?? [];
  if (relevant.length === 0) return -1;
  return Math.max(...relevant.map((record) => record.sequence));
}

function staleAfterMutation(
  evidence: TurnEvidence | undefined,
  record: EvidenceRecord | undefined,
  directory?: string
): boolean {
  if (!record) return false;
  const lastMutation = latestMutationSequence(evidence);
  if (lastMutation >= 0 && lastMutation >= record.sequence) {
    return true;
  }
  if (record.stateFingerprint === "unverified-state") {
    return true;
  }
  if (record.stateFingerprint?.startsWith("sha256:")) {
    const files = record.snapshotFiles?.length ? record.snapshotFiles : evidence?.mutatedFiles;
    if (!directory || !files || (Array.isArray(files) ? !files.length : !files.size)) return true;
    const fp = calculateProductFingerprint(directory, files);
    if (fp === "unverified-state" || `sha256:${fp}` !== record.stateFingerprint) {
      return true;
    }
  }
  return false;
}

function lastRelevantVerification(
  evidence: TurnEvidence | undefined,
  directory?: string
): EvidenceRecord | undefined {
  if (!evidence) return undefined;
  const relevant = new Set<EvidenceKind>(["test", "build", "typecheck", "lint"]);
  const record = evidence.records
    .filter((candidate) => relevant.has(candidate.kind))
    .sort((a, b) => b.sequence - a.sequence)[0];
  return staleAfterMutation(evidence, record, directory) ? undefined : record;
}

function gitStatusSemanticEvidence(
  record: EvidenceRecord | undefined
): EvidenceRecord | undefined {
  if (!record) return undefined;
  if (record.status === "failure") return record;
  if (record.status !== "success") return undefined;
  const output = (record.output ?? "").trim();

  if (/nothing to commit, working tree clean/i.test(output)) {
    return { ...record, status: "success" };
  }

  if (
    record.command &&
    /(?:--short|-s\b|--porcelain(?:=\S+)?)/.test(record.command)
  ) {
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

function evidenceForClaim(
  pattern: ClaimPattern,
  evidence: TurnEvidence | undefined,
  directory?: string
): EvidenceRecord | undefined {
  if (pattern.mode === "verification") {
    const verification = lastRelevantVerification(evidence, directory);
    // A generic "bug fixed" statement cannot safely be contradicted by an
    // unrelated failing lint/test/build. Successful verification supports it;
    // otherwise keep the finding advisory unless strict mode is configured.
    return verification?.status === "success" ? verification : undefined;
  }
  if (!pattern.kind) return undefined;

  const record = latestEvidence(evidence, pattern.kind);
  if (record?.ambiguousOutcome) {
    return { ...record, status: "unknown" };
  }
  if (pattern.kind === "git-status") {
    if (staleAfterMutation(evidence, record, directory)) return undefined;
    return gitStatusSemanticEvidence(record);
  }
  if (
    ["test", "build", "typecheck", "lint", "audit", "git-push"].includes(
      pattern.kind
    ) &&
    staleAfterMutation(evidence, record, directory)
  ) {
    return undefined;
  }

  return record;
}

function evidenceSummary(record: EvidenceRecord): string {
  const subject = record.command ?? record.toolName;
  const exit =
    record.exitCode === undefined ? "" : ` (exit ${record.exitCode})`;
  return `${record.kind}: ${record.status} via ${subject}${exit}`;
}

export const noUnverifiedClaimsRule: GuardRule = {
  id: "integrity/no-unverified-claims",
  description:
    "Correlates concrete success/completion claims with tool evidence and blocks claims that directly contradict the observed result.",
  inspect: (context: TurnInspectionContext): RuleResult => {
    const findings: RuleFinding[] = [];
    const contradictions: RuleFinding[] = [];
    const strict = context.ruleConfig.blockUnverified === true;

    for (const message of context.currentTurn) {
      if (message.info.role !== "assistant") continue;

      for (const part of message.parts) {
        if (part.type !== "text" || typeof part.text !== "string") continue;
        const text = sanitizeProseForInspection(part.text, { preserveParagraphs: true });
        if (!text) continue;

        // Compare explicit pass-count claims only to fresh, matching test evidence.
        const testRecord = latestEvidence(context.evidence, "test");
        const counts = testRecord?.testSummary;
        if (counts && !staleAfterMutation(context.evidence, testRecord, context.directory)) {
          for (const countClaim of text.matchAll(/\b(?:all\s+)?(\d+)\s+(?:tests?\s+(?:passed|passing)|passed\s+tests?)\b/gi)) {
            const sentence = sentenceAround(text, countClaim.index);
            if (isUncertaintyClaim(sentence) || /\b(?:before|previously|earlier|expected|would|will|should)\b/i.test(sentence)) continue;
            if (Number(countClaim[1]) === counts.passed) continue;
            const finding: RuleFinding = {
              ruleId: "integrity/no-unverified-claims", pattern: "test count contradicts observed summary", messageSnippet: sentence,
              description: `Claimed ${countClaim[1]} passed tests; observed ${counts.passed} passed, ${counts.skipped} skipped and ${counts.failed} failed`,
              confidence: "high",
            };
            findings.push(finding);
            contradictions.push(finding);
          }
        }

        for (const claim of CLAIM_PATTERNS) {
          const flags = claim.regex.flags.includes("g") ? claim.regex.flags : `${claim.regex.flags}g`;
          const globalRegex = new RegExp(claim.regex.source, flags);
          let iterations = 0;
          let matchedFinding = false;
          let match = globalRegex.exec(text);
          while (match !== null && iterations < 64) {
            iterations++;
            const sentence = sentenceAround(text, match.index);
            if (!isUncertaintyClaim(sentence)) {
              const evidence = evidenceForClaim(claim, context.evidence, context.directory);
              if (evidence?.status === "success") {
                matchedFinding = true;
                break;
              }
              const finding: RuleFinding = {
                ruleId: "integrity/no-unverified-claims",
                pattern: claim.name,
                messageSnippet: sentence || match[0],
                description:
                  evidence?.status === "failure"
                    ? `Claim contradicts the latest ${evidence.kind} result`
                    : `Claim has no matching verification evidence in this turn`,
                evidence: evidence ? [evidenceSummary(evidence)] : [],
                confidence: evidence?.status === "failure" ? "high" : "medium",
              };
              findings.push(finding);
              if (evidence?.status === "failure") contradictions.push(finding);
              matchedFinding = true;
              break;
            }
            if (match[0].length === 0) globalRegex.lastIndex++;
            match = globalRegex.exec(text);
          }
          if (matchedFinding) continue;
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

    const prohibited = extractTaskContract(context.currentTurn, context.sessionID)?.prohibitedVerifications ?? [];
    const step2 = prohibited.length > 0
      ? `2. Do NOT run verification commands explicitly prohibited by the user (${prohibited.join(", ")}); instead retract any unverified pass claim and report only observed results.`
      : `2. Run the actual verification command (e.g. tests, typecheck, build) to produce concrete evidence before claiming success.`;

    return {
      ruleId: "integrity/no-unverified-claims",
      decision: "block",
      findings,
      remediationPrompt:
        `Unsupported or contradictory completion claim detected:\n${list}\n\n` +
        `ACTION REQUIRED:\n` +
        `1. State only what actual command/test tool output proves. Do not claim tests passed or work succeeded without executing verification commands.\n` +
        `${step2}\n` +
        `3. If verification was not possible, say so explicitly and explain what was verified and what remains unverified.`,
    };
  },
};
