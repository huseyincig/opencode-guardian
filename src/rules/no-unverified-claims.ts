import type {
  EvidenceKind,
  EvidenceRecord,
  GuardRule,
  RuleFinding,
  RuleResult,
  TurnEvidence,
  TurnInspectionContext,
} from "../types.js";
import { isVerificationSnapshotCurrent, latestEvidence } from "../evidence.js";
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

function isNonCompiledJsTestOnlyShellMutation(command: string | undefined): boolean {
  if (!command) return false;
  const trimmed = command.trim();
  // Recognize pure in-place `perl -pi` / `sed -i` commands whose target file arguments are ALL `.test.mjs`/`.spec.js` etc.
  const withoutCd = trimmed.replace(/^(?:cd\s+(?:"[^"]*"|'[^']*'|\S+)\s*&&\s*)+/i, "").trim();
  if (/[;&|\n\x60$<>]/.test(withoutCd)) return false;
  const tokens = withoutCd.match(/"(?:\\.|[^"\\])*"|'[^']*'|\S+/g) ?? [];
  if (tokens.length < 3) return false;
  const bin = (tokens[0] ?? "").toLowerCase();
  if (bin !== "perl" && bin !== "sed") return false;
  const files: string[] = [];
  let skipNext = false;
  for (let i = 1; i < tokens.length; i++) {
    const tok = tokens[i]!;
    if (skipNext) {
      skipNext = false;
      continue;
    }
    if (tok === "-e" || tok === "-E" || tok === "-f" || tok === "-i") {
      if (tok === "-e" || tok === "-E" || tok === "-f") skipNext = true;
      continue;
    }
    if (tok.startsWith("-")) continue;
    const unquoted =
      (tok.startsWith('"') && tok.endsWith('"')) || (tok.startsWith("'") && tok.endsWith("'"))
        ? tok.slice(1, -1)
        : tok;
    // Skip inline sed expression if `-e` was omitted (first non-flag arg for `sed`).
    if (bin === "sed" && files.length === 0 && !/\.(?:[cm]?[jt]sx?|json|md)$/i.test(unquoted)) {
      continue;
    }
    files.push(unquoted);
  }
  return files.length > 0 && files.every((f) => /\.(?:test|spec)\.[cm]?js$/i.test(f));
}

function latestMutationSequence(
  evidence: TurnEvidence | undefined,
  ignoreNonCompiledJsTestFiles = false
): number {
  const relevant = (evidence?.fileMutations ?? []).filter((record) => {
    if (record.status === "failure") return false;
    if (ignoreNonCompiledJsTestFiles) {
      if (typeof record.filePath === "string" && /\.(?:test|spec)\.[cm]?js$/i.test(record.filePath)) {
        return false;
      }
      if (!record.filePath && isNonCompiledJsTestOnlyShellMutation(record.command)) {
        return false;
      }
    }
    return true;
  });
  if (relevant.length === 0) return -1;
  return Math.max(...relevant.map((record) => record.sequence));
}

function staleAfterMutation(
  evidence: TurnEvidence | undefined,
  record: EvidenceRecord | undefined,
  directory?: string
): boolean {
  if (!record) return false;
  // Non-compiled `.test.mjs`/`.test.js` edits invalidate test runs, not compiled `tsc`/`npm run build` outputs.
  const ignoreNonCompiledTests = record.kind === "build" || record.kind === "typecheck";
  const lastMutation = latestMutationSequence(evidence, ignoreNonCompiledTests);
  if (lastMutation >= 0 && lastMutation >= record.sequence) {
    return true;
  }
  if (!ignoreNonCompiledTests && !isVerificationSnapshotCurrent(record, evidence, directory)) {
    return true;
  }
  if (ignoreNonCompiledTests && record.stateFingerprint?.startsWith("sha256:")) {
    const files = (record.snapshotFiles?.length ? record.snapshotFiles : [...(evidence?.mutatedFiles ?? [])]).filter(
      (f) => !/\.(?:test|spec)\.[cm]?js$/i.test(f)
    );
    if (files.length > 0 && !isVerificationSnapshotCurrent({ ...record, snapshotFiles: files }, evidence, directory)) {
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
    const isPorcelainV2 = /--porcelain=(?:2|v2)\b/i.test(record.command);
    const lines = output
      .split(/\r?\n/)
      .map((line) => line.trimEnd())
      .filter((line) => {
        if (!line) return false;
        // Ignore branch headers (`## main...origin/main`) and host harness trailers (`[task bash-...]`, `[exit code: 0]`).
        if (line.startsWith("## ") || line.startsWith("# branch.")) return false;
        if (/^\[(?:task\s+[^\]]+|exit\s+code:\s*\d+)\]$/.test(line.trim())) return false;
        return true;
      });
    // Recognize genuine git status porcelain entries only so compound commands like
    // `git status --short --branch && echo '---LOG---' && git log --oneline -12`
    // do not misclassify git-log hashes or divider lines as dirty working-tree files.
    const dirtyLines = lines.filter((line) =>
      isPorcelainV2
        ? /^(?:[12u]\s|[?]\s|!\s)/.test(line)
        : /^(?:[MTADRCU?!][ MTADRCU?!]| [MTADRCU?!])\s+\S/.test(line)
    );
    return {
      ...record,
      status: dirtyLines.length === 0 ? "success" : "failure",
    };
  }

  if (/(?:^|\n)\s*(?:modified:|deleted:|new file:|untracked files:|changes not staged for commit:|changes to be committed:)/i.test(output)) {
    return { ...record, status: "failure" };
  }

  return undefined;
}

function hasSupportingSubagentVerification(
  currentTurn: TurnInspectionContext["currentTurn"],
  messageIndex: number,
  kind: EvidenceKind | undefined
): boolean {
  if (!kind || !["test", "build", "typecheck", "lint", "audit"].includes(kind)) return false;
  const passSignal =
    /\b(?:pass(?:ed|es|ing)?|0\s+fail(?:ed|ures?)?|exit\s+0|clean|green|no\s+errors?|0\s+errors?|0\s+vulnerabilit(?:y|ies))\b|(?<!\p{L})(?:geçti|başarılı|temiz|sorun\s+yok)(?!\p{L})/iu;
  const kindMatches = (text: string): boolean => {
    switch (kind) {
      case "test":
        return /\b(?:tests?|suites?|specs?|pytest|vitest|jest|node\s+--test)\b|(?<!\p{L})test(?:ler)?(?!\p{L})/iu.test(text);
      case "typecheck":
        return /\b(?:type\s*-?check(?:ing)?|tsc|mypy|pyright)\b/i.test(text);
      case "build":
        return /\b(?:build|dist|compile[ds]?)\b|(?<!\p{L})derleme(?!\p{L})/iu.test(text);
      case "lint":
        return /\b(?:lint(?:ing)?|oxlint|eslint|ruff|clippy)\b/i.test(text);
      case "audit":
        return /\b(?:audit|vulnerabilit(?:y|ies))\b/i.test(text);
      default:
        return false;
    }
  };

  let lastSupportingSubagentIdx = -1;
  for (let i = 0; i <= messageIndex && i < currentTurn.length; i++) {
    const msg = currentTurn[i]!;
    for (const part of msg.parts) {
      let text = "";
      if (part.type === "tool" && part.state?.status === "completed") {
        const name = (typeof part.tool === "string" ? part.tool : typeof part.name === "string" ? part.name : "").toLowerCase();
        if (name === "subagent" || name === "task") {
          text = typeof part.state.output === "string" ? part.state.output : "";
        }
      } else if (part.type === "text" && typeof part.text === "string") {
        const meta = (part as { metadata?: Record<string, unknown> }).metadata;
        const isSubagentNotice =
          meta?.source === "subagent" ||
          /<(?:background-result|task-result|subagent)\b/i.test(part.text);
        if (isSubagentNotice) {
          text = part.text;
        }
      }
      if (text && passSignal.test(text) && kindMatches(text)) {
        lastSupportingSubagentIdx = i;
      }
    }
  }
  if (lastSupportingSubagentIdx < 0) return false;

  // Ensure no local file-mutation tool ran AFTER the supporting subagent result and BEFORE this message.
  for (let i = lastSupportingSubagentIdx + 1; i <= messageIndex && i < currentTurn.length; i++) {
    const msg = currentTurn[i]!;
    if (msg.info.role !== "assistant") continue;
    for (const part of msg.parts) {
      if (part.type !== "tool" || part.state?.status === "error") continue;
      const name = (typeof part.tool === "string" ? part.tool : typeof part.name === "string" ? part.name : "").toLowerCase();
      if (/^(?:write|edit|patch|apply_patch|multiedit|multi_edit|replace_file_content|write_to_file|create_file|delete_file)$/.test(name)) {
        return false;
      }
    }
  }
  return true;
}

function hasScopedSubsetTestSupport(
  sentence: string,
  fullMessageText: string,
  evidence: TurnEvidence | undefined,
  directory?: string
): boolean {
  if (!evidence) return false;
  // Never treat universal claims ("all tests pass", "entire test suite passes", "tüm testler geçti") as scoped subsets.
  if (/\b(?:all(?:\s+of)?(?:\s+the)?|entire|full|whole)\s+tests?\b|\btest\s+suite\b|(?<!\p{L})tüm\s+testler(?!\p{L})/iu.test(sentence)) {
    return false;
  }
  const freshPassingTests = evidence.records.filter(
    (r) => r.kind === "test" && r.status === "success" && !staleAfterMutation(evidence, r, directory)
  );
  if (freshPassingTests.length === 0) return false;
  const countMatch = /\b(\d+)\s+(?:[\w/-]+\s+){0,3}tests?\s+(?:all\s+)?(?:pass(?:ed|es|ing)?|succeed(?:ed|s)?)\b/i.exec(sentence);
  const matchingPass = countMatch?.[1]
    ? freshPassingTests.find((r) => r.testSummary?.passed === Number(countMatch[1]))
    : freshPassingTests[freshPassingTests.length - 1];
  if (!matchingPass) return false;

  // If any later test run failed (either status=failure or testSummary.failed > 0),
  // require transparent disclosure of failures in the same message.
  const hasLaterFailure = evidence.records.some(
    (r) =>
      r.kind === "test" &&
      r.sequence > matchingPass.sequence &&
      (r.status === "failure" || (r.testSummary?.failed ?? 0) > 0)
  );
  if (hasLaterFailure) {
    const disclosesFailure =
      /\b(?:fail(?:s|ed|ing|ures?)?|broken)\b|(?<!\p{L})(?:başarısız|hata\s+ver|fail)(?!\p{L})/iu.test(fullMessageText);
    if (!disclosesFailure) return false;
  }
  return true;
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
    const taskContract = extractTaskContract(context.currentTurn, context.sessionID);
    const prohibited = taskContract?.prohibitedVerifications ?? [];
    const requiredVerifications = taskContract?.requiredVerifications ?? [];
    const codeVerifProhibited =
      prohibited.some((k) => k === "test" || k === "build" || k === "typecheck" || k === "lint") &&
      requiredVerifications.length === 0;
    const latestCodeVerification = lastRelevantVerification(context.evidence, context.directory);

    for (let msgIdx = 0; msgIdx < context.currentTurn.length; msgIdx++) {
      const message = context.currentTurn[msgIdx]!;
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

        // Explicit honest disclosure that verification was intentionally not run / delegated to manager.
        const explicitlyDisclosesUnverified =
          /\b(?:did\s+not\s+run|didn't\s+run|have\s+not\s+run|haven't\s+run|not\s+run|no\s+(?:tests?|checks?|verification)\s+(?:were\s+)?run|left\s+(?:verification|testing)\s+to|leaving\s+(?:verification|testing)\s+to|delegat(?:ed|ing)\s+(?:verification|testing)\s+to|not\s+verified)\b|(?<!\p{L})(?:çalıştırmadım|çalıştırılmadı|doğrulanmadı|doğrulamayı\s+(?:yöneticiye|managere)\s+(?:bıraktım|devrediyorum|devrettim))(?!\p{L})/iu.test(
            text
          );

        for (const claim of CLAIM_PATTERNS) {
          const flags = claim.regex.flags.includes("g") ? claim.regex.flags : `${claim.regex.flags}g`;
          const globalRegex = new RegExp(claim.regex.source, flags);
          let iterations = 0;
          let matchedFinding = false;
          let match = globalRegex.exec(text);
          while (match !== null && iterations < 64) {
            iterations++;
            const sentence = sentenceAround(text, match.index);
            const isHistoricalReference =
              /\b(?:earlier\s+report|previous\s+report|previously\s+reported)\b/i.test(sentence);
            if (!isUncertaintyClaim(sentence) && !isHistoricalReference) {
              const evidence = evidenceForClaim(claim, context.evidence, context.directory);
              if (evidence?.status === "success") {
                matchedFinding = true;
                break;
              }
              if (
                claim.kind === "test" &&
                evidence?.status !== "failure" &&
                hasScopedSubsetTestSupport(sentence, text, context.evidence, context.directory)
              ) {
                matchedFinding = true;
                break;
              }
              // Explicit partial pass report (`781 of 786 targeted tests pass`, `356/359 tests pass` where X < Y)
              // transparently discloses failures rather than claiming full test success.
              if (claim.kind === "test" && evidence?.status !== "failure") {
                const partialCount = /\b(\d+)\s*(?:of|\/)\s*(\d+)\b/i.exec(sentence);
                if (partialCount?.[1] && partialCount[2] && Number(partialCount[1]) < Number(partialCount[2])) {
                  matchedFinding = true;
                  break;
                }
              }
              if (
                !strict &&
                !evidence &&
                hasSupportingSubagentVerification(context.currentTurn, msgIdx, claim.kind)
              ) {
                matchedFinding = true;
                break;
              }
              // When the user explicitly prohibited/delegated code verification OR the assistant
              // transparently discloses in the same message that verification was not run (with no
              // failed verification observed), do not warn on generic fix statements ("fixed"/"resolved").
              // Explicit pass claims ("all tests passed") and failed verification runs are ALWAYS flagged.
              if (
                claim.mode === "verification" &&
                !evidence &&
                (codeVerifProhibited || explicitlyDisclosesUnverified) &&
                latestCodeVerification?.status !== "failure"
              ) {
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
