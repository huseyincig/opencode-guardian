import type {
  GuardRule,
  RuleFinding,
  RuleResult,
  TurnInspectionContext,
} from "../types.js";
import {
  extractLikelyShellMutation,
  extractStructuredEditTexts,
  extractToolCommand,
} from "../tool-input.js";
import { isAuthorizedTestEdit, isTestBypassProhibited, isSpecificTestBypassAuthorized } from "../locale-intents.js";
import { currentHumanMessage } from "../task-contract.js";

/**
 * High-confidence patterns that directly disable or bypass tests.
 */
export const TEST_CHEAT_PATTERNS: { regex: RegExp; name: string; alwaysBlock?: boolean }[] = [
  {
    regex: /\b(?:test|it|describe)\.skip\s*\(/,
    name: "test.skip() / it.skip() (JS/TS)",
  },
  {
    regex: /\b(?:xit|xtest)\s*\(/,
    name: "xit() / xtest() skipped test (JS/TS)",
  },
  {
    regex: /\b(?:test|it|describe)\.only\s*\(/,
    name: "test.only() / it.only() focus filter (JS/TS)",
  },
  {
    regex: /\btest\.todo\s*\(/,
    name: "test.todo() downgrade (JS/TS)",
  },
  {
    regex: /@pytest\.mark\.skip(?:\s*\(.*\))?/,
    name: "@pytest.mark.skip decorator (Python)",
  },
  {
    regex: /\bpytest\.skip\s*\(/,
    name: "pytest.skip() call (Python)",
  },
  {
    regex: /@unittest\.skip(?:\s*\(.*\))?/,
    name: "@unittest.skip decorator (Python)",
  },
  {
    regex: /\bt\.Skip(?:f|now)?\s*\(/,
    name: "t.Skip() call (Go)",
  },
  {
    regex: /#\[ignore(?:\s*\(.*\))?\]/,
    name: "#[ignore] test attribute (Rust)",
  },
  {
    regex: /(?:\/\/|#)\s*(?:expect\s*\(|assert(?:\.|\s*\()|self\.assert)/,
    name: "commented-out assertion (expect / assert)",
  },
  {
    regex: /\b(?:test|it)\s*\(\s*["'`][^"'`]+["'`]\s*,\s*(?:async\s*)?(?:(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*|function\s*\([^)]*\)\s*)\{\s*(?:\/\/[^\n]*(?:\n|$)|\/\*[\s\S]*?\*\/|\s)*\}/,
    name: "empty test block without assertions (JS/TS)",
    alwaysBlock: true,
  },
  {
    regex: /def\s+test_\w+\s*\([^)]*\)\s*:\s*(?:#[^\n]*\n\s*)*(?:pass|\.\.\.|return)\s*(?:\n|$)(?!\s+[a-zA-Z])/,
    name: "empty def test_...: pass without assertions (Python)",
    alwaysBlock: true,
  },
];

function isTestFilePath(filePath?: string): boolean {
  if (!filePath) return false;
  const lower = filePath.toLowerCase().replace(/\\/g, "/");
  const base = lower.split("/").pop() ?? lower;
  return (
    lower.includes(".test.") ||
    lower.includes(".spec.") ||
    lower.includes("_test.") ||
    lower.includes("/tests/") ||
    lower.includes("/test/") ||
    base.startsWith("test_")
  );
}

function isCiFilePath(filePath?: string): boolean {
  if (!filePath) return false;
  const lower = filePath.toLowerCase().replace(/\\/g, "/");
  return (
    lower.startsWith(".github/workflows/") ||
    lower.includes("/.github/workflows/") ||
    lower === ".gitlab-ci.yml" ||
    lower.endsWith("/.gitlab-ci.yml") ||
    lower === ".gitlab-ci.yaml" ||
    lower.endsWith("/.gitlab-ci.yaml") ||
    lower === ".circleci/config.yml" ||
    lower.endsWith("/.circleci/config.yml")
  );
}

function hasTestContext(code: string): boolean {
  return /\b(?:describe|it|test|suite)\s*\(|def\s+test_|func\s+Test|#\[test\]/.test(
    code
  );
}

function extractFilePathFromPatch(patch: unknown): string | undefined {
  if (typeof patch !== "string") return undefined;
  const match = patch.match(/\+\+\+\s+(?:b\/)?([^\s\t\n]+)/);
  if (match && match[1] !== "/dev/null") return match[1];
  const oldMatch = patch.match(/---\s+(?:a\/)?([^\s\t\n]+)/);
  return oldMatch && oldMatch[1] !== "/dev/null" ? oldMatch[1] : undefined;
}

function extractAddedLines(text: unknown): string {
  if (typeof text !== "string") return "";
  return text
    .split("\n")
    .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
    .map((line) => line.slice(1))
    .join("\n");
}

function extractRemovedLines(text: unknown): string {
  if (typeof text !== "string") return "";
  return text
    .split("\n")
    .filter((line) => line.startsWith("-") && !line.startsWith("---"))
    .map((line) => line.slice(1))
    .join("\n");
}

function extractSnippet(text: string, matchIndex: number, matchLen: number): string {
  const maxPerSide = 80;
  const start = Math.max(0, matchIndex - maxPerSide);
  const end = Math.min(text.length, matchIndex + matchLen + maxPerSide);

  let snippet = text
    .slice(start, end)
    .replace(/\r?\n/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (start > 0) snippet = `…${snippet}`;
  if (end < text.length) snippet = `${snippet}…`;
  return snippet;
}

const STRONG_ASSERTION =
  /\b(?:expect\s*\([^\n]+\)\.(?:toBe|toEqual|toStrictEqual|toMatchObject|toHaveLength|toContain|toThrow)|assert\.(?:strictEqual|deepEqual|equal|match|throws)\s*\(|self\.assert(?:Equal|True|False|In|Raises)\s*\(|assert\s+[^\n]+(?:==|!=|<=|>=|\sin\s))/i;

const WEAK_ASSERTION =
  /\b(?:expect\s*\([^\n]+\)\.(?:toBeTruthy|toBeDefined|not\.toBeNull)|assert\.ok\s*\(|assert\s+[A-Za-z_$][\w.$]*\s*$)/im;

function detectAssertionWeakening(
  patch: string,
  filePath: string | undefined
): RuleFinding | undefined {
  if (!isTestFilePath(filePath)) return undefined;

  const hunks = patch.includes("@@")
    ? patch.split(/^@@.*$/m).slice(1)
    : [patch];

  for (const hunk of hunks) {
    const removed = extractRemovedLines(hunk);
    const added = extractAddedLines(hunk);
    if (!STRONG_ASSERTION.test(removed) || !WEAK_ASSERTION.test(added)) {
      continue;
    }

    return {
      ruleId: "testing/no-cheat",
      pattern: "assertion weakened",
      messageSnippet: `removed: ${removed.replace(/\s+/g, " ").slice(0, 120)} | added: ${added.replace(/\s+/g, " ").slice(0, 120)}`,
      description:
        "A specific assertion was replaced with a materially weaker truthiness/existence assertion in the same patch hunk",
      confidence: "high",
      ...(filePath ? {
        filePath,
        fingerprint: `${filePath}:assertion weakened:${removed.replace(/\s+/g, " ").trim()}=>${added.replace(/\s+/g, " ").trim()}`,
      } : {}),
    };
  }

  return undefined;
}

function coverageValues(lines: string[]): Map<string, number[]> {
  const values = new Map<string, number[]>();
  const keyPattern =
    /\b(fail-under|threshold|branches|functions|statements|lines)\b\s*[:=]?\s*(\d+(?:\.\d+)?)/gi;

  for (const line of lines) {
    for (const match of line.matchAll(keyPattern)) {
      const rawKey = match[1];
      const rawValue = match[2];
      if (!rawKey || rawValue === undefined) continue;
      const key = rawKey.toLowerCase();
      const value = Number(rawValue);
      if (!Number.isFinite(value)) continue;
      const current = values.get(key) ?? [];
      current.push(value);
      values.set(key, current);
    }
  }

  return values;
}

function detectCoverageReduction(
  patch: string,
  filePath?: string
): RuleFinding | undefined {
  const before = coverageValues(extractRemovedLines(patch).split("\n"));
  const after = coverageValues(extractAddedLines(patch).split("\n"));

  for (const [key, beforeValues] of before) {
    const afterValues = after.get(key);
    if (!afterValues?.length) continue;

    const beforeMax = Math.max(...beforeValues);
    const afterMax = Math.max(...afterValues);
    if (afterMax >= beforeMax) continue;

    return {
      ruleId: "testing/no-cheat",
      pattern: "coverage threshold reduced",
      messageSnippet: `${key}: ${beforeMax} → ${afterMax}`,
      description: `Coverage/quality threshold "${key}" was lowered in this patch`,
      confidence: "high",
      ...(filePath ? {
        filePath,
        fingerprint: `${filePath}:coverage threshold reduced:${key}:${beforeMax}->${afterMax}`,
      } : {}),
    };
  }

  return undefined;
}

function detectsTestFileDeletion(
  input: Record<string, unknown>,
  patchRaw: unknown,
  targetFile: string | undefined
): boolean {
  const action =
    typeof input.action === "string" ? input.action.toLowerCase() : "";
  if (
    (action === "delete" || action === "remove") &&
    isTestFilePath(targetFile)
  ) {
    return true;
  }

  if (
    typeof patchRaw === "string" &&
    /\+\+\+\s+\/dev\/null/.test(patchRaw) &&
    isTestFilePath(targetFile)
  ) {
    return true;
  }

  const command = extractToolCommand(input);
  return Boolean(
    command &&
      /\b(?:rm|del|erase|remove-item)\b[^\n;&|]*(?:tests?[\\/]|\.test\.|\.spec\.|test_[^\s\\/]+\.py|_test\.)/i.test(
        command
      )
  );
}

function detectCiTestRemoval(
  patchRaw: unknown,
  targetFile: string | undefined
): RuleFinding | undefined {
  if (typeof patchRaw !== "string" || !isCiFilePath(targetFile)) {
    return undefined;
  }

  const removed = extractRemovedLines(patchRaw);
  const added = extractAddedLines(patchRaw);
  const testCommand =
    /\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test\b|\b(?:pytest|go\s+test|cargo\s+test|node\s+--test|jest|vitest)\b/i;

  if (!testCommand.test(removed) || testCommand.test(added)) return undefined;

  return {
    ruleId: "testing/no-cheat",
    pattern: "CI test step removed",
    messageSnippet: removed.replace(/\s+/g, " ").slice(0, 220),
    description:
      "A CI test command was removed without a replacement test command in the same patch",
    confidence: "high",
    ...(targetFile ? {
      filePath: targetFile,
      fingerprint: `${targetFile}:CI test step removed:${removed.replace(/\s+/g, " ").trim()}`,
    } : {}),
  };
}

function snapshotUpdateCommand(command: string): boolean {
  return (
    /\b(?:jest|vitest)\b[^\n;&|]*(?:--updateSnapshot|(?:^|\s)-u(?:\s|$))/i.test(
      command
    ) ||
    /\bpytest\b[^\n;&|]*(?:--snapshot-update|--update-snapshots)\b/i.test(
      command
    )
  );
}

export function explicitlyAuthorizedTestEdit(text?: string): boolean {
  return isAuthorizedTestEdit(text);
}

function extractUserInstruction(context: TurnInspectionContext): string {
  const messages = context.messages?.length ? context.messages : context.currentTurn;
  const human = currentHumanMessage(messages ?? []);
  if (!human) return "";
  return human.parts
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

export const noCheatRule: GuardRule = {
  id: "testing/no-cheat",
  description:
    "Prevents test bypasses including skips/focus filters, assertion weakening, test deletion, coverage reductions, and CI test removal.",
  inspect: (context: TurnInspectionContext): RuleResult => {
    const findings: RuleFinding[] = [];
    const blocking: RuleFinding[] = [];
    const seen = new Set<string>();
    const blockSnapshotUpdates =
      context.ruleConfig.blockSnapshotUpdates === true;
    const hasFailedTestEvidence = Boolean(
      context.evidence?.records.some(
        (record) => record.kind === "test" && record.status === "failure"
      )
    );
    const blockStructuralTestChanges =
      context.ruleConfig.blockStructuralTestChanges === true ||
      hasFailedTestEvidence;
    const userInstruction = extractUserInstruction(context);
    const authorizedTestModification = explicitlyAuthorizedTestEdit(userInstruction);

    const specificallyAuthorized = (finding: RuleFinding): boolean => {
      const pattern = finding.pattern;
      if (!authorizedTestModification) return false;
      // A prohibition ("do not skip") is never an authorization to skip.
      if (isTestBypassProhibited(userInstruction)) return false;
      const namedFile = / in ([\w./-]+\.(?:test|spec)\.[a-z]+)/iu.exec(finding.description)?.[1];
      const requestedFiles = userInstruction.match(/[\w./-]+\.(?:test|spec)\.[a-z]+/giu) ?? [];
      if (namedFile && requestedFiles.length &&
          !requestedFiles.some((requested) => namedFile.toLowerCase().endsWith(requested.toLowerCase()))) return false;
      // Permission to edit tests is NOT permission to bypass them. Each
      // integrity-reducing operation needs explicit authorization.
      return isSpecificTestBypassAuthorized(userInstruction, pattern);
    };

    const addFinding = (finding: RuleFinding, shouldBlock = true) => {
      const key = `${finding.pattern}:${finding.messageSnippet}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push(finding);
      if (shouldBlock && !specificallyAuthorized(finding)) blocking.push(finding);
    };

    const checkTestCode = (
      code: string,
      filePath?: string,
      directPatternsBlock = true
    ) => {
      if (!code || typeof code !== "string") return;

      const isTestFile = isTestFilePath(filePath);
      const isTestCode = isTestFile || (!filePath && hasTestContext(code));

      for (const pattern of TEST_CHEAT_PATTERNS) {
        pattern.regex.lastIndex = 0;

        if (
          pattern.name.includes("commented-out assertion") &&
          !isTestCode
        ) {
          continue;
        }
        if (filePath && !isTestFile && !hasTestContext(code)) continue;

        const match = pattern.regex.exec(code);
        if (!match) continue;

        addFinding(
          {
            ruleId: "testing/no-cheat",
            pattern: pattern.name,
            messageSnippet: extractSnippet(code, match.index, match[0].length),
            description: `Weakened test detected in ${filePath ?? "test code"}`,
            confidence: directPatternsBlock ? "high" : "medium",
            ...(filePath ? {
              filePath,
              fingerprint: `${filePath}:${pattern.name}:${match[0].trim()}`,
            } : {}),
          },
          directPatternsBlock || pattern.alwaysBlock === true
        );
      }
    };

    for (const msg of context.currentTurn) {
      if (msg.info.role !== "assistant") continue;

      for (const part of msg.parts) {
        if (part.type !== "tool" || !part.state?.input) continue;
        const input = part.state.input;
        const patchRaw = input.patchText ?? input.patch;
        const targetFile =
          (input.path as string) ??
          (input.targetFile as string) ??
          (input.filePath as string) ??
          (input.file as string) ??
          extractFilePathFromPatch(patchRaw);

        if (typeof input.content === "string") {
          // Whole-file writes may preserve pre-existing skips/ignores. Treat
          // them as advisory unless failed-test evidence or strict structural
          // mode makes the intent suspicious.
          checkTestCode(input.content, targetFile, blockStructuralTestChanges);
        }
        if (typeof input.new_string === "string") {
          checkTestCode(input.new_string, targetFile);
        }
        if (typeof input.newString === "string") {
          checkTestCode(input.newString, targetFile);
        }
        for (const edit of extractStructuredEditTexts(input, targetFile)) {
          checkTestCode(edit.text, edit.filePath);
        }

        const patchText = extractAddedLines(patchRaw);
        if (patchText) checkTestCode(patchText, targetFile);

        if (typeof patchRaw === "string") {
          const weakening = detectAssertionWeakening(patchRaw, targetFile);
          if (weakening) addFinding(weakening, blockStructuralTestChanges);

          const coverage = detectCoverageReduction(patchRaw, targetFile);
          if (coverage) addFinding(coverage, blockStructuralTestChanges);

          const ciRemoval = detectCiTestRemoval(patchRaw, targetFile);
          if (ciRemoval) addFinding(ciRemoval, blockStructuralTestChanges);
        }

        if (detectsTestFileDeletion(input, patchRaw, targetFile)) {
          addFinding(
            {
              ruleId: "testing/no-cheat",
              pattern: "test file deleted",
              messageSnippet: targetFile ?? "test file",
              description:
                "A test file was deleted; this becomes blocking when paired with failed-test evidence or strict structural-test mode",
              confidence: hasFailedTestEvidence ? "high" : "medium",
              ...(targetFile ? {
                filePath: targetFile,
                fingerprint: `${targetFile}:test file deleted`,
              } : {}),
            },
            blockStructuralTestChanges
          );
        }

        const shellMutation = extractLikelyShellMutation(input);
        if (shellMutation) {
          checkTestCode(shellMutation, targetFile, blockStructuralTestChanges);
        }

        const command = extractToolCommand(input);
        if (command && snapshotUpdateCommand(command)) {
          addFinding(
            {
              ruleId: "testing/no-cheat",
              pattern: "snapshot update",
              messageSnippet: command.replace(/\s+/g, " ").slice(0, 220),
              description:
                "Snapshots were regenerated; review that the changed behavior is intentional rather than accepting failures blindly",
              confidence: "medium",
            },
            blockSnapshotUpdates
          );
        }
      }
    }

    if (findings.length === 0) {
      return {
        ruleId: "testing/no-cheat",
        decision: "pass",
        findings: [],
      };
    }

    if (blocking.length === 0) {
      return {
        ruleId: "testing/no-cheat",
        decision: "pass",
        findings,
      };
    }

    const list = blocking
      .map((finding) => `  - [${finding.pattern}] → ${finding.messageSnippet}`)
      .join("\n");

    return {
      ruleId: "testing/no-cheat",
      decision: "block",
      findings,
      remediationPrompt:
        `Test integrity violation detected in this turn:\n${list}\n\n` +
        `Do not make tests pass by disabling coverage, deleting tests, weakening assertions, removing CI verification, or focusing/skipping failing cases. Fix the underlying implementation or explicitly justify a legitimate test change with matching behavior evidence.`,
    };
  },
};
