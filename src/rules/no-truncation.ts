import type { GuardRule, RuleFinding, RuleResult, TurnInspectionContext } from "../types.js";
import { extractLikelyShellMutation, extractStructuredEditTexts } from "../tool-input.js";

/**
 * Regex patterns that detect lazy file truncation comments like:
 * "// ... existing code unchanged ..."
 * "# ... rest of code ..."
 * "<!-- ... previous content ... -->"
 */
export const TRUNCATION_PATTERNS: RegExp[] = [
  /(?:\/\/|#|\/\*|<!--)\s*\.{3}\s*(?:existing|rest\s+of|remaining|previous|earlier|unchanged|keep\s+existing|other|more|code\s+here)\b/i,
  /(?:\/\/|#|\/\*|<!--)\s*(?:existing|rest\s+of|remaining|previous|earlier|unchanged)\s*(?:code|methods|functions|implementation|content|logic)\s*(?:remains|here|unchanged|as\s+is|continues)?\s*\.{3}/i,
  /(?:\/\/|#|\/\*|<!--)\s*\[?\.\.\.\s*(?:rest|existing|code|truncated)\s*(?:of\s+code)?\s*\.?\]?/i,
  /(?:\/\/|#)\s*\.{3}\s*$/m,
];

function extractAddedLines(text: unknown): string {
  if (typeof text !== "string") return "";
  return text
    .split("\n")
    .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
    .map((line) => line.slice(1))
    .join("\n");
}

function extractSnippet(text: string, matchIndex: number, matchLen: number): string {
  const maxPerSide = 80;
  const start = Math.max(0, matchIndex - maxPerSide);
  const end = Math.min(text.length, matchIndex + matchLen + maxPerSide);

  let snippet = text.slice(start, end).replace(/\r?\n/g, " ").replace(/\s+/g, " ").trim();
  if (start > 0) snippet = `…${snippet}`;
  if (end < text.length) snippet = `${snippet}…`;
  return snippet;
}

export const noTruncationRule: GuardRule = {
  id: "safety/no-truncation",
  description: "Prevents models from deleting existing code by using lazy truncation placeholders like '// ... existing code ...'.",
  inspect: (context: TurnInspectionContext): RuleResult => {
    const findings: RuleFinding[] = [];
    const seen = new Set<string>();

    const checkCode = (code: string, source: string) => {
      if (!code || typeof code !== "string") return;

      for (const regex of TRUNCATION_PATTERNS) {
        const match = regex.exec(code);
        if (match) {
          const matchedText = match[0].trim();
          if (seen.has(matchedText)) continue;
          seen.add(matchedText);

          const snippet = extractSnippet(code, match.index, match[0].length);
          findings.push({
            ruleId: "safety/no-truncation",
            pattern: matchedText,
            messageSnippet: snippet,
            description: `Lazy code truncation placeholder detected in ${source}: "${matchedText}" → "${snippet}"`,
          });
        }
      }
    };

    for (const msg of context.currentTurn) {
      if (msg.info.role !== "assistant") continue;

      for (const part of msg.parts) {
        if (part.type === "tool" && part.state?.input) {
          const input = part.state.input;
          if (typeof input.content === "string") {
            checkCode(input.content, "file write content");
          }
          if (typeof input.new_string === "string") {
            checkCode(input.new_string, "file edit");
          }
          if (typeof input.newString === "string") {
            checkCode(input.newString, "file edit");
          }
          for (const edit of extractStructuredEditTexts(input)) {
            checkCode(edit.text, "structured file edit");
          }
          const patchText = extractAddedLines(input.patchText ?? input.patch);
          if (patchText) {
            checkCode(patchText, "patch added lines");
          }
          const shellMutation = extractLikelyShellMutation(input);
          if (shellMutation) {
            checkCode(shellMutation, "shell file mutation");
          }
        }
      }
    }

    if (findings.length === 0) {
      return {
        ruleId: "safety/no-truncation",
        decision: "pass",
        findings: [],
      };
    }

    const list = findings.map((f) => `  - "${f.pattern}" → ${f.messageSnippet}`).join("\n");
    const remediationPrompt =
      `Lazy code truncation placeholder detected in this turn:\n${list}\n\n` +
      `Never use placeholders like '// ... existing code unchanged ...' or '// ...' when modifying files. ` +
      `This accidentally deletes real source code. ` +
      `Please provide the complete, untruncated file content or targeted replacement.`;

    return {
      ruleId: "safety/no-truncation",
      decision: "block",
      findings,
      remediationPrompt,
    };
  },
};
