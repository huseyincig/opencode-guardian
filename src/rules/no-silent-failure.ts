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
import { isVerificationFailureMask } from "../evidence.js";
import { maskCodeLiterals } from "../code-context.js";

const EMPTY_HANDLER_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  {
    name: "empty JavaScript/TypeScript catch",
    regex: /\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}/m,
  },
  {
    name: "empty Promise catch",
    regex: /\.catch\s*\(\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)?\s*=>\s*\{\s*\}\s*\)/m,
  },
  {
    name: "Python except: pass",
    regex: /\bexcept(?:\s+(?:\([^\n)]+\)|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)(?:\s+as\s+[A-Za-z_]\w*)?)?\s*:\s*(?:#[^\n]*\n\s*)*pass\b/m,
  },
];

const MASKED_VERIFICATION =
  /\b(?:npm|pnpm|yarn|bun)\s+(?:(?:run\s+)?(?:test|build|lint|typecheck)|audit)\b|\b(?:pytest|py\.test|go\s+test|cargo\s+(?:test|build|clippy|audit)|node\s+--test|jest|vitest|tsc\b[^\n;&|]*--noEmit|mypy|pyright|eslint|ruff|flake8|pip-audit|govulncheck)\b/i;

const EXPLORATORY_VERIFICATION =
  /(?:^|\s)(?:--help|--version|--listtests|--list-tests|--collect-only|--list|--dry-run|--showconfig|--show-config)(?=\s|$)/i;

const CONSTANT_FALLBACK = "(?:null|undefined|false|true|\\[\\s*\\]|\\{\\s*\\}|0)";
const FALLBACK_HANDLERS = [
  new RegExp(`\\bcatch\\s*(?:\\([^)]*\\))?\\s*\\{\\s*return\\s+${CONSTANT_FALLBACK}\\s*;?\\s*\\}`, "m"),
  new RegExp(`\\.catch\\s*\\(\\s*(?:\\([^)]*\\)|[A-Za-z_$][\\w$]*)\\s*=>\\s*(?:${CONSTANT_FALLBACK}|\\{\\s*return\\s+${CONSTANT_FALLBACK}\\s*;?\\s*\\})\\s*\\)`, "m"),
];

/** Small shell lexical view. Single quotes are literal; double quotes still
 * execute substitutions. This is deliberately not a general shell evaluator. */
function shellVerificationViews(command: string): { code: string; hidden: string[]; executed: string[] } {
  const output = command.split("");
  const hidden: string[] = [];
  const executed: string[] = [];
  let quote = "";
  let segmentStart = 0;
  const blank = (start: number, end: number) => {
    for (let at = start; at < end; at++) if (command[at] !== "\n") output[at] = " ";
  };
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (ch === "\\" && quote !== "'") { blank(i, i + 2); i++; continue; }
    if (quote === "'") {
      if (ch === "'") quote = "";
      blank(i, i + 1); continue;
    }
    if (ch === "'" && !quote) { quote = "'"; blank(i, i + 1); continue; }
    if (ch === '"') { quote = quote ? "" : '"'; blank(i, i + 1); continue; }
    if (ch === "`" || command.startsWith("$(", i) && !command.startsWith("$((", i)) {
      const backtick = ch === "`";
      const start = i + (backtick ? 1 : 2);
      let end = start;
      let depth = 1;
      let innerQuote = "";
      for (; end < command.length; end++) {
        const c = command[end];
        if (c === "\\") { end++; continue; }
        if (backtick && c === "`") break;
        if (c === "'" || c === '"') {
          if (!innerQuote) innerQuote = c;
          else if (innerQuote === c) innerQuote = "";
          continue;
        }
        if (!backtick && !innerQuote) {
          if (c === "(") depth++;
          if (c === ")" && --depth === 0) break;
        }
      }
      if (end >= command.length) { blank(i, command.length); break; }
      const inner = command.slice(start, end);
      executed.push(inner);
      const prefix = output.slice(segmentStart, i).join("").trim();
      // A plain assignment preserves substitution status. Declaration builtins
      // and commands consuming its output report their own status instead.
      if (!/^(?:(?:if|elif|while|until)\s+)?[A-Za-z_]\w*=\s*$/.test(prefix)) hidden.push(inner);
      blank(i, end + 1);
      i = end;
      continue;
    }
    if (!quote && ch === "#" && (i === 0 || /\s/.test(command[i - 1] ?? ""))) {
      const end = command.indexOf("\n", i);
      const until = end < 0 ? command.length : end;
      blank(i, until); i = until - 1; continue;
    }
    if (quote) blank(i, i + 1);
    else if (ch && /[;\n&|]/.test(ch)) segmentStart = i + 1;
  }
  return { code: output.join(""), hidden, executed };
}

function verificationMask(command: string, depth = 0): boolean {
  if (depth > 8) return false;
  const views = shellVerificationViews(command);
  if (MASKED_VERIFICATION.test(views.code) && !EXPLORATORY_VERIFICATION.test(views.code) && isVerificationFailureMask(views.code)) return true;
  return views.hidden.some((inner) => {
    const view = shellVerificationViews(inner).code;
    return MASKED_VERIFICATION.test(view) && !EXPLORATORY_VERIFICATION.test(view);
  }) || views.executed.some((inner) => verificationMask(inner, depth + 1));
}

function extractAddedLines(text: unknown): string {
  if (typeof text !== "string") return "";
  return text
    .split("\n")
    .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
    .map((line) => line.slice(1))
    .join("\n");
}

function extractSnippet(text: string, index: number, length: number): string {
  const start = Math.max(0, index - 80);
  const end = Math.min(text.length, index + length + 80);
  return text
    .slice(start, end)
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 220);
}

export const noSilentFailureRule: GuardRule = {
  id: "integrity/no-silent-failure",
  description:
    "Detects swallowed errors and verification commands whose failure status is deliberately masked.",
  inspect: (context: TurnInspectionContext): RuleResult => {
    const findings: RuleFinding[] = [];
    const blocking: RuleFinding[] = [];
    const blockEmptyHandlers = context.ruleConfig.blockEmptyHandlers === true;

    const checkCode = (code: string, source: string, filePath?: string) => {
      if (!code) return;
      const executable = maskCodeLiterals(code, false, filePath);
      for (const pattern of EMPTY_HANDLER_PATTERNS) {
        pattern.regex.lastIndex = 0;
        const match = pattern.regex.exec(executable);
        if (!match) continue;
        const finding: RuleFinding = {
          ruleId: "integrity/no-silent-failure",
          pattern: pattern.name,
          messageSnippet: extractSnippet(code, match.index, match[0].length),
          description: `Error is swallowed without logging, propagation, or an explicit fallback in ${source}`,
          confidence: "medium",
        };
        findings.push(finding);
        if (blockEmptyHandlers) blocking.push(finding);
      }
      for (const regex of FALLBACK_HANDLERS) {
        const match = regex.exec(executable);
        if (match) findings.push({ ruleId: "integrity/no-silent-failure", pattern: "constant error fallback",
          messageSnippet: extractSnippet(code, match.index, match[0].length),
          description: `An error becomes a constant fallback in ${source}; review that this recovery is intentional.`,
          confidence: "medium",
        });
      }
    };

    for (const message of context.currentTurn) {
      if (message.info.role !== "assistant") continue;
      for (const part of message.parts) {
        if (part.type !== "tool" || !part.state?.input) continue;
        const input = part.state.input;
        const target = input.filePath ?? input.path ?? input.file ?? input.targetFile;
        const filePath = typeof target === "string" ? target : undefined;

        for (const value of [
          input.content,
          input.new_string,
          input.newString,
          extractAddedLines(input.patchText ?? input.patch),
          extractLikelyShellMutation(input),
        ]) {
          if (typeof value === "string" && value) checkCode(value, "code mutation", filePath);
        }
        for (const edit of extractStructuredEditTexts(input)) {
          checkCode(edit.text, "structured code mutation", edit.filePath ?? filePath);
        }

        const command = extractToolCommand(input);

        if (
          command &&
          verificationMask(command)
        ) {
          const finding: RuleFinding = {
            ruleId: "integrity/no-silent-failure",
            pattern: "masked verification failure",
            messageSnippet: command.replace(/\s+/g, " ").slice(0, 220),
            description:
              "A test/build/lint/typecheck/audit command masks its failing exit status",
            confidence: "high",
          };
          findings.push(finding);
          blocking.push(finding);
        }
      }
    }

    if (findings.length === 0) {
      return {
        ruleId: "integrity/no-silent-failure",
        decision: "pass",
        findings: [],
      };
    }

    if (blocking.length === 0) {
      return {
        ruleId: "integrity/no-silent-failure",
        decision: "pass",
        findings,
      };
    }

    const list = blocking
      .map((finding) => `  - [${finding.pattern}] ${finding.messageSnippet}`)
      .join("\n");

    return {
      ruleId: "integrity/no-silent-failure",
      decision: "block",
      findings,
      remediationPrompt:
        `Silent failure masking detected:\n${list}\n\n` +
        `Do not force verification commands to succeed after a real failure. Preserve the actual exit status and report or handle errors explicitly.`,
    };
  },
};
