import type { GuardRule, RuleFinding, RuleResult, TurnInspectionContext } from "../types.js";
import { extractLikelyShellMutation, extractStructuredEditTexts } from "../tool-input.js";
import { extractFilePathFromPatch } from "./no-secrets.js";

/**
 * Patterns that indicate fake or stubbed implementations in code.
 */
export const STUB_PATTERNS: { regex: RegExp; name: string }[] = [
  {
    regex: /throw\s+new\s+(?:NotImplementedError|Error\s*\(\s*["'`][^"'`]*(?:not\s+implemented|todo|to\s+be\s+implemented|stub|placeholder)[^"'`]*["'`]\s*\))/i,
    name: "throw NotImplementedError",
  },
  {
    regex: /raise\s+NotImplementedError(?:\s*\(.*\))?/i,
    name: "raise NotImplementedError (Python)",
  },
  {
    regex: /\b(?:todo!|unimplemented!)\s*\(/i,
    name: "todo! / unimplemented! macro (Rust)",
  },
  {
    regex: /\bpanic\s*\(\s*["'`][^"'`]*(?:not\s+implemented|todo|stub)[^"'`]*["'`]\s*\)/i,
    name: "panic('not implemented') (Go/Rust)",
  },
  {
    regex: /(?:\/\/|#|\/\*)\s*(?:TODO|FIXME|STUB|PLACEHOLDER)\s*:\s*(?:implement|add\s+logic|fill\s+in|complete\s+this)/i,
    name: "TODO: implement comment",
  },
  {
    regex: /def\s+\w+\s*\(.*?\)\s*:\s*(?:#[^\n]*\n\s*)*pass\b/,
    name: "empty def ...: pass (Python stub)",
  },
  {
    regex: /\breturn\s+(?:null|undefined|true|false|\[\]|\{\})\s*;?\s*(?:\/\/|#)\s*(?:TODO|FIXME|stub|placeholder|temporary)\b/i,
    name: "placeholder constant return",
  },
  {
    regex: /\breturn\s+None\s*(?:#\s*(?:TODO|FIXME|stub|placeholder|temporary)\b)/i,
    name: "placeholder return None (Python)",
  },
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

export const noStubsRule: GuardRule = {
  id: "integrity/no-stubs",
  description: "Prevents unfinished functions, NotImplemented stubs, and placeholder methods in code.",
  inspect: (context: TurnInspectionContext): RuleResult => {
    const findings: RuleFinding[] = [];
    const seen = new Set<string>();

    const checkCode = (code: string, source: string, filePath?: string) => {
      if (!code || typeof code !== "string") return;

      for (const pattern of STUB_PATTERNS) {
        if (seen.has(pattern.name)) continue;

        const match = pattern.regex.exec(code);
        if (match) {
          seen.add(pattern.name);
          const snippet = extractSnippet(code, match.index, match[0].length);
          findings.push({
            ruleId: "integrity/no-stubs",
            pattern: pattern.name,
            messageSnippet: snippet,
            description: `Stub / incomplete implementation detected in ${source}: "${match[0]}" → "${snippet}"`,
            ...(filePath ? {
              filePath,
              fingerprint: `${filePath}:${pattern.name}:${match[0].trim()}`,
            } : {}),
          });
        }
      }
    };

    for (const msg of context.currentTurn) {
      if (msg.info.role !== "assistant") continue;

      for (const part of msg.parts) {
        if (part.type === "tool" && part.state?.input) {
          const input = part.state.input;
          const patchRaw = input.patchText ?? input.patch;
          const targetFile =
            (input.path as string) ??
            (input.targetFile as string) ??
            (input.filePath as string) ??
            (input.file as string) ??
            extractFilePathFromPatch(patchRaw);
          if (typeof input.content === "string") {
            checkCode(input.content, "file write content", targetFile);
          }
          if (typeof input.new_string === "string") {
            checkCode(input.new_string, "file edit", targetFile);
          }
          if (typeof input.newString === "string") {
            checkCode(input.newString, "file edit", targetFile);
          }
          for (const edit of extractStructuredEditTexts(input, targetFile)) {
            checkCode(edit.text, "structured file edit", edit.filePath);
          }
          const patchText = extractAddedLines(patchRaw);
          if (patchText) {
            checkCode(patchText, "patch added lines", targetFile);
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
        ruleId: "integrity/no-stubs",
        decision: "pass",
        findings: [],
      };
    }

    const list = findings.map((f) => `  - [${f.pattern}] → ${f.messageSnippet}`).join("\n");
    const remediationPrompt =
      `Incomplete or stubbed implementation detected in this turn:\n${list}\n\n` +
      `Do not leave placeholder methods, empty stubs, or NotImplementedError exceptions in production code. ` +
      `Please provide the actual, complete implementation of the required functionality before stopping.`;

    return {
      ruleId: "integrity/no-stubs",
      decision: "block",
      findings,
      remediationPrompt,
    };
  },
};
