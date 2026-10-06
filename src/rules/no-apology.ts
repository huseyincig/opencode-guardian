import type { GuardRule, RuleFinding, RuleResult, TurnInspectionContext } from "../types.js";
import { sanitizeProseForInspection } from "../prose.js";

export interface ApologyPattern {
  name: string;
  regex: RegExp;
}

/**
 * Universal multi-lingual apology and sycophancy patterns.
 * Matches root stems and expressions across English, Turkish, German, French,
 * Spanish, Italian, Portuguese, Russian, and Dutch with zero false-positives
 * on technical nouns/verbs.
 */
export const MULTILINGUAL_APOLOGY_PATTERNS: ApologyPattern[] = [
  // English
  {
    name: "English",
    regex: /(?<!\p{L})(?:(?:i(?:'m| am)?\s+)?(?:deeply|sincerely|terribly|truly|so)?\s*(?:apologiz\p{L}*|apologis\p{L}*|sorr(?:y|ier))|(?:my|our|sincere|deepest)\s+apolog\p{L}*|apologies\s+for|pardon(?:\s+me)?|forgive\s+me|excuse\s+my\s+mistake|my\s+bad|my\s+fault)(?!\p{L})/iu,
  },
  // Turkish
  {
    name: "Turkish",
    regex: /(?<!\p{L})(?:(?:çok\s+|binlerce\s+kez\s+)?özür\s*(?:diler(?:im|iz)?|diliyor(?:um|uz)?|dileyerek)|kusur(?:a|uma)?\s*bakma(?:yın|yınız)?|affeder(?:im|siniz)?|afeder(?:im|siniz)?|bağışla(?:yın)?)(?!\p{L})/iu,
  },
  // German
  {
    name: "German",
    regex: /(?<!\p{L})(?:entschuldig\p{L}*|es\s+tut\s+mir\s+leid|verzeih\p{L}*)(?!\p{L})/iu,
  },
  // French
  {
    name: "French",
    regex: /(?<!\p{L})(?:désol[ée]\p{L}*|pardon(?:nez-moi)?|excuse[zr]?-moi|veuillez\s+m'excuser|navr[ée]\p{L}*|mille\s+excuses)(?!\p{L})/iu,
  },
  // Spanish
  {
    name: "Spanish",
    regex: /(?<!\p{L})(?:disculp\p{L}*|perd[oó]n\p{L}*|lo\s+siento|mil\s+disculpas)(?!\p{L})/iu,
  },
  // Italian
  {
    name: "Italian",
    regex: /(?<!\p{L})(?:scus\p{L}*|spiacente|chiedo\s+scusa|perdon\p{L}*)(?!\p{L})/iu,
  },
  // Portuguese
  {
    name: "Portuguese",
    regex: /(?<!\p{L})(?:desculp\p{L}*|perd[aã]o|sinto\s+muito|peço\s+desculpas)(?!\p{L})/iu,
  },
  // Russian
  {
    name: "Russian",
    regex: /(?<!\p{L})(?:извини\p{L}*|прости\p{L}*|сожале\p{L}*|прошу\s+прощения)(?!\p{L})/iu,
  },
  // Dutch
  {
    name: "Dutch",
    regex: /(?<!\p{L})(?:het\s+spijt\s+me|verontschuldig\p{L}*)(?!\p{L})/iu,
  },
];

function isReportedApologyToken(text: string, matchIndex: number): boolean {
  const prefix = text.slice(Math.max(0, matchIndex - 100), matchIndex);
  return (
    /\b(?:return(?:ed|s)?|report(?:ed|s)?|contain(?:ed|s)?|emit(?:ted|s)?|print(?:ed|s)?|say|says|said)\s+(?:the\s+(?:word|text)\s+)?$/i.test(
      prefix
    ) ||
    /\b(?:payload|response|message|error|output|text|string|token|word)\b[^.!?]{0,30}\b(?:is|was|equals?|contains?|included?)\s*$/i.test(
      prefix
    )
  );
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

export const noApologyRule: GuardRule = {
  id: "discipline/no-apology",
  description: "Detects sycophantic, defensive, or excessive apology language in assistant responses across all languages.",
  inspect: (context: TurnInspectionContext): RuleResult => {
    const findings: RuleFinding[] = [];
    const seenPatterns = new Set<string>();

    const customPatterns: ApologyPattern[] = (context.ruleConfig.customPhrases ?? [])
      .filter((phrase) => phrase.trim().length > 0)
      .map((phrase) => ({
      name: `Custom ("${phrase}")`,
        regex: new RegExp(`(?<!\\p{L})${phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?!\\p{L})`, "iu"),
      }));

    const activePatterns = [...MULTILINGUAL_APOLOGY_PATTERNS, ...customPatterns];

    for (const msg of context.currentTurn) {
      if (msg.info.role !== "assistant") continue;

      for (const part of msg.parts) {
        if (part.type !== "text" || !part.text || typeof part.text !== "string") {
          continue;
        }

        const cleanText = sanitizeProseForInspection(part.text);
        if (!cleanText) continue;

        for (const pattern of activePatterns) {
          if (seenPatterns.has(pattern.name)) continue;

          const regex = new RegExp(
            pattern.regex.source,
            pattern.regex.flags.includes("g")
              ? pattern.regex.flags
              : `${pattern.regex.flags}g`
          );
          let match = regex.exec(cleanText);
          while (match !== null) {
            if (isReportedApologyToken(cleanText, match.index)) {
              match = regex.exec(cleanText);
              continue;
            }

            seenPatterns.add(pattern.name);
            const snippet = extractSnippet(cleanText, match.index, match[0].length);
            findings.push({
              ruleId: "discipline/no-apology",
              pattern: pattern.name,
              messageSnippet: snippet,
              description: `Apology/sycophancy language detected (${pattern.name}): "${match[0]}" → "${snippet}"`,
            });
            break;
          }
        }
      }
    }

    if (findings.length === 0) {
      return {
        ruleId: "discipline/no-apology",
        decision: "pass",
        findings: [],
      };
    }

    const list = findings.map((f) => `  - [${f.pattern}] → ${f.messageSnippet}`).join("\n");
    const remediationPrompt =
      `Excessive apology / sycophancy language detected in this turn:\n${list}\n\n` +
      `Do not apologize or use conversational filler. Focus strictly and directly on: ` +
      `(1) the factual root cause of the issue, (2) the concrete evidence, and ` +
      `(3) the exact corrective action taken or proposed. Be professional, direct, and outcome-focused.`;

    return {
      ruleId: "discipline/no-apology",
      decision: "block",
      findings,
      remediationPrompt,
    };
  },
};
