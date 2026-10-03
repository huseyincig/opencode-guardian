import type { GuardRule, RuleFinding, RuleResult, TurnInspectionContext } from "../types.js";
import { extractLikelyShellMutation } from "../tool-input.js";

export const SECRET_PATTERNS: { regex: RegExp; name: string }[] = [
  { regex: /\b(?:sk-proj-|sk-)[a-zA-Z0-9_-]{32,}\b/, name: "OpenAI API Key (sk-...)" },
  { regex: /\bghp_[a-zA-Z0-9]{36}\b/, name: "GitHub Personal Access Token (ghp_...)" },
  { regex: /\bgithub_pat_[a-zA-Z0-9_]{50,}\b/, name: "GitHub Fine-Grained Token (github_pat_...)" },
  { regex: /\bAKIA[0-9A-Z]{16}\b/, name: "AWS Access Key ID (AKIA...)" },
  { regex: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b/, name: "Slack API Token (xoxb-...)" },
  { regex: /-----BEGIN\s+(?:RSA\s+|OPENSSH\s+|EC\s+|DSA\s+|PGP\s+)?PRIVATE\s+KEY-----/, name: "Private Key Header (PEM/SSH)" },
  { regex: /\b(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[^:\s'"]+:([^@\s'"]+)@[a-zA-Z0-9.-]+(?::[0-9]+)?\/[a-zA-Z0-9_.-]+/, name: "Database Connection String with Password" },
  { regex: /\beyJ[a-zA-Z0-9_-]{15,}\.eyJ[a-zA-Z0-9_-]{15,}\.[a-zA-Z0-9_-]{15,}\b/, name: "JSON Web Token (JWT)" },
  { regex: /\bnpm_[a-zA-Z0-9]{32,}\b/, name: "npm Access Token (npm_...)" },
  { regex: /\bglpat-[a-zA-Z0-9_-]{20,}\b/, name: "GitLab Personal Access Token (glpat-...)" },
  { regex: /\bAIza[0-9A-Za-z_-]{35}\b/, name: "Google API Key (AIza...)" },
  { regex: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b/, name: "Stripe Live Secret Key" },
  { regex: /\b(?:_authToken|npmAuthToken)\s*=\s*["']?([A-Za-z0-9._~-]{20,})["']?/i, name: "npm Registry Auth Token" },
  { regex: /\bAuthorization\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9._~-]{24,})["']?/i, name: "Bearer Authorization Token" },
];

function extractFilePathFromPatch(patch: unknown): string | undefined {
  if (typeof patch !== "string") return undefined;
  const match = patch.match(/\+\+\+\s+(?:b\/)?([^\s\t\n]+)/);
  return match ? match[1] : undefined;
}

function extractAddedLines(text: unknown): string {
  if (typeof text !== "string") return "";
  return text.split("\n").filter((line) => line.startsWith("+") && !line.startsWith("+++")).map((line) => line.slice(1)).join("\n");
}

function maskSecret(secret: string): string {
  if (secret.length <= 8) return "********";
  return `${secret.slice(0, 4)}...${secret.slice(-4)}`;
}

function isExplicitTemplateValue(secretValue: string, capturedPassword?: string): boolean {
  return [secretValue, capturedPassword ?? ""].some(
    (value) =>
      value.includes("${") ||
      value.includes("process.env") ||
      /^\$[A-Z_][A-Z0-9_]*$/i.test(value) ||
      /<(?:YOUR_[A-Z0-9_]+|PASSWORD|TOKEN|API_KEY)>/i.test(value)
  );
}

/** Documented, local-only example credentials are not real deployment secrets.
 * Never exempt token-shaped strings or remote service credentials by filename. */
function isDocumentedLocalPasswordSample(
  filePath: string | undefined,
  value: string,
  password: string | undefined
): boolean {
  if (!filePath || !password) return false;
  if (!/(?:^|[\/])(?:[^\/]+\.)?(?:env\.)?(?:example|sample|template|dist)$/i.test(filePath)) {
    return false;
  }
  if (!/^(?:pass|password|example|sample|dummy|test|changeme|your_password_here)$/i.test(password)) {
    return false;
  }
  // A plausible password on a real database host must still be reported.
  return /@(?:localhost|127\.0\.0\.1|\[::1\]|(?:db\.)?example\.(?:com|org|net))(?::[0-9]+)?\//i.test(value);
}

export const noSecretsRule: GuardRule = {
  id: "security/no-secrets",
  description: "Detects hardcoded secrets, API keys, credentials, and connection strings in code modifications.",
  inspect: (context: TurnInspectionContext): RuleResult => {
    const findings: RuleFinding[] = [];
    const seen = new Set<string>();

    const checkCode = (code: string, filePath?: string, source = "file") => {
      if (!code || typeof code !== "string") return;

      for (const pattern of SECRET_PATTERNS) {
        if (seen.has(pattern.name)) continue;
        // A permitted example value must not hide a later real credential
        // matched by the same pattern in the same file.
        let remaining = code;
        let match: RegExpExecArray | null = null;
        while (remaining.length > 0) {
          pattern.regex.lastIndex = 0;
          const next = pattern.regex.exec(remaining);
          if (!next) break;
          const value = next[0];
          const password = next[1];
          const isSample = password !== undefined
            ? isExplicitTemplateValue(password) ||
              isDocumentedLocalPasswordSample(filePath, value, password)
            : isExplicitTemplateValue(value);
          if (!isSample) {
            match = next;
            break;
          }
          remaining = remaining.slice(next.index + value.length);
        }
        if (!match) continue;
        const secretValue = match[0];

        seen.add(pattern.name);
        const masked = maskSecret(secretValue);
        findings.push({
          ruleId: "security/no-secrets",
          pattern: pattern.name,
          messageSnippet: masked,
          description: `Potential hardcoded secret detected in ${filePath ?? source}: ${pattern.name} (${masked})`,
        });
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

        if (typeof input.content === "string") checkCode(input.content, targetFile);
        if (typeof input.new_string === "string") checkCode(input.new_string, targetFile);
        if (typeof input.newString === "string") checkCode(input.newString, targetFile);

        const patchText = extractAddedLines(patchRaw);
        if (patchText) checkCode(patchText, targetFile);

        const shellMutation = extractLikelyShellMutation(input);
        if (shellMutation) checkCode(shellMutation, undefined, "shell file mutation");
      }
    }

    if (findings.length === 0) {
      return { ruleId: "security/no-secrets", decision: "pass", findings: [] };
    }

    const list = findings.map((f) => `  - [${f.pattern}] → ${f.messageSnippet}`).join("\n");
    const remediationPrompt =
      `Hardcoded secret or credential detected in this turn:\n${list}\n\n` +
      `Never hardcode raw API keys, private tokens, or database credentials directly in source files. ` +
      `Please remove the credentials from code and use environment variables (e.g. process.env, .env) instead.`;

    return { ruleId: "security/no-secrets", decision: "block", findings, remediationPrompt };
  },
};
