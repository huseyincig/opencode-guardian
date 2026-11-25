import type { GuardRule, RuleFinding, RuleResult, TurnInspectionContext } from "../types.js";
import { extractLikelyShellMutation, extractStructuredEditTexts, splitFilePatches } from "../tool-input.js";
import { KNOWN_CREDENTIAL_PATTERNS } from "../secrets/patterns.js";
import { defaultRuntimeSecrets } from "../secrets/runtime-secrets.js";
import type { SanitizerOptions } from "../secrets/types.js";

export const SECRET_PATTERNS: { regex: RegExp; name: string }[] = [
  // Clone regex instances so write scans cannot alter output redaction state.
  ...KNOWN_CREDENTIAL_PATTERNS.map(({ name, regex }) => ({ name, regex: new RegExp(regex.source, regex.flags) })),
  { regex: /-----BEGIN(?:\s+[A-Z0-9_-]+)?\s+PRIVATE\s+KEY-----/, name: "Private Key Header (PEM/SSH)" },
  { regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|mssql):\/\/[^:\s'"]*:(?!\/\/)([^@\s'"]+)@[a-zA-Z0-9.-]+(?::[0-9]+)?(?:\/[a-zA-Z0-9_.-]*)?/, name: "Database Connection String with Password" },
  { regex: /\b(?:_authToken|npmAuthToken)\s*=\s*["']?([A-Za-z0-9._~-]{20,})["']?/i, name: "npm Registry Auth Token" },
  { regex: /\bAuthorization\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9._~-]{24,})["']?/i, name: "Bearer Authorization Token" },
];

export function extractFilePathFromPatch(patch: unknown): string | undefined {
  if (typeof patch !== "string") return undefined;
  return splitFilePatches(patch)[0]?.filePath;
}

export function extractAddedLines(text: unknown): string {
  if (typeof text !== "string") return "";
  return text.split("\n").filter((line) => line.startsWith("+") && !line.startsWith("+++")).map((line) => line.slice(1)).join("\n");
}

export function maskSecret(secret: string): string {
  if (secret.length <= 8) return "********";
  return `${secret.slice(0, 4)}...${secret.slice(-4)}`;
}

export function isExplicitTemplateValue(secretValue: string, capturedPassword?: string): boolean {
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
export function isDocumentedLocalPasswordSample(
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

export interface DetectedSecret {
  name: string;
  secretValue: string;
  masked: string;
}

export function findAllSecretsInCode(
  code: string,
  filePath?: string,
  alreadySeen?: Set<string>,
  secretOptions?: SanitizerOptions
): DetectedSecret[] {
  if (!code || typeof code !== "string") return [];
  const results: DetectedSecret[] = [];
  const seen = alreadySeen ?? new Set<string>();
  const safeValueSet = secretOptions?.safeValues?.length ? new Set(secretOptions.safeValues) : undefined;

  for (const pattern of SECRET_PATTERNS) {
    if (seen.has(pattern.name)) continue;
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
      const isSafeValue =
        Boolean(safeValueSet?.has(value)) ||
        (password !== undefined && Boolean(safeValueSet?.has(password)));
      if (!isSample && !isSafeValue) {
        match = next;
        break;
      }
      remaining = remaining.slice(next.index + value.length);
    }
    if (!match) continue;
    const secretValue = match[0];
    seen.add(pattern.name);
    results.push({ name: pattern.name, secretValue, masked: maskSecret(secretValue) });
  }

  if (secretOptions) {
    const runtimeSecrets =
      secretOptions.includeRuntimeEnv !== false
        ? defaultRuntimeSecrets.getSecrets()
        : [];
    const literalCandidates = [
      ...(secretOptions.customSecretValues ?? []),
      ...runtimeSecrets,
    ];
    for (const secretVal of literalCandidates) {
      if (!secretVal || secretVal.length < 6 || safeValueSet?.has(secretVal)) continue;
      if (isExplicitTemplateValue(secretVal)) continue;
      const key = "Configured/Runtime Secret Value";
      if (seen.has(key)) break;
      if (code.includes(secretVal)) {
        seen.add(key);
        results.push({ name: key, secretValue: secretVal, masked: maskSecret(secretVal) });
        break;
      }
    }

    if (secretOptions.customSensitiveKeys?.length && !seen.has("Custom Sensitive Key Assignment")) {
      const stringKeys = secretOptions.customSensitiveKeys
        .filter((k): k is string => typeof k === "string")
        .map((k) => k.trim())
        .filter((k) => k.length > 0 && /^[A-Za-z0-9_.-]+$/.test(k));
      const regexKeys = secretOptions.customSensitiveKeys.filter(
        (k): k is RegExp => k instanceof RegExp
      );
      const safeStringKeys = (secretOptions.safeKeyNames ?? [])
        .filter((k): k is string => typeof k === "string")
        .map((k) => k.trim().toLowerCase())
        .filter((k) => k.length > 0);
      const isSafeKey = (candidateKey: string): boolean =>
        safeStringKeys.includes(candidateKey.toLowerCase());
      const keyMatcher = (candidateKey: string): boolean => {
        if (isSafeKey(candidateKey)) return false;
        const lower = candidateKey.toLowerCase();
        if (stringKeys.some((k) => k.toLowerCase() === lower)) return true;
        return regexKeys.some((re) => {
          re.lastIndex = 0;
          return re.test(candidateKey);
        });
      };
      const TS_OR_CODE_UNQUOTED_VALUE =
        /^(?:string|number|boolean|unknown|any|void|never|object|undefined|null|symbol|bigint|true|false|readonly|partial|required|record|promise|buffer|uint8array|array|set|map|date|regexp|error|function)(?:[?[\]]*)?$/i;
      const CODE_REF_ROOTS = new Set([
        "this", "self", "super", "process", "env", "global", "window", "document", "module",
        "user", "req", "request", "res", "response", "ctx", "context", "cfg", "config",
        "opts", "options", "props", "state", "data", "body", "headers", "auth", "vault",
        "client", "app", "params", "query", "result", "payload", "input", "output", "meta",
        "args", "event", "store", "cache", "db", "service", "provider", "runtime", "account",
      ]);
      const isCleanCodeSeg = (seg: string): boolean =>
        seg.length > 0 && seg.length <= 24 && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(seg) && !/\d/.test(seg);
      const isCodeReference = (unquotedVal: string, sep: string): boolean => {
        // Never treat `key=value` (.env / shell / INI) dotted or parenthesized tokens as code expressions.
        if (sep !== ":") return false;
        if (TS_OR_CODE_UNQUOTED_VALUE.test(unquotedVal)) return true;
        const cleanCallArgs = (argsRaw: string): boolean => {
          const argsText = argsRaw.trim();
          if (!argsText) return true;
          return argsText.split(",").every((p) => {
            const pt = p.trim();
            return (
              /^[a-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*$/.test(pt) &&
              pt.split(/\?\.|\./).every(isCleanCodeSeg)
            );
          });
        };
        if (unquotedVal.includes("?.")) {
          const optMatch = /^([A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)+)(?:\(([^)\r\n]*)\))?$/.exec(unquotedVal);
          if (optMatch?.[1] && optMatch[1].split(/\?\.|\./).every(isCleanCodeSeg)) {
            if (optMatch[2] === undefined || cleanCallArgs(optMatch[2])) {
              return true;
            }
          }
        }
        const callMatch = /^([a-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*)\(([^)\r\n]*)\)$/.exec(unquotedVal);
        if (callMatch?.[1]) {
          const segs = callMatch[1].split(/\?\.|\./);
          if (segs.length <= 3 && segs.every(isCleanCodeSeg) && cleanCallArgs(callMatch[2] ?? "")) return true;
        }
        if (/^[a-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(unquotedVal)) {
          const segs = unquotedVal.split(".");
          if (segs.length <= 3 && CODE_REF_ROOTS.has(segs[0] ?? "") && segs.every(isCleanCodeSeg)) {
            return true;
          }
        }
        return false;
      };
      // Scan quoted/unquoted key assignments across JS/TS, JSON, YAML, and .env formats.
      // For oversized payloads (>512 KiB), scan both the leading 512 KiB and trailing 128 KiB
      // so secrets appended at the end of large files are not silently missed.
      const MAX_HEAD = 512 * 1024;
      const MAX_TAIL = 128 * 1024;
      const scanSlices = code.length > MAX_HEAD + MAX_TAIL
        ? [code.slice(0, MAX_HEAD), code.slice(code.length - MAX_TAIL)]
        : [code];
      const assignmentRe =
        /(?:["'])?([A-Za-z0-9_.-]{2,80})(?:["'])?\s*([:=])\s*(?:"([^"\r\n]{6,})"|'([^'\r\n]{6,})'|([A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*\([^)\r\n]*\)|[A-Za-z_$][\w$]*(?:\[\])+|[^\s"'`,;)}\]\r\n]{6,}))/g;
      for (const scanSource of scanSlices) {
        if (seen.has("Custom Sensitive Key Assignment")) break;
        assignmentRe.lastIndex = 0;
        let m = assignmentRe.exec(scanSource);
        let iter = 0;
        while (m !== null && iter < 20_000) {
          iter++;
          const k = m[1] ?? "";
          const sep = m[2] ?? "";
          const quotedVal = m[3] ?? m[4];
          const unquotedVal = m[5];
          const val = quotedVal ?? unquotedVal ?? "";
          if (
            k &&
            val &&
            keyMatcher(k) &&
            (quotedVal !== undefined || !isCodeReference(val, sep)) &&
            !isExplicitTemplateValue(val) &&
            !safeValueSet?.has(val)
          ) {
            seen.add("Custom Sensitive Key Assignment");
            results.push({
              name: "Custom Sensitive Key Assignment",
              secretValue: val,
              masked: maskSecret(val),
            });
            break;
          }
          m = assignmentRe.exec(scanSource);
        }
      }
    }
  }
  return results;
}

export function findSecretInCode(
  code: string,
  filePath?: string,
  secretOptions?: SanitizerOptions
): DetectedSecret | undefined {
  return findAllSecretsInCode(code, filePath, undefined, secretOptions)[0];
}

export const noSecretsRule: GuardRule = {
  id: "security/no-secrets",
  description: "Detects hardcoded secrets, API keys, credentials, and connection strings in code modifications.",
  inspect: (context: TurnInspectionContext): RuleResult => {
    const findings: RuleFinding[] = [];
    const seenByFile = new Map<string, Set<string>>();

    const checkCode = (code: string, filePath?: string, source = "file") => {
      const scopeKey = filePath ?? source;
      let seen = seenByFile.get(scopeKey);
      if (!seen) {
        seen = new Set<string>();
        seenByFile.set(scopeKey, seen);
      }
      const detected = findAllSecretsInCode(code, filePath, seen, context.secretOptions);
      for (const item of detected) {
        findings.push({
          ruleId: "security/no-secrets",
          pattern: item.name,
          messageSnippet: item.masked,
          description: `Potential hardcoded secret detected in ${filePath ?? source}: ${item.name} (${item.masked})`,
          ...(filePath ? { filePath } : {}),
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
          (input.TargetFile as string) ??
          (input.filePath as string) ??
          (input.file as string) ??
          extractFilePathFromPatch(patchRaw);

        for (const key of [
          "content",
          "new_string",
          "newString",
          "new_str",
          "appendContent",
          "prependContent",
          "file_text",
          "CodeContent",
          "ReplacementContent",
          "text",
        ]) {
          if (typeof input[key] === "string") {
            checkCode(input[key] as string, targetFile);
          }
        }
        for (const edit of extractStructuredEditTexts(input, targetFile)) {
          checkCode(edit.text, edit.filePath);
        }

        for (const section of splitFilePatches(patchRaw)) {
          const patchText = extractAddedLines(section.patch);
          if (patchText) checkCode(patchText, section.filePath ?? targetFile);
        }

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
      `ACTION REQUIRED:\n` +
      `1. Remove the raw API key, token, or secret from the source code immediately.\n` +
      `2. Read the credential from an environment variable (e.g. process.env.KEY or configuration file) instead.\n` +
      `3. Verify the file no longer contains sensitive credentials before continuing.`;

    return { ruleId: "security/no-secrets", decision: "block", findings, remediationPrompt };
  },
};
