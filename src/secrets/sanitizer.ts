import {
  CONNECTION_STRING_PASSWORD_REGEX,
  isSensitiveKey,
  KNOWN_CREDENTIAL_PATTERNS,
  PASSWORD_HASH_PATTERNS,
  PEM_PRIVATE_KEY_REGEX,
} from './patterns.js';
import { defaultRuntimeSecrets } from './runtime-secrets.js';
import type { SanitizerOptions, SanitizeResult, SecretFinding } from './types.js';

const INLINE_STOPWORDS = new Set<string>([
  'is',
  'was',
  'were',
  'the',
  'a',
  'an',
  'in',
  'to',
  'for',
  'and',
  'or',
  'of',
  'with',
  'from',
  'at',
  'by',
  'on',
  'invalid',
  'expired',
  'missing',
  'required',
  'null',
  'undefined',
  'true',
  'false',
  'none',
  'not',
  'empty',
  'valid',
]);

const DEFAULT_REPLACEMENT = '[REDACTED]';
const FAIL_SAFE_OUTPUT = '[OUTPUT REDACTED: sanitization failure]';

const TS_TYPE_OR_KEYWORD =
  /^(?:string|number|boolean|unknown|any|void|never|object|undefined|null|symbol|bigint|true|false|readonly|partial|required|record|promise|buffer|uint8array|array|set|map|date|regexp|error|function)(?:[?[\]]*)?(?:\s*\|\s*(?:string|number|boolean|unknown|any|void|never|object|undefined|null|symbol|bigint)(?:[?[\]]*)?)*$/i;

const CODE_EXPR_ROOT_IDENTIFIERS = new Set([
  'this', 'self', 'super', 'process', 'env', 'global', 'window', 'document', 'module',
  'user', 'req', 'request', 'res', 'response', 'ctx', 'context', 'cfg', 'config',
  'opts', 'options', 'props', 'state', 'data', 'body', 'headers', 'auth', 'vault',
  'client', 'app', 'params', 'query', 'result', 'payload', 'input', 'output', 'meta',
  'args', 'event', 'store', 'cache', 'db', 'service', 'provider', 'runtime', 'account',
]);

function isPlausibleCodeIdentifierSegment(seg: string): boolean {
  if (!seg || seg.length > 24) return false;
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(seg)) return false;
  // Reject high-entropy / digit-containing token segments (e.g. `abc123def456`, `v4`, `MTIzNDU2Nzg5`).
  if (/\d/.test(seg)) return false;
  return true;
}

function isPlausibleCodeCallArgs(argsText: string): boolean {
  const trimmed = argsText.trim();
  if (!trimmed) return true;
  // Allow simple clean identifier/member args like `getToken(user, req.id)`,
  // NEVER digit-bearing/overlong/password literals like `MyPass(2024)` or `ab?.cd(mySecret2024)`.
  return trimmed.split(',').every((part) => {
    const p = part.trim();
    if (!/^[a-z_$][A-Za-z0-9_$]*(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*)*$/.test(p)) return false;
    return p.split(/\?\.|\./).every(isPlausibleCodeIdentifierSegment);
  });
}

function isCodeExpressionValue(rawVal: string, requireCodeSyntaxHint = false): boolean {
  const trimmedRaw = rawVal.trim();
  if (!trimmedRaw) return false;
  const hasCodeTerminator = /[;,]$/.test(trimmedRaw);
  const trimmed = trimmedRaw.replace(/[;,]+$/, '').trim();
  if (!trimmed) return false;
  if (TS_TYPE_OR_KEYWORD.test(trimmed)) return true;
  // Optional chaining `opts?.vaultKey` or `cfg?.getToken(req.id)` is unambiguously JS/TS code
  // only when call arguments (if present) are also clean identifiers, never raw secret literals.
  if (trimmed.includes('?.')) {
    const optMatch = /^([A-Za-z_$][A-Za-z0-9_$]*(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*)+)(?:\(([^)\r\n]*)\))?$/.exec(trimmed);
    if (
      optMatch?.[1] &&
      optMatch[1].split(/\?\.|\./).every(isPlausibleCodeIdentifierSegment) &&
      (optMatch[2] === undefined || isPlausibleCodeCallArgs(optMatch[2]))
    ) {
      return true;
    }
  }
  // Function call: camelCase/lowercase identifier (or `obj.method`) with empty/identifier args.
  const callMatch = /^([a-z_$][A-Za-z0-9_$]*(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*)*)\(([^)\r\n]*)\)$/.exec(trimmed);
  if (callMatch?.[1] && isPlausibleCodeCallArgs(callMatch[2] ?? '')) {
    const segs = callMatch[1].split(/\?\.|\./);
    if (segs.length <= 3 && segs.every(isPlausibleCodeIdentifierSegment)) {
      if (!requireCodeSyntaxHint || hasCodeTerminator || segs.length >= 2) return true;
    }
  }
  // Plain dotted member access (e.g. `user.token`, `env.SECRET`, `process.env.API_KEY`):
  // require a known lowercase code root and clean identifier segments so dotted secrets
  // like `SG.xxx.yyy`, `v4.local.xxx`, `session.abc123`, or `my.secret.passphrase` NEVER pass.
  if (/^[a-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$/.test(trimmed)) {
    const segs = trimmed.split('.');
    const root = segs[0] ?? '';
    if (
      segs.length <= 3 &&
      CODE_EXPR_ROOT_IDENTIFIERS.has(root) &&
      segs.every(isPlausibleCodeIdentifierSegment) &&
      (!requireCodeSyntaxHint || hasCodeTerminator)
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Escapes characters for safe RegExp construction.
 */
function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Sanitizes a single line if it resembles an environment variable assignment or key-value pair.
 */
function sanitizeKeyValueLine(
  line: string,
  replacement: string,
  customKeys?: (string | RegExp)[],
  safeKeyNames?: string[],
  findings: SecretFinding[] = [],
  safeValues?: Set<string>
): string {
  const stripQuotes = (raw: string): string =>
    (raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))
      ? raw.slice(1, -1)
      : raw;

  // 1. Env assignment: [export ]KEY=VALUE
  const envMatch = line.match(/^(\s*(?:export\s+)?)([a-zA-Z0-9_.-]+)(\s*=\s*)(.*)$/);
  if (envMatch) {
    const prefix = envMatch[1] ?? '';
    const key = envMatch[2] ?? '';
    const eq = envMatch[3] ?? '';
    const rawVal = envMatch[4] ?? '';

    const unquotedEnvVal = stripQuotes(rawVal);
    if (
      unquotedEnvVal.trim().length > 0 &&
      unquotedEnvVal !== replacement &&
      isSensitiveKey(key, customKeys, safeKeyNames) &&
      !safeValues?.has(unquotedEnvVal)
    ) {
      findings.push({ kind: 'key-value', category: 'env-assignment', keyName: key });
      // Preserve quotes if present
      if (
        (rawVal.startsWith('"') && rawVal.endsWith('"')) ||
        (rawVal.startsWith("'") && rawVal.endsWith("'"))
      ) {
        const quote = rawVal[0];
        return `${prefix}${key}${eq}${quote}${replacement}${quote}`;
      }
      return `${prefix}${key}${eq}${replacement}`;
    }
  }

  // 2. YAML / Header assignment: KEY: VALUE (including YAML sequence items: - KEY: VALUE)
  const yamlMatch = line.match(/^(\s*(?:-\s+)?["']?)([a-zA-Z0-9_.-]+)(["']?\s*:\s*)(.*)$/);
  if (yamlMatch) {
    const prefix = yamlMatch[1] ?? '';
    const key = yamlMatch[2] ?? '';
    const colon = yamlMatch[3] ?? '';
    const rawVal = yamlMatch[4] ?? '';
    const unquotedYamlVal = stripQuotes(rawVal);
    const isQuotedYamlVal = unquotedYamlVal !== rawVal;
    const isAuthOrCookieKey = /^(?:proxy[_-]?)?authorization$|^(?:set[_-]?)?cookie$/i.test(key);

    if (
      unquotedYamlVal.trim().length > 0 &&
      unquotedYamlVal !== replacement &&
      (isQuotedYamlVal || isAuthOrCookieKey || !isCodeExpressionValue(rawVal, true)) &&
      isSensitiveKey(key, customKeys, safeKeyNames) &&
      !safeValues?.has(unquotedYamlVal)
    ) {
      findings.push({ kind: 'key-value', category: 'yaml-assignment', keyName: key });
      if (
        (rawVal.startsWith('"') && rawVal.endsWith('"')) ||
        (rawVal.startsWith("'") && rawVal.endsWith("'"))
      ) {
        const quote = rawVal[0];
        return `${prefix}${key}${colon}${quote}${replacement}${quote}`;
      }
      return `${prefix}${key}${colon}${replacement}`;
    }
  }

  return line;
}

/**
 * Sanitizes text content against all secret rules.
 */
export function sanitizeString(
  text: string,
  options: SanitizerOptions = {}
): SanitizeResult<string> {
  if (typeof text !== 'string') {
    return { sanitized: text, redactedCount: 0, findings: [] };
  }

  const safeValueSet = options.safeValues?.length ? new Set(options.safeValues) : undefined;
  if (safeValueSet?.has(text)) {
    return { sanitized: text, redactedCount: 0, findings: [] };
  }

  const replacement = options.replacement ?? DEFAULT_REPLACEMENT;
  const findings: SecretFinding[] = [];
  let redactedCount = 0;

  try {
    // Check if entire text is a JSON payload
    const trimmed = text.trim();
    if (
      (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
      (trimmed.startsWith('[') && trimmed.endsWith(']'))
    ) {
      try {
        const parsed = JSON.parse(text);
        const objResult = sanitizeObject(parsed, options);
        if (objResult.redactedCount > 0) {
          const indent = text.includes('\n') ? 2 : undefined;
          return {
            sanitized: JSON.stringify(objResult.sanitized, null, indent),
            redactedCount: objResult.redactedCount,
            findings: objResult.findings,
          };
        }
      } catch {
        // Not valid JSON, proceed with string processing
      }
    }

    let result = text;

    // Credential context is meaningful even when a query value has no known
    // token format and is not registered as a runtime literal.
    result = result.replace(/([?&])([^=&#\s]+)=([^&#\s]*)/g, (match, lead: string, key: string, val: string) => {
      if (!val || val === replacement) return match;
      let decodedVal = val;
      try { decodedVal = decodeURIComponent(val.replace(/\+/g, " ")); } catch {}
      if (safeValueSet?.has(val) || safeValueSet?.has(decodedVal)) return match;
      let decoded: string;
      try { decoded = decodeURIComponent(key.replace(/\+/g, " ")); } catch { decoded = key; }
      if (!isSensitiveKey(decoded, options.customSensitiveKeys, options.safeKeyNames)) return match;
      redactedCount++;
      findings.push({ kind: "key-value", category: "URL Query Credential" });
      return `${lead}${key}=${replacement}`;
    });

    // 1. Multiline PEM Private Key Blocks
    PEM_PRIVATE_KEY_REGEX.lastIndex = 0;
    if (PEM_PRIVATE_KEY_REGEX.test(result)) {
      result = result.replace(PEM_PRIVATE_KEY_REGEX, () => {
        redactedCount++;
        findings.push({ kind: 'private-key', category: 'PEM Private Key' });
        return `[REDACTED:PRIVATE_KEY]`;
      });
    }

    // 2. Connection Strings with embedded passwords
    CONNECTION_STRING_PASSWORD_REGEX.lastIndex = 0;
    if (CONNECTION_STRING_PASSWORD_REGEX.test(result)) {
      result = result.replace(
        CONNECTION_STRING_PASSWORD_REGEX,
        (_match, prefix, _password, suffix) => {
          redactedCount++;
          findings.push({ kind: 'connection-string', category: 'Database URI Password' });
          return `${prefix}${replacement}${suffix}`;
        }
      );
    }

    // 3. Line-by-line key-value checks (env, docker exec env, YAML including block scalars)
    const lines = result.split('\n');
    let lineModified = false;
    let activeYamlBlockIndent: number | null = null;
    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i] ?? '';
      const hasCr = rawLine.endsWith('\r');
      const original = hasCr ? rawLine.slice(0, -1) : rawLine;
      const eol = hasCr ? '\r' : '';
      if (activeYamlBlockIndent !== null) {
        if (original.trim().length === 0) {
          continue;
        }
        const indentMatch = /^(\s*)/.exec(original);
        const lineIndent = indentMatch?.[1]?.length ?? 0;
        if (lineIndent > activeYamlBlockIndent) {
          lines[i] = `${' '.repeat(lineIndent)}${replacement}${eol}`;
          lineModified = true;
          redactedCount++;
          findings.push({ kind: 'key-value', category: 'yaml-block-scalar' });
          continue;
        }
        activeYamlBlockIndent = null;
      }

      const yamlBlockHeader = /^(\s*(?:-\s+)?)(["']?)([a-zA-Z0-9_.-]+)(["']?\s*:\s*)([|>](?:[+-]?\d*|\d*[+-]?)\s*(?:#.*)?)$/.exec(original);
      if (
        yamlBlockHeader &&
        isSensitiveKey(yamlBlockHeader[3] ?? '', options.customSensitiveKeys, options.safeKeyNames)
      ) {
        const leadingIndent = yamlBlockHeader[1] ?? '';
        activeYamlBlockIndent = leadingIndent.length;
        lines[i] = `${leadingIndent}${yamlBlockHeader[2] ?? ''}${yamlBlockHeader[3] ?? ''}${yamlBlockHeader[4] ?? ''}${replacement}${eol}`;
        lineModified = true;
        redactedCount++;
        findings.push({ kind: 'key-value', category: 'yaml-assignment', keyName: yamlBlockHeader[3] ?? '' });
        continue;
      }

      const sanitized = sanitizeKeyValueLine(
        original,
        replacement,
        options.customSensitiveKeys,
        options.safeKeyNames,
        findings,
        safeValueSet
      );
      if (sanitized !== original) {
        lines[i] = sanitized + eol;
        lineModified = true;
        redactedCount++;
      }
    }
    if (lineModified) {
      result = lines.join('\n');
    }

    // 3b. Inline key-value assignments (e.g. "token=xyz", "password: xyz", "password=\"multi word\"", "--api-key=xyz")
    // Linearly consume arbitrarily long quoted values on the same line so tails past 4096 chars never leak.
    const customInlineStems = (options.customSensitiveKeys ?? [])
      .filter((k): k is string => typeof k === 'string')
      .map((k) => k.trim())
      .filter((k) => k.length > 0 && /^[a-zA-Z0-9_.-]+$/.test(k))
      .map(escapeRegExp);
    const hasRegexCustomKeys = (options.customSensitiveKeys ?? []).some(
      (k) => k instanceof RegExp
    );
    const defaultInlineStems =
      'token|api[_-]?key|secret|password|passwd|pass|auth[_-]?token|authorization|proxy[_-]authorization|cookie|set[_-]cookie|private[_-]?key|pin[_-]?code|credentials?|database_url|conn(?:ection)?[_-]?str(?:ing)?';
    const keyStemAlternation = customInlineStems.length > 0
      ? `(?:${defaultInlineStems}|${customInlineStems.join('|')})`
      : `(?:${defaultInlineStems})`;
    const isAuthHeaderKey = (k: string): boolean =>
      /^(?:proxy[_-]?)?authorization$|^(?:set[_-]?)?cookie$/i.test(k);
    const applyInlinePass = (prefixRegex: RegExp): void => {
      let out = '';
      let cursor = 0;
      prefixRegex.lastIndex = 0;
      let match = prefixRegex.exec(result);
      while (match !== null) {
        const matchStart = match.index;
        if (matchStart < cursor) {
          prefixRegex.lastIndex = cursor;
          match = prefixRegex.exec(result);
          continue;
        }
        const lead = match[1] ?? '';
        const key = match[2] ?? '';
        const sep = match[3] ?? '';
        const valStart = matchStart + match[0].length;
        if (valStart >= result.length) break;

        let valEnd = valStart;
        let val = '';
        let quoted = false;
        const firstCh = result[valStart];
        const isBareWhitespaceSep = /^\s+$/.test(sep);
        if (firstCh === '"' || firstCh === "'") {
          quoted = true;
          let i = valStart + 1;
          while (i < result.length && result[i] !== '\n' && result[i] !== '\r') {
            if (result[i] === '\\' && i + 1 < result.length && result[i + 1] !== '\n' && result[i + 1] !== '\r') {
              i += 2;
              continue;
            }
            if (result[i] === firstCh) {
              val = result.slice(valStart + 1, i);
              valEnd = i + 1;
              break;
            }
            i++;
          }
          if (valEnd === valStart) {
            // Unclosed quote on this line: redact through end of line.
            val = result.slice(valStart + 1, i);
            valEnd = i;
          }
        } else if (
          (lead === '"' || lead === "'") &&
          /^\s*[:=]\s*$/.test(sep) &&
          isAuthHeaderKey(key)
        ) {
          // Quoted HTTP header like `-H "Authorization: Basic dXNlcjpwYXNz"` or `-H 'Cookie: a=1; b=2'`
          let i = valStart;
          while (i < result.length && result[i] !== lead && result[i] !== '\n' && result[i] !== '\r') {
            if (result[i] === '\\' && lead === '"' && i + 1 < result.length) {
              i += 2;
              continue;
            }
            i++;
          }
          val = result.slice(valStart, i).trim();
          valEnd = i;
        } else {
          let i = valStart;
          let parenDepth = 0;
          while (i < result.length && result[i] !== '\n' && result[i] !== '\r') {
            const c = result[i]!;
            if (!isBareWhitespaceSep && c === '(') {
              parenDepth++;
              i++;
              continue;
            }
            if (!isBareWhitespaceSep && c === ')') {
              if (parenDepth > 0) {
                parenDepth--;
                i++;
                continue;
              }
              break;
            }
            if (parenDepth === 0 && (isBareWhitespaceSep ? /[\s,;)"'>]/.test(c) : /[\s,;"'>]/.test(c))) {
              break;
            }
            i++;
          }
          val = result.slice(valStart, i);
          valEnd = i;
          // Consume `Scheme <credential>` pair for Authorization headers (e.g. Authorization: Basic dXNlcjpwYXNz)
          if (
            /^(?:basic|bearer|token|digest|apikey|bot|oauth)$/i.test(val) &&
            result[i] === ' '
          ) {
            let j = i;
            while (j < result.length && result[j] === ' ') j++;
            const credStart = j;
            while (j < result.length && !/[\s,;)"'>\n\r]/.test(result[j]!)) j++;
            if (j > credStart) {
              val = result.slice(valStart, j);
              valEnd = j;
            }
          }
        }

        const isPlainProseWord =
          /^[A-Za-z][a-z]{2,}[.,;:!?]?$/.test(val) ||
          /^\([A-Za-z][a-z]{2,}\)?[.,;:!?]?$/.test(val);
        const skipBareSpaceProse =
          isBareWhitespaceSep &&
          !quoted &&
          (val.length < 6 ||
            val.startsWith('(') ||
            INLINE_STOPWORDS.has(val.toLowerCase()) ||
            (!key.startsWith('-') && isPlainProseWord));
        const isColonSep = sep.includes(':');
        const skipCodeAnnotation =
          !quoted &&
          isColonSep &&
          !isAuthHeaderKey(key) &&
          !sep.startsWith('"') &&
          !sep.startsWith("'") &&
          isCodeExpressionValue(val, false);

        const isRuntimeMetaProperty =
          /\.(?:lastIndex|source|flags|length|prototype|name|message|stack)$/i.test(key);
        const isMarkdownProseCodeToken =
          !quoted &&
          isColonSep &&
          /^`[a-z][a-z_-]{1,20}`[.,;:!?]?$/.test(val);

        const shouldRedact =
          val.length > 0 &&
          !isRuntimeMetaProperty &&
          !isMarkdownProseCodeToken &&
          isSensitiveKey(key, options.customSensitiveKeys, options.safeKeyNames) &&
          val !== replacement &&
          val !== '[REDACTED:PRIVATE_KEY]' &&
          !safeValueSet?.has(val) &&
          !skipBareSpaceProse &&
          !skipCodeAnnotation;

        if (shouldRedact) {
          const outVal = quoted ? `${firstCh}${replacement}${firstCh}` : replacement;
          out += result.slice(cursor, matchStart) + `${lead}${key}${sep}${outVal}`;
          cursor = valEnd;
          redactedCount++;
          findings.push({ kind: 'key-value', category: 'inline-assignment', keyName: key });
          prefixRegex.lastIndex = cursor;
        } else if (valStart > matchStart + 1) {
          // Rewind to the delimiter right before `valStart` so a non-sensitive prefix
          // like `log: ` never swallows the leading delimiter of an immediately following
          // custom key like `x_vault_key=...`.
          prefixRegex.lastIndex = valStart - 1;
        }
        match = prefixRegex.exec(result);
      }
      if (cursor > 0) {
        out += result.slice(cursor);
        result = out;
      }
    };
    applyInlinePass(
      new RegExp(
        `(^|[\\s,;([{"'=])([a-zA-Z0-9_.-]{0,64}${keyStemAlternation}[a-zA-Z0-9_.-]{0,64})(["']?[ \\t]*[:=][ \\t]*|[ \\t]+)`,
        'gi'
      )
    );
    if (hasRegexCustomKeys) {
      applyInlinePass(
        /(^|[\s,;([{"'=])([a-zA-Z0-9_.-]{2,80})(["']?[ \t]*[:=][ \t]*)/gi
      );
    }

    // 4. Known Credential Value Formats (OpenAI, Stripe, GitHub, Slack, AWS, Google, etc.)
    for (const pattern of KNOWN_CREDENTIAL_PATTERNS) {
      pattern.regex.lastIndex = 0;
      if (pattern.regex.test(result)) {
        result = result.replace(pattern.regex, (matched) => {
          if (safeValueSet?.has(matched)) return matched;
          redactedCount++;
          findings.push({ kind: 'known-pattern', category: pattern.name });
          return replacement;
        });
      }
    }

    // 5. Bearer tokens
    const bearerRegex = /\bBearer\s+([A-Za-z0-9._~-]{24,})\b/gi;
    if (bearerRegex.test(result)) {
      result = result.replace(bearerRegex, (matched, token) => {
        if (safeValueSet?.has(matched) || safeValueSet?.has(token)) return matched;
        redactedCount++;
        findings.push({ kind: 'known-pattern', category: 'Bearer Token' });
        return `Bearer ${replacement}`;
      });
    }

    // 6. Password Hashes (bcrypt, argon2, sha512crypt, scrypt)
    for (const p of PASSWORD_HASH_PATTERNS) {
      p.regex.lastIndex = 0;
      if (p.regex.test(result)) {
        result = result.replace(p.regex, (matched) => {
          if (safeValueSet?.has(matched)) return matched;
          redactedCount++;
          findings.push({ kind: 'password-hash', category: p.name });
          return replacement;
        });
      }
    }

    // 7. Runtime-Discovered Environment Secrets & Custom Secret Values
    const runtimeSecrets =
      options.includeRuntimeEnv !== false
        ? defaultRuntimeSecrets.getSecrets()
        : [];
    const allSecretLiterals = [
      ...runtimeSecrets,
      ...(options.customSecretValues ?? []),
    ].sort((a, b) => b.length - a.length);

    // Dedup secret literals
    const seenLiterals = new Set<string>();
    for (const secretVal of allSecretLiterals) {
      if (!secretVal || secretVal.length < 6 || seenLiterals.has(secretVal) || safeValueSet?.has(secretVal)) continue;
      seenLiterals.add(secretVal);

      if (result.includes(secretVal)) {
        const escaped = escapeRegExp(secretVal);
        const re = new RegExp(escaped, 'g');
        result = result.replace(re, () => {
          redactedCount++;
          findings.push({ kind: 'runtime-secret', category: 'Runtime Env Secret' });
          return replacement;
        });
      }
    }

    return { sanitized: result, redactedCount, findings };
  } catch (err) {
    void err;
    options.logger?.('Sanitization error encountered');
    return {
      sanitized: FAIL_SAFE_OUTPUT,
      redactedCount: 1,
      findings: [{ kind: 'runtime-secret', category: 'FailSafe' }],
    };
  }
}

const UUID_TOKEN_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NUMERIC_COUNTER_KEY_REGEX =
  /(?:[_-]?(?:count|total|len|length|size|limit|max|min|ttl|ms|sec|seconds|timeout|retries|attempts|version|port|age|timestamp|index|idx))$/i;

export function neutralizeInheritedSerializer(
  output: Record<string, unknown>,
  proto: object | null,
  options: SanitizerOptions,
  replacement: string
): void {
  if (!proto || proto === Object.prototype) return;
  if (typeof (proto as Record<string, unknown>).toJSON === 'function') {
    Object.defineProperty(output, 'toJSON', {
      value() {
        const plain: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(output)) {
          plain[k] = v;
        }
        return plain;
      },
      enumerable: false,
      writable: true,
      configurable: true,
    });
  }
  let cursor: object | null = proto;
  while (cursor && cursor !== Object.prototype) {
    for (const propName of Object.getOwnPropertyNames(cursor)) {
      if (propName === 'constructor' || propName === 'toJSON' || Object.hasOwn(output, propName)) continue;
      const desc = Object.getOwnPropertyDescriptor(cursor, propName);
      if (desc && typeof desc.get === 'function' && isSensitiveKey(propName, options.customSensitiveKeys, options.safeKeyNames)) {
        Object.defineProperty(output, propName, {
          value: replacement,
          enumerable: desc.enumerable ?? false,
          writable: true,
          configurable: true,
        });
      }
    }
    cursor = Object.getPrototypeOf(cursor);
  }
}

/**
 * Recursively sanitizes JavaScript objects, arrays, and Error instances.
 */
export function sanitizeObject<T>(
  data: T,
  options: SanitizerOptions = {},
  rootInsideMeshEnvelope = false
): SanitizeResult<T> {
  const replacement = options.replacement ?? DEFAULT_REPLACEMENT;
  const findings: SecretFinding[] = [];
  let redactedCount = 0;
  const seenObjects = new WeakMap<object, unknown>();

  try {
    function propertyValue(key: string, value: unknown, insideMeshEnvelope = false): unknown {
      if (
        value === null ||
        value === undefined ||
        typeof value === 'boolean' ||
        value === ''
      ) {
        return value;
      }
      if (typeof value === 'number') {
        if (
          !NUMERIC_COUNTER_KEY_REGEX.test(key) &&
          isSensitiveKey(key, options.customSensitiveKeys, options.safeKeyNames)
        ) {
          redactedCount++;
          findings.push({ kind: 'key-value', category: 'Object Property', keyName: key });
          return replacement;
        }
        return value;
      }
      if (typeof value === 'string' && Array.isArray(options.safeValues) && options.safeValues.includes(value)) {
        return value;
      }
      const isValidMeshUuidToken =
        insideMeshEnvelope &&
        key === 'token' &&
        typeof value === 'string' &&
        UUID_TOKEN_REGEX.test(value);
      if (
        !isValidMeshUuidToken &&
        isSensitiveKey(key, options.customSensitiveKeys, options.safeKeyNames)
      ) {
        redactedCount++;
        findings.push({ kind: 'key-value', category: 'Object Property', keyName: key });
        return replacement;
      }
      const isMeshEnvelopeCandidate =
        key === 'opencode-mesh' &&
        Boolean(value) &&
        typeof value === 'object' &&
        !Array.isArray(value) &&
        (value as Record<string, unknown>).v === 2 &&
        typeof (value as Record<string, unknown>).owner === 'string' &&
        typeof (value as Record<string, unknown>).kind === 'string';
      return recurse(value, isMeshEnvelopeCandidate);
    }

    function recurse(val: unknown, insideMeshEnvelope = false): unknown {
      if (val === null || val === undefined) return val;
      // Retained callbacks (notably toJSON) could reintroduce raw data later,
      // when the host serializes a result that has already been sanitized.
      if (typeof val === 'function') return undefined;

      if (typeof val === 'string') {
        const res = sanitizeString(val, options);
        if (res.redactedCount > 0) {
          redactedCount += res.redactedCount;
          findings.push(...res.findings);
        }
        return res.sanitized;
      }

      if (typeof val === 'object') {
        if (seenObjects.has(val)) {
          return seenObjects.get(val);
        }
      }

      if (val instanceof Date) {
        return new Date(val.getTime());
      }

      if (val instanceof RegExp) {
        const res = sanitizeString(val.source, options);
        if (res.redactedCount > 0) {
          redactedCount += res.redactedCount;
          findings.push(...res.findings);
          try {
            return new RegExp(res.sanitized.replace(/\[REDACTED\]/g, 'REDACTED'), val.flags);
          } catch {
            return new RegExp('REDACTED', val.flags);
          }
        }
        return new RegExp(val.source, val.flags);
      }

      if (val instanceof Error) {
        const output = new Error();
        const errProto = Object.getPrototypeOf(val);
        if (errProto && errProto !== Error.prototype) {
          try { Object.setPrototypeOf(output, errProto); } catch {}
        }
        seenObjects.set(val, output);
        // Error.cause and AggregateError.errors are non-enumerable. Inspect
        // every own property, including provider metadata, at the same boundary.
        const standardErrorKeys = new Set(['name', 'message', 'stack', 'cause', 'errors', 'code']);
        for (const key of new Set(['name', ...Object.getOwnPropertyNames(val)])) {
          const value = (val as unknown as Record<string, unknown>)[key];
          let outKey = key;
          if (!standardErrorKeys.has(key)) {
            const keyScan = sanitizeString(key, options);
            if (keyScan.redactedCount > 0) {
              redactedCount += keyScan.redactedCount;
              findings.push(...keyScan.findings);
              outKey = keyScan.sanitized;
            }
            if (Object.hasOwn(output, outKey)) {
              let suffix = 2;
              while (Object.hasOwn(output, `${outKey}#${suffix}`)) suffix++;
              outKey = `${outKey}#${suffix}`;
            }
          }
          Object.defineProperty(output, outKey, {
            value: propertyValue(key, value),
            enumerable: Object.getOwnPropertyDescriptor(val, key)?.enumerable ?? false,
            writable: true,
            configurable: true,
          });
        }
        neutralizeInheritedSerializer(
          output as unknown as Record<string, unknown>,
          errProto,
          options,
          replacement
        );
        return output;
      }

      const isLikelyTextBytes = (bytes: Uint8Array, allowNul: boolean): boolean => {
        if (bytes.byteLength === 0) return false;
        // Preserve binary media/archive headers untouched (PNG, JPEG, GIF, PDF, ZIP, GZIP, ELF).
        if (bytes.byteLength >= 4) {
          const b0 = bytes[0], b1 = bytes[1], b2 = bytes[2], b3 = bytes[3];
          if (
            (b0 === 0x89 && b1 === 0x50 && b2 === 0x4e && b3 === 0x47) ||
            (b0 === 0xff && b1 === 0xd8 && b2 === 0xff) ||
            (b0 === 0x47 && b1 === 0x49 && b2 === 0x46 && b3 === 0x38) ||
            (b0 === 0x25 && b1 === 0x50 && b2 === 0x44 && b3 === 0x46) ||
            (b0 === 0x50 && b1 === 0x4b && b2 === 0x03 && b3 === 0x04) ||
            (b0 === 0x1f && b1 === 0x8b) ||
            (b0 === 0x7f && b1 === 0x45 && b2 === 0x4c && b3 === 0x46)
          ) {
            return false;
          }
        }
        const sampleLen = Math.min(bytes.byteLength, 4096);
        let controlBytes = 0;
        for (let i = 0; i < sampleLen; i++) {
          const b = bytes[i]!;
          if (b === 0) {
            if (!allowNul) return false;
            continue;
          }
          if (b < 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d) {
            controlBytes++;
          }
        }
        return controlBytes / sampleLen <= 0.05;
      };

      const sanitizeTextBytes = (bytes: Uint8Array): Buffer | undefined => {
        if (bytes.byteLength === 0 || bytes.byteLength > 16 * 1024 * 1024 || !isLikelyTextBytes(bytes, true)) {
          return undefined;
        }
        const bufView = Buffer.isBuffer(bytes)
          ? bytes
          : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        if (bufView.includes(0)) {
          // NUL-delimited text buffers (e.g. /proc/self/environ): sanitize each NUL-separated record.
          const decoded = bufView.toString('utf8');
          const parts = decoded.split('\0');
          let anyRedacted = false;
          const outParts = parts.map((segment) => {
            if (!segment) return segment;
            const res = sanitizeString(segment, options);
            if (res.redactedCount > 0) {
              anyRedacted = true;
              redactedCount += res.redactedCount;
              findings.push(...res.findings);
              return res.sanitized;
            }
            return segment;
          });
          if (anyRedacted) {
            return Buffer.from(outParts.join('\0'), 'utf8');
          }
          return undefined;
        }
        if (bufView.byteLength <= 2 * 1024 * 1024) {
          const decoded = bufView.toString('utf8');
          const res = sanitizeString(decoded, options);
          if (res.redactedCount > 0) {
            redactedCount += res.redactedCount;
            findings.push(...res.findings);
            return Buffer.from(res.sanitized, 'utf8');
          }
          return undefined;
        }
        // Chunk large UTF-8 text buffers (>2 MiB) into 1 MiB line-aligned slices,
        // extending across PEM PRIVATE KEY blocks, arbitrarily long indented YAML block scalars,
        // and any single-line key=value or secret straddling a boundary without newlines.
        const decoded = bufView.toString('utf8');
        const CHUNK = 1024 * 1024;
        const MAX_BLOCK_EXTEND = 256 * 1024;
        let out = '';
        let anyRedacted = false;
        for (let pos = 0; pos < decoded.length; ) {
          let end = Math.min(pos + CHUNK, decoded.length);
          if (end < decoded.length) {
            const nl = decoded.lastIndexOf('\n', end);
            if (nl > pos) {
              end = nl + 1;
            } else {
              // No newline in chunk: scan forward from `pos` with exact quote/escape tracking
              // (ignoring intra-word apostrophes like `don't`) so we never cut inside an open
              // quoted string (even >2048 chars) and never cut around key/flag/auth-scheme
              // delimiters (`password: `, `"password" : `, `database_url = `, `Bearer `, `--token `).
              let inDq = false;
              let inSq = false;
              let escaped = false;
              let lastSafeCut = -1;
              let lastStructCut = -1;
              const minCut = pos + 1024;
              for (let k = pos; k < end; k++) {
                const ch = decoded[k]!;
                if (escaped) { escaped = false; continue; }
                if (ch === '\\' && (inDq || inSq)) { escaped = true; continue; }
                if (ch === '"' && !inSq) { inDq = !inDq; continue; }
                if (ch === "'" && !inDq) {
                  // Do not treat English intra-word apostrophes (`don't`, `it's`) as opening single-quoted strings.
                  if (!inSq && k > pos && /[A-Za-z]/.test(decoded[k - 1]!) && k + 1 < end && /[A-Za-z]/.test(decoded[k + 1]!)) {
                    continue;
                  }
                  inSq = !inSq;
                  continue;
                }
                if (!inDq && !inSq && k >= minCut) {
                  if (ch === ',' || ch === ';' || ch === '}' || ch === ']') {
                    lastStructCut = k + 1;
                    lastSafeCut = k + 1;
                  } else if (ch === ' ' || ch === '\t') {
                    const beforeWs = decoded.slice(Math.max(pos, k - 64), k).trimEnd();
                    const afterWs = decoded.slice(k + 1, Math.min(decoded.length, k + 17));
                    const unsafeNext = /^[ \t]*[:=]/.test(afterWs);
                    const unsafePrefix =
                      unsafeNext ||
                      /[:=]$/.test(beforeWs) ||
                      /(?:^|[\s,;{[("'])(?:bearer|basic|token|digest|apikey|oauth|jwt|hoba|mutual|negotiate|scram-sha-256)$/i.test(beforeWs) ||
                      /(?:^|\s)--?[A-Za-z0-9_-]+$/.test(beforeWs) ||
                      /(?:^|[\s,;{[("'])[A-Za-z0-9_.-]*(?:pass(?:word|wd|phrase)?|secret|token|key|auth|cred(?:ential)?|cookie|session|jwt|pwd|pin|database[_-]?url|conn(?:ection)?[_-]?str(?:ing)?|dsn)[A-Za-z0-9_.-]*["']?$/i.test(beforeWs);
                    if (!unsafePrefix) {
                      lastSafeCut = k + 1;
                    }
                  }
                }
              }
              const preferredCut = lastSafeCut > pos ? lastSafeCut : lastStructCut;
              if (preferredCut > pos) {
                end = preferredCut;
              } else {
                // Still inside an unsplit token or >1 MiB quoted string: extend past closing quote
                // and always run a boundary probe if closing quote was not reached within MAX_BLOCK_EXTEND.
                let closedQuote = false;
                if (inDq || inSq) {
                  const targetQuote = inDq ? '"' : "'";
                  let ext = end;
                  let extEsc = escaped;
                  const maxExt = Math.min(decoded.length, end + MAX_BLOCK_EXTEND);
                  while (ext < maxExt) {
                    const c = decoded[ext++]!;
                    if (extEsc) { extEsc = false; continue; }
                    if (c === '\\') { extEsc = true; continue; }
                    if (c === targetQuote) { closedQuote = true; break; }
                  }
                  end = ext;
                }
                if (!closedQuote && end < decoded.length) {
                  const boundaryProbe = decoded.slice(
                    Math.max(pos, end - 512),
                    Math.min(decoded.length, end + 512)
                  );
                  if (sanitizeString(boundaryProbe, options).redactedCount > 0) {
                    end = Math.min(decoded.length, end + 512);
                  }
                }
              }
            }
            const candidate = decoded.slice(pos, end);
            const lastBegin = candidate.lastIndexOf('-----BEGIN');
            const lastEnd = candidate.lastIndexOf('-----END');
            if (lastBegin >= 0 && lastBegin > lastEnd) {
              const closingSearch = decoded.slice(end, Math.min(decoded.length, end + MAX_BLOCK_EXTEND));
              const endMarker = /-----END(?:\s+[A-Z0-9_-]+)?\s+PRIVATE\s+KEY-----\r?\n?/.exec(closingSearch);
              if (endMarker) {
                end = end + endMarker.index + endMarker[0].length;
              }
            }
            // Scan the entire chunk linearly for an active YAML block scalar straddling `end`
            // (so YAML blocks >4 KiB are never cut mid-block).
            let activeIndent: number | null = null;
            let linePos = pos;
            while (linePos < end) {
              const nextNl = decoded.indexOf('\n', linePos);
              const lineStop = nextNl === -1 || nextNl >= end ? end : nextNl;
              const l = decoded.slice(linePos, lineStop).replace(/\r$/, '');
              linePos = lineStop < end ? lineStop + 1 : end;
              if (activeIndent !== null) {
                if (l.trim().length === 0) continue;
                const ind = /^(\s*)/.exec(l)?.[1]?.length ?? 0;
                if (ind > activeIndent) continue;
                activeIndent = null;
              }
              if (l.includes(':') && (l.includes('|') || l.includes('>'))) {
                const hdr = /^(\s*(?:-\s+)?)(["']?)([a-zA-Z0-9_.-]+)(["']?\s*:\s*)([|>](?:[+-]?\d*|\d*[+-]?)\s*(?:#.*)?)$/.exec(l);
                if (hdr && isSensitiveKey(hdr[3] ?? '', options.customSensitiveKeys, options.safeKeyNames)) {
                  activeIndent = (hdr[1] ?? '').length;
                }
              }
            }
            if (activeIndent !== null) {
              let cursorPos = end;
              const limit = Math.min(decoded.length, end + MAX_BLOCK_EXTEND);
              while (cursorPos < limit) {
                const nextNl = decoded.indexOf('\n', cursorPos);
                const lineEnd = nextNl === -1 ? decoded.length : nextNl + 1;
                const lineText = decoded.slice(cursorPos, nextNl === -1 ? decoded.length : nextNl).replace(/\r$/, '');
                if (lineText.trim().length === 0) {
                  cursorPos = lineEnd;
                  continue;
                }
                const ind = /^(\s*)/.exec(lineText)?.[1]?.length ?? 0;
                if (ind > activeIndent) {
                  cursorPos = lineEnd;
                  continue;
                }
                break;
              }
              end = cursorPos;
            }
          }
          const slice = decoded.slice(pos, end);
          const res = sanitizeString(slice, options);
          if (res.redactedCount > 0) {
            anyRedacted = true;
            redactedCount += res.redactedCount;
            findings.push(...res.findings);
            out += res.sanitized;
          } else {
            out += slice;
          }
          pos = end;
        }
        if (anyRedacted) {
          return Buffer.from(out, 'utf8');
        }
        return undefined;
      };

      if (Buffer.isBuffer(val)) {
        const sanitizedBuf = sanitizeTextBytes(val);
        return sanitizedBuf ?? val;
      }

      if (val instanceof Uint8Array && !(val instanceof Buffer)) {
        const sanitizedBuf = sanitizeTextBytes(val);
        return sanitizedBuf ? new Uint8Array(sanitizedBuf) : val;
      }

      if (ArrayBuffer.isView(val) || val instanceof ArrayBuffer) {
        return val;
      }

      if (Array.isArray(val)) {
        const arrOut: unknown[] = [];
        seenObjects.set(val, arrOut);
        for (const item of val) {
          arrOut.push(recurse(item));
        }
        return arrOut;
      }

      if (typeof val === 'object') {
        const proto = Object.getPrototypeOf(val);
        const output: Record<string, unknown> =
          proto === null
            ? Object.create(null)
            : proto !== Object.prototype
              ? Object.create(proto)
              : {};
        seenObjects.set(val, output);
        for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
          const sanitizedVal = propertyValue(k, v, insideMeshEnvelope);
          const keyScan = sanitizeString(k, options);
          let outKey = k;
          if (keyScan.redactedCount > 0) {
            redactedCount += keyScan.redactedCount;
            findings.push(...keyScan.findings);
            outKey = keyScan.sanitized;
          }
          if (Object.hasOwn(output, outKey)) {
            let suffix = 2;
            while (Object.hasOwn(output, `${outKey}#${suffix}`)) suffix++;
            outKey = `${outKey}#${suffix}`;
          }
          Object.defineProperty(output, outKey, {
            value: sanitizedVal, enumerable: true, writable: true, configurable: true,
          });
        }
        neutralizeInheritedSerializer(output, proto, options, replacement);
        return output;
      }

      return val;
    }

    const sanitized = recurse(data, rootInsideMeshEnvelope) as T;
    return { sanitized, redactedCount, findings };
  } catch (err) {
    void err;
    options.logger?.('Object sanitization error encountered');
    return {
      sanitized: FAIL_SAFE_OUTPUT as unknown as T,
      redactedCount: 1,
      findings: [{ kind: 'runtime-secret', category: 'FailSafe' }],
    };
  }
}

/**
 * Universal Tool Result Sanitizer with redaction metadata.
 * Runs a single pass over any tool result shape (string, Error, V2 { content, output, metadata },
 * process { stdout, stderr }, or generic object/array) so callers do not need JSON.stringify diffs.
 */
export function sanitizeToolResultWithMeta<T>(
  result: T,
  options: SanitizerOptions = {}
): { sanitized: T; redactedCount: number } {
  if (result === null || result === undefined) {
    return { sanitized: result, redactedCount: 0 };
  }
  try {
    if (typeof result === 'string') {
      const res = sanitizeString(result, options);
      return { sanitized: res.sanitized as unknown as T, redactedCount: res.redactedCount };
    }

    if (typeof result === 'object') {
      const res = sanitizeObject(result, options);
      return { sanitized: res.sanitized, redactedCount: res.redactedCount };
    }

    return { sanitized: result, redactedCount: 0 };
  } catch {
    return { sanitized: FAIL_SAFE_OUTPUT as unknown as T, redactedCount: 1 };
  }
}

/**
 * Universal Tool Result Sanitizer.
 * Safely transforms any tool result shape (string, { output, metadata }, { stdout, stderr }, MCP content)
 * into a sanitized version without modifying internal non-string metadata.
 */
export function sanitizeToolResult<T>(result: T, options: SanitizerOptions = {}): T {
  return sanitizeToolResultWithMeta(result, options).sanitized;
}

/**
 * Sanitizes an array of session messages and parts before sending to the model context.
 */
export function sanitizeMessages<T = unknown>(messages: T[], options: SanitizerOptions = {}): T[] {
  if (!Array.isArray(messages)) return messages;

  try {
    return messages.map((msg) => {
      if (!msg || typeof msg !== 'object') return msg;
      const msgObj = msg as Record<string, unknown>;

      // Handle message with parts: { info, parts: [...] } while preserving Message/Part prototypes
      if (Array.isArray(msgObj.parts)) {
        const sanitizedParts = msgObj.parts.map((part) => {
          if (!part || typeof part !== 'object') return part;
          return sanitizeObject(part, options).sanitized;
        });
        const msgProto = Object.getPrototypeOf(msgObj);
        const clonedMsg: Record<string, unknown> =
          msgProto && msgProto !== Object.prototype ? Object.create(msgProto) : {};
        for (const [k, v] of Object.entries(msgObj)) {
          if (k === 'parts') continue;
          const isValidMeshEnv =
            k === 'opencode-mesh' &&
            Boolean(v) &&
            typeof v === 'object' &&
            !Array.isArray(v) &&
            (v as Record<string, unknown>).v === 2 &&
            typeof (v as Record<string, unknown>).owner === 'string' &&
            typeof (v as Record<string, unknown>).kind === 'string';
          const sanitizedVal =
            v === null || v === undefined || typeof v === 'boolean' || v === ''
              ? v
              : typeof v === 'number'
                ? (!NUMERIC_COUNTER_KEY_REGEX.test(k) &&
                    isSensitiveKey(k, options.customSensitiveKeys, options.safeKeyNames)
                    ? (options.replacement ?? DEFAULT_REPLACEMENT)
                    : v)
                : typeof v === 'string' && Array.isArray(options.safeValues) && options.safeValues.includes(v)
                  ? v
                  : isSensitiveKey(k, options.customSensitiveKeys, options.safeKeyNames)
                    ? (options.replacement ?? DEFAULT_REPLACEMENT)
                    : sanitizeObject(v, options, isValidMeshEnv).sanitized;
          Object.defineProperty(clonedMsg, k, {
            value: sanitizedVal,
            enumerable: true,
            writable: true,
            configurable: true,
          });
        }
        Object.defineProperty(clonedMsg, 'parts', {
          value: sanitizedParts,
          enumerable: true,
          writable: true,
          configurable: true,
        });
        neutralizeInheritedSerializer(clonedMsg, msgProto, options, options.replacement ?? DEFAULT_REPLACEMENT);
        return clonedMsg as unknown as T;
      }

      return sanitizeObject(msg, options).sanitized;
    });
  } catch {
    // FINAL context sanitization is a security boundary. Returning the source
    // messages here would fail open and could expose the exact content whose
    // sanitization failed. Suppress the context instead.
    return [];
  }
}

/**
 * Resolves SanitizerOptions from GuardianConfig or returns null if explicitly disabled.
 */
export function resolveSanitizerOptions(config?: {
  secrets?: {
    enabled?: boolean | undefined;
    replacement?: string | undefined;
    customSensitiveKeys?: (string | RegExp)[] | undefined;
    customSecretValues?: string[] | undefined;
    includeRuntimeEnv?: boolean | undefined;
    safeKeyNames?: string[] | undefined;
    safeValues?: string[] | undefined;
  } | undefined;
} | undefined): SanitizerOptions | null {
  if (config?.secrets?.enabled === false) {
    return null;
  }
  return {
    replacement: typeof config?.secrets?.replacement === 'string' ? config.secrets.replacement : DEFAULT_REPLACEMENT,
    customSensitiveKeys: config?.secrets?.customSensitiveKeys,
    customSecretValues: config?.secrets?.customSecretValues,
    includeRuntimeEnv: config?.secrets?.includeRuntimeEnv !== false,
    safeKeyNames: config?.secrets?.safeKeyNames,
    safeValues: config?.secrets?.safeValues,
  };
}

