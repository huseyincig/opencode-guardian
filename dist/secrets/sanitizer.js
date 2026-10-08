import { CONNECTION_STRING_PASSWORD_REGEX, isSensitiveKey, KNOWN_CREDENTIAL_PATTERNS, PASSWORD_HASH_PATTERNS, PEM_PRIVATE_KEY_REGEX, } from './patterns.js';
import { defaultRuntimeSecrets } from './runtime-secrets.js';
const INLINE_STOPWORDS = new Set([
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
/**
 * Escapes characters for safe RegExp construction.
 */
function escapeRegExp(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
/**
 * Sanitizes a single line if it resembles an environment variable assignment or key-value pair.
 */
function sanitizeKeyValueLine(line, replacement, customKeys, safeKeyNames, findings = []) {
    // 1. Env assignment: [export ]KEY=VALUE
    const envMatch = line.match(/^(\s*(?:export\s+)?)([a-zA-Z0-9_.-]+)(\s*=\s*)(.*)$/);
    if (envMatch) {
        const prefix = envMatch[1] ?? '';
        const key = envMatch[2] ?? '';
        const eq = envMatch[3] ?? '';
        const rawVal = envMatch[4] ?? '';
        if (isSensitiveKey(key, customKeys, safeKeyNames)) {
            findings.push({ kind: 'key-value', category: 'env-assignment', keyName: key });
            // Preserve quotes if present
            if ((rawVal.startsWith('"') && rawVal.endsWith('"')) ||
                (rawVal.startsWith("'") && rawVal.endsWith("'"))) {
                const quote = rawVal[0];
                return `${prefix}${key}${eq}${quote}${replacement}${quote}`;
            }
            return `${prefix}${key}${eq}${replacement}`;
        }
    }
    // 2. YAML / Header assignment: KEY: VALUE
    const yamlMatch = line.match(/^(\s*["']?)([a-zA-Z0-9_.-]+)(["']?\s*:\s*)(.*)$/);
    if (yamlMatch) {
        const prefix = yamlMatch[1] ?? '';
        const key = yamlMatch[2] ?? '';
        const colon = yamlMatch[3] ?? '';
        const rawVal = yamlMatch[4] ?? '';
        if (isSensitiveKey(key, customKeys, safeKeyNames)) {
            findings.push({ kind: 'key-value', category: 'yaml-assignment', keyName: key });
            if ((rawVal.startsWith('"') && rawVal.endsWith('"')) ||
                (rawVal.startsWith("'") && rawVal.endsWith("'"))) {
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
export function sanitizeString(text, options = {}) {
    if (typeof text !== 'string') {
        return { sanitized: text, redactedCount: 0, findings: [] };
    }
    const replacement = options.replacement ?? DEFAULT_REPLACEMENT;
    const findings = [];
    let redactedCount = 0;
    try {
        // Check if entire text is a JSON payload
        const trimmed = text.trim();
        if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
            (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
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
            }
            catch {
                // Not valid JSON, proceed with string processing
            }
        }
        let result = text;
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
            result = result.replace(CONNECTION_STRING_PASSWORD_REGEX, (_match, prefix, _password, suffix) => {
                redactedCount++;
                findings.push({ kind: 'connection-string', category: 'Database URI Password' });
                return `${prefix}${replacement}${suffix}`;
            });
        }
        // 3. Line-by-line key-value checks (env, docker exec env, etc.)
        const lines = result.split('\n');
        let lineModified = false;
        for (let i = 0; i < lines.length; i++) {
            const original = lines[i] ?? '';
            const sanitized = sanitizeKeyValueLine(original, replacement, options.customSensitiveKeys, options.safeKeyNames, findings);
            if (sanitized !== original) {
                lines[i] = sanitized;
                lineModified = true;
                redactedCount++;
            }
        }
        if (lineModified) {
            result = lines.join('\n');
        }
        // 3b. Inline key-value assignments (e.g. "token=xyz", "password: xyz", "password xyz", "--api-key=xyz")
        const inlineKvRegex = /(^|[\s,;([{"'=-])([a-zA-Z0-9_.-]*(?:token|api[_-]?key|secret|password|passwd|pass|auth[_-]?token)[a-zA-Z0-9_.-]*)(\s*[:=]\s*|\s+)["']?([^\s,;)"'>\n\r]+)["']?/gi;
        result = result.replace(inlineKvRegex, (match, lead, key, sep, val) => {
            if (!isSensitiveKey(key, options.customSensitiveKeys, options.safeKeyNames)) {
                return match;
            }
            if (val === replacement || val === '[REDACTED:PRIVATE_KEY]') {
                return match;
            }
            if (/^\s+$/.test(sep)) {
                if (val.length < 6 || INLINE_STOPWORDS.has(val.toLowerCase())) {
                    return match;
                }
            }
            redactedCount++;
            findings.push({ kind: 'key-value', category: 'inline-assignment', keyName: key });
            return `${lead}${key}${sep}${replacement}`;
        });
        // 4. Known Credential Value Formats (OpenAI, Stripe, GitHub, Slack, AWS, Google, etc.)
        for (const pattern of KNOWN_CREDENTIAL_PATTERNS) {
            pattern.regex.lastIndex = 0;
            if (pattern.regex.test(result)) {
                result = result.replace(pattern.regex, () => {
                    redactedCount++;
                    findings.push({ kind: 'known-pattern', category: pattern.name });
                    return replacement;
                });
            }
        }
        // 5. Bearer tokens
        const bearerRegex = /\bBearer\s+([A-Za-z0-9._~-]{24,})\b/gi;
        if (bearerRegex.test(result)) {
            result = result.replace(bearerRegex, () => {
                redactedCount++;
                findings.push({ kind: 'known-pattern', category: 'Bearer Token' });
                return `Bearer ${replacement}`;
            });
        }
        // 6. Password Hashes (bcrypt, argon2, sha512crypt, scrypt)
        for (const p of PASSWORD_HASH_PATTERNS) {
            p.regex.lastIndex = 0;
            if (p.regex.test(result)) {
                result = result.replace(p.regex, () => {
                    redactedCount++;
                    findings.push({ kind: 'password-hash', category: p.name });
                    return replacement;
                });
            }
        }
        // 7. Runtime-Discovered Environment Secrets & Custom Secret Values
        const runtimeSecrets = options.includeRuntimeEnv !== false
            ? defaultRuntimeSecrets.getSecrets()
            : [];
        const allSecretLiterals = [
            ...runtimeSecrets,
            ...(options.customSecretValues ?? []),
        ].sort((a, b) => b.length - a.length);
        // Dedup secret literals
        const seenLiterals = new Set();
        for (const secretVal of allSecretLiterals) {
            if (!secretVal || secretVal.length < 6 || seenLiterals.has(secretVal))
                continue;
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
    }
    catch (err) {
        void err;
        options.logger?.('Sanitization error encountered');
        return {
            sanitized: FAIL_SAFE_OUTPUT,
            redactedCount: 1,
            findings: [{ kind: 'runtime-secret', category: 'FailSafe' }],
        };
    }
}
/**
 * Recursively sanitizes JavaScript objects, arrays, and Error instances.
 */
export function sanitizeObject(data, options = {}) {
    const replacement = options.replacement ?? DEFAULT_REPLACEMENT;
    const findings = [];
    let redactedCount = 0;
    try {
        function recurse(val) {
            if (val === null || val === undefined)
                return val;
            if (typeof val === 'string') {
                const res = sanitizeString(val, options);
                if (res.redactedCount > 0) {
                    redactedCount += res.redactedCount;
                    findings.push(...res.findings);
                }
                return res.sanitized;
            }
            if (val instanceof Error) {
                const msgRes = sanitizeString(val.message, options);
                if (msgRes.redactedCount > 0) {
                    redactedCount += msgRes.redactedCount;
                    findings.push(...msgRes.findings);
                    val.message = msgRes.sanitized;
                }
                if (val.stack) {
                    const stackRes = sanitizeString(val.stack, options);
                    if (stackRes.redactedCount > 0) {
                        val.stack = stackRes.sanitized;
                    }
                }
                return val;
            }
            if (Array.isArray(val)) {
                return val.map((item) => recurse(item));
            }
            if (typeof val === 'object') {
                const output = {};
                for (const [k, v] of Object.entries(val)) {
                    if (isSensitiveKey(k, options.customSensitiveKeys, options.safeKeyNames)) {
                        redactedCount++;
                        findings.push({ kind: 'key-value', category: 'Object Property', keyName: k });
                        // A sensitive key defines the trust boundary for its complete value.
                        // Do not recurse into nested objects/arrays and retain an arbitrary
                        // secret under a non-sensitive child key.
                        output[k] = replacement;
                    }
                    else {
                        output[k] = recurse(v);
                    }
                }
                return output;
            }
            return val;
        }
        const sanitized = recurse(data);
        return { sanitized, redactedCount, findings };
    }
    catch (err) {
        void err;
        options.logger?.('Object sanitization error encountered');
        return {
            sanitized: FAIL_SAFE_OUTPUT,
            redactedCount: 1,
            findings: [{ kind: 'runtime-secret', category: 'FailSafe' }],
        };
    }
}
/**
 * Universal Tool Result Sanitizer.
 * Safely transforms any tool result shape (string, { output, metadata }, { stdout, stderr }, MCP content)
 * into a sanitized version without modifying internal non-string metadata.
 */
export function sanitizeToolResult(result, options = {}) {
    if (result === null || result === undefined)
        return result;
    try {
        if (typeof result === 'string') {
            return sanitizeString(result, options).sanitized;
        }
        if (result instanceof Error) {
            const sanitizedMsg = sanitizeString(result.message, options).sanitized;
            const errCopy = new Error(sanitizedMsg);
            errCopy.name = result.name;
            if (result.stack) {
                errCopy.stack = sanitizeString(result.stack, options).sanitized;
            }
            return errCopy;
        }
        if (typeof result === 'object') {
            // Check for common tool result shapes
            const resObj = result;
            // 1. OpenCode V1/V2 tool output shape: { title?, output, metadata? }
            if ('output' in resObj && typeof resObj.output === 'string') {
                const sanitizedOutput = sanitizeString(resObj.output, options).sanitized;
                return {
                    ...resObj,
                    output: sanitizedOutput,
                    ...(resObj.metadata ? { metadata: sanitizeObject(resObj.metadata, options).sanitized } : {}),
                };
            }
            // 2. Process stdout/stderr shape: { stdout, stderr, ... }.
            // Sanitize the complete envelope so sibling metadata/raw fields cannot
            // retain a secret after stdout/stderr themselves are redacted.
            if ('stdout' in resObj || 'stderr' in resObj) {
                return sanitizeObject(resObj, options).sanitized;
            }
            // 3. MCP/OpenCode content shape: { content: [...], output?, metadata? }.
            // Tool.Result officially allows output/content/metadata siblings. Never
            // sanitize only content and then spread raw sibling fields back in.
            if (Array.isArray(resObj.content)) {
                const sanitizedContent = resObj.content.map((item) => {
                    if (item && typeof item === 'object' && 'text' in item && typeof item.text === 'string') {
                        return {
                            ...sanitizeObject(item, options).sanitized,
                            text: sanitizeString(item.text, options).sanitized,
                        };
                    }
                    return sanitizeObject(item, options).sanitized;
                });
                const sanitizedEnvelope = sanitizeObject(resObj, options).sanitized;
                return {
                    ...sanitizedEnvelope,
                    content: sanitizedContent,
                };
            }
            // Generic object/array
            return sanitizeObject(result, options).sanitized;
        }
        return result;
    }
    catch {
        return FAIL_SAFE_OUTPUT;
    }
}
/**
 * Sanitizes an array of session messages and parts before sending to the model context.
 */
export function sanitizeMessages(messages, options = {}) {
    if (!Array.isArray(messages))
        return messages;
    try {
        return messages.map((msg) => {
            if (!msg || typeof msg !== 'object')
                return msg;
            const msgObj = msg;
            // Handle message with parts: { info, parts: [...] }
            if (Array.isArray(msgObj.parts)) {
                const sanitizedParts = msgObj.parts.map((part) => {
                    if (!part || typeof part !== 'object')
                        return part;
                    const partObj = { ...part };
                    if (partObj.type === 'text' && typeof partObj.text === 'string') {
                        partObj.text = sanitizeString(partObj.text, options).sanitized;
                    }
                    else if (partObj.type === 'tool' && partObj.state && typeof partObj.state === 'object') {
                        // FINAL context gate: sanitize the complete tool state, not only
                        // selected output/result/error fields. Host metadata/raw/content
                        // can also become model-visible when a POST adapter misses them.
                        partObj.state = sanitizeObject(partObj.state, options).sanitized;
                    }
                    else {
                        // General part fields
                        if (typeof partObj.content === 'string') {
                            partObj.content = sanitizeString(partObj.content, options).sanitized;
                        }
                    }
                    return partObj;
                });
                return { ...msgObj, parts: sanitizedParts };
            }
            return sanitizeObject(msg, options).sanitized;
        });
    }
    catch {
        // FINAL context sanitization is a security boundary. Returning the source
        // messages here would fail open and could expose the exact content whose
        // sanitization failed. Suppress the context instead.
        return [];
    }
}
/**
 * Resolves SanitizerOptions from GuardianConfig or returns null if explicitly disabled.
 */
export function resolveSanitizerOptions(config) {
    if (config?.secrets?.enabled === false) {
        return null;
    }
    return {
        replacement: typeof config?.secrets?.replacement === 'string' ? config.secrets.replacement : DEFAULT_REPLACEMENT,
        customSensitiveKeys: config?.secrets?.customSensitiveKeys,
        customSecretValues: config?.secrets?.customSecretValues,
        includeRuntimeEnv: config?.secrets?.includeRuntimeEnv !== false,
        safeKeyNames: config?.secrets?.safeKeyNames,
    };
}
