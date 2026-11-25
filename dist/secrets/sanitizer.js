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
function sanitizeKeyValueLine(line, replacement, customKeys, safeKeyNames, findings = [], safeValues) {
    const stripQuotes = (raw) => (raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))
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
        if (unquotedEnvVal.trim().length > 0 &&
            unquotedEnvVal !== replacement &&
            isSensitiveKey(key, customKeys, safeKeyNames) &&
            !safeValues?.has(unquotedEnvVal)) {
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
        const unquotedYamlVal = stripQuotes(rawVal);
        if (unquotedYamlVal.trim().length > 0 &&
            unquotedYamlVal !== replacement &&
            isSensitiveKey(key, customKeys, safeKeyNames) &&
            !safeValues?.has(unquotedYamlVal)) {
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
    const safeValueSet = options.safeValues?.length ? new Set(options.safeValues) : undefined;
    if (safeValueSet?.has(text)) {
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
        // Credential context is meaningful even when a query value has no known
        // token format and is not registered as a runtime literal.
        result = result.replace(/([?&])([^=&#\s]+)=([^&#\s]*)/g, (match, lead, key, val) => {
            if (!val || val === replacement)
                return match;
            let decodedVal = val;
            try {
                decodedVal = decodeURIComponent(val.replace(/\+/g, " "));
            }
            catch { }
            if (safeValueSet?.has(val) || safeValueSet?.has(decodedVal))
                return match;
            let decoded;
            try {
                decoded = decodeURIComponent(key.replace(/\+/g, " "));
            }
            catch {
                decoded = key;
            }
            if (!isSensitiveKey(decoded, options.customSensitiveKeys, options.safeKeyNames))
                return match;
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
            const sanitized = sanitizeKeyValueLine(original, replacement, options.customSensitiveKeys, options.safeKeyNames, findings, safeValueSet);
            if (sanitized !== original) {
                lines[i] = sanitized;
                lineModified = true;
                redactedCount++;
            }
        }
        if (lineModified) {
            result = lines.join('\n');
        }
        // 3b. Inline key-value assignments (e.g. "token=xyz", "password: xyz", "password=\"multi word\"", "--api-key=xyz")
        const inlineKvRegex = /(^|[\s,;([{"'=-])([a-zA-Z0-9_.-]*(?:token|api[_-]?key|secret|password|passwd|pass|auth[_-]?token)[a-zA-Z0-9_.-]*)(\s*[:=]\s*|\s+)(?:"((?:\\.|[^"\\\r\n]){1,512})"|'((?:\\.|[^'\\\r\n]){1,512})'|([^\s,;)"'>\n\r]+))/gi;
        result = result.replace(inlineKvRegex, (match, lead, key, sep, dqVal, sqVal, bareVal) => {
            const val = (dqVal ?? sqVal ?? bareVal ?? "");
            if (!isSensitiveKey(key, options.customSensitiveKeys, options.safeKeyNames)) {
                return match;
            }
            if (val === replacement || val === '[REDACTED:PRIVATE_KEY]' || safeValueSet?.has(val)) {
                return match;
            }
            if (/^\s+$/.test(sep) && dqVal === undefined && sqVal === undefined) {
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
                result = result.replace(pattern.regex, (matched) => {
                    if (safeValueSet?.has(matched))
                        return matched;
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
                if (safeValueSet?.has(matched) || safeValueSet?.has(token))
                    return matched;
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
                    if (safeValueSet?.has(matched))
                        return matched;
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
            if (!secretVal || secretVal.length < 6 || seenLiterals.has(secretVal) || safeValueSet?.has(secretVal))
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
const UUID_TOKEN_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NUMERIC_COUNTER_KEY_REGEX = /(?:[_-]?(?:count|total|len|length|size|limit|max|min|ttl|ms|sec|seconds|timeout|retries|attempts|version|port|age|timestamp|index|idx))$/i;
function neutralizeInheritedSerializer(output, proto, options, replacement) {
    if (!proto || proto === Object.prototype)
        return;
    if (typeof proto.toJSON === 'function') {
        Object.defineProperty(output, 'toJSON', {
            value() {
                const plain = {};
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
    let cursor = proto;
    while (cursor && cursor !== Object.prototype) {
        for (const propName of Object.getOwnPropertyNames(cursor)) {
            if (propName === 'constructor' || propName === 'toJSON' || Object.hasOwn(output, propName))
                continue;
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
export function sanitizeObject(data, options = {}, rootInsideMeshEnvelope = false) {
    const replacement = options.replacement ?? DEFAULT_REPLACEMENT;
    const findings = [];
    let redactedCount = 0;
    const seenObjects = new WeakMap();
    try {
        function propertyValue(key, value, insideMeshEnvelope = false) {
            if (value === null ||
                value === undefined ||
                typeof value === 'boolean' ||
                value === '') {
                return value;
            }
            if (typeof value === 'number') {
                if (!NUMERIC_COUNTER_KEY_REGEX.test(key) &&
                    isSensitiveKey(key, options.customSensitiveKeys, options.safeKeyNames)) {
                    redactedCount++;
                    findings.push({ kind: 'key-value', category: 'Object Property', keyName: key });
                    return replacement;
                }
                return value;
            }
            if (typeof value === 'string' && Array.isArray(options.safeValues) && options.safeValues.includes(value)) {
                return value;
            }
            const isValidMeshUuidToken = insideMeshEnvelope &&
                key === 'token' &&
                typeof value === 'string' &&
                UUID_TOKEN_REGEX.test(value);
            if (!isValidMeshUuidToken &&
                isSensitiveKey(key, options.customSensitiveKeys, options.safeKeyNames)) {
                redactedCount++;
                findings.push({ kind: 'key-value', category: 'Object Property', keyName: key });
                return replacement;
            }
            return recurse(value, key === 'opencode-mesh');
        }
        function recurse(val, insideMeshEnvelope = false) {
            if (val === null || val === undefined)
                return val;
            // Retained callbacks (notably toJSON) could reintroduce raw data later,
            // when the host serializes a result that has already been sanitized.
            if (typeof val === 'function')
                return undefined;
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
                return new RegExp(val.source, val.flags);
            }
            if (val instanceof Error) {
                const output = new Error();
                const errProto = Object.getPrototypeOf(val);
                if (errProto && errProto !== Error.prototype) {
                    try {
                        Object.setPrototypeOf(output, errProto);
                    }
                    catch { }
                }
                seenObjects.set(val, output);
                // Error.cause and AggregateError.errors are non-enumerable. Inspect
                // every own property, including provider metadata, at the same boundary.
                for (const key of new Set(['name', ...Object.getOwnPropertyNames(val)])) {
                    const value = val[key];
                    Object.defineProperty(output, key, {
                        value: propertyValue(key, value),
                        enumerable: Object.getOwnPropertyDescriptor(val, key)?.enumerable ?? false,
                        writable: true,
                        configurable: true,
                    });
                }
                return output;
            }
            if (ArrayBuffer.isView(val) || val instanceof ArrayBuffer) {
                return val;
            }
            if (Array.isArray(val)) {
                const arrOut = [];
                seenObjects.set(val, arrOut);
                for (const item of val) {
                    arrOut.push(recurse(item));
                }
                return arrOut;
            }
            if (typeof val === 'object') {
                const proto = Object.getPrototypeOf(val);
                const output = proto === null
                    ? Object.create(null)
                    : proto !== Object.prototype
                        ? Object.create(proto)
                        : {};
                seenObjects.set(val, output);
                for (const [k, v] of Object.entries(val)) {
                    Object.defineProperty(output, k, {
                        value: propertyValue(k, v, insideMeshEnvelope), enumerable: true, writable: true, configurable: true,
                    });
                }
                neutralizeInheritedSerializer(output, proto, options, replacement);
                return output;
            }
            return val;
        }
        const sanitized = recurse(data, rootInsideMeshEnvelope);
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
 * Universal Tool Result Sanitizer with redaction metadata.
 * Runs a single pass over any tool result shape (string, Error, V2 { content, output, metadata },
 * process { stdout, stderr }, or generic object/array) so callers do not need JSON.stringify diffs.
 */
export function sanitizeToolResultWithMeta(result, options = {}) {
    if (result === null || result === undefined) {
        return { sanitized: result, redactedCount: 0 };
    }
    try {
        if (typeof result === 'string') {
            const res = sanitizeString(result, options);
            return { sanitized: res.sanitized, redactedCount: res.redactedCount };
        }
        if (typeof result === 'object') {
            const res = sanitizeObject(result, options);
            return { sanitized: res.sanitized, redactedCount: res.redactedCount };
        }
        return { sanitized: result, redactedCount: 0 };
    }
    catch {
        return { sanitized: FAIL_SAFE_OUTPUT, redactedCount: 1 };
    }
}
/**
 * Universal Tool Result Sanitizer.
 * Safely transforms any tool result shape (string, { output, metadata }, { stdout, stderr }, MCP content)
 * into a sanitized version without modifying internal non-string metadata.
 */
export function sanitizeToolResult(result, options = {}) {
    return sanitizeToolResultWithMeta(result, options).sanitized;
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
            // Handle message with parts: { info, parts: [...] } while preserving Message/Part prototypes
            if (Array.isArray(msgObj.parts)) {
                const sanitizedParts = msgObj.parts.map((part) => {
                    if (!part || typeof part !== 'object')
                        return part;
                    return sanitizeObject(part, options).sanitized;
                });
                const msgProto = Object.getPrototypeOf(msgObj);
                const clonedMsg = msgProto && msgProto !== Object.prototype ? Object.create(msgProto) : {};
                for (const [k, v] of Object.entries(msgObj)) {
                    if (k === 'parts')
                        continue;
                    const sanitizedVal = typeof v === 'string' && Array.isArray(options.safeValues) && options.safeValues.includes(v)
                        ? v
                        : isSensitiveKey(k, options.customSensitiveKeys, options.safeKeyNames)
                            ? (options.replacement ?? DEFAULT_REPLACEMENT)
                            : sanitizeObject(v, options, k === 'opencode-mesh').sanitized;
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
                return clonedMsg;
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
        safeValues: config?.secrets?.safeValues,
    };
}
