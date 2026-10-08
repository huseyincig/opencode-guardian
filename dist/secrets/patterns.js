/**
 * Standard environment/system keys that must NEVER be redacted as sensitive keys.
 */
export const SAFE_KEY_NAMES = new Set([
    'PATH',
    'HOME',
    'PORT',
    'NODE_ENV',
    'USER',
    'SHELL',
    'LANG',
    'PWD',
    'HOSTNAME',
    'TERM',
    'EDITOR',
    'DISPLAY',
    'LOGNAME',
    'SHLVL',
    'OLDPWD',
    'UID',
    'GID',
    'PUBLIC_KEY',
    'SSH_PUBLIC_KEY',
    'KEYBOARD',
    'KEYMAP',
    'KEY_CODE',
    'PRIMARY_KEY',
    'FOREIGN_KEY',
    'PARTITION_KEY',
    'SORT_KEY',
    'LC_ALL',
    'LC_CTYPE',
    'MANPATH',
    'INFOPATH',
    'XDG_DATA_DIRS',
    'XDG_CONFIG_DIRS',
    'DEBIAN_FRONTEND',
    'PYTHONPATH',
    'GOPATH',
    'CARGO_HOME',
    'RUSTUP_HOME',
    'TMPDIR',
    'TEMP',
    'TMP',
]);
/**
 * Regex matching sensitive key names in key-value pairs (env, JSON, YAML).
 */
export const SENSITIVE_KEY_REGEX = /^(?:.*[_-])?(?:API[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|BEARER[_-]?TOKEN|SECRET[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|PASSWORD[_-]?HASH|PASS(?:WORD|WD)?|SECRET|TOKEN|CREDENTIALS?|DATABASE_URL|CONN(?:ECTION)?[_-]?STR(?:ING)?)(?:[_-].*)?$/i;
/**
 * Checks whether a key name represents a sensitive credential name.
 */
export function isSensitiveKey(key, customKeys, safeKeyNames) {
    if (!key || typeof key !== 'string')
        return false;
    const upper = key.trim().toUpperCase();
    // Caller-provided safe names are explicit exceptions and win over every
    // key-name detector. Built-in safe names remain overridable by an explicit
    // custom sensitive rule.
    if (safeKeyNames?.some((safe) => safe.trim().toUpperCase() === upper)) {
        return false;
    }
    if (customKeys) {
        for (const pattern of customKeys) {
            if (typeof pattern === 'string' && upper === pattern.trim().toUpperCase()) {
                return true;
            }
            if (pattern instanceof RegExp) {
                pattern.lastIndex = 0;
                const matched = pattern.test(key);
                pattern.lastIndex = 0;
                if (matched)
                    return true;
            }
        }
    }
    if (SAFE_KEY_NAMES.has(upper))
        return false;
    SENSITIVE_KEY_REGEX.lastIndex = 0;
    return SENSITIVE_KEY_REGEX.test(key);
}
/**
 * Known autonomous credential format patterns (can match value even without key name).
 */
export const KNOWN_CREDENTIAL_PATTERNS = [
    { name: 'OpenAI API Key', regex: /\b(?:sk-proj-|sk-)[a-zA-Z0-9_-]{20,}\b/g },
    { name: 'GitHub Token', regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b/g },
    { name: 'GitHub Fine-Grained Token', regex: /\bgithub_pat_[a-zA-Z0-9_]{50,}\b/g },
    { name: 'Slack Token', regex: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b/g },
    { name: 'AWS Access Key ID', regex: /\bAKIA[0-9A-Z]{16}\b/g },
    { name: 'Google API Key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    { name: 'npm Access Token', regex: /\bnpm_[a-zA-Z0-9]{36}\b/g },
    { name: 'GitLab Token', regex: /\bglpat-[a-zA-Z0-9_-]{20,}\b/g },
    { name: 'Stripe Live Secret Key', regex: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b/g },
];
/**
 * PEM Private Key Block Regex (matches entire multi-line block).
 */
export const PEM_PRIVATE_KEY_REGEX = /-----BEGIN(?:\s+[A-Z0-9_-]+)?\s+PRIVATE\s+KEY-----[\s\S]*?-----END(?:\s+[A-Z0-9_-]+)?\s+PRIVATE\s+KEY-----/g;
/**
 * Connection string with embedded password (Postgres, MySQL, Mongo, Redis, AMQP, MSSQL).
 */
export const CONNECTION_STRING_PASSWORD_REGEX = /\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^:\s'"\\]+:)([^@\s'"\\]+)(@[a-zA-Z0-9.-]+(?::[0-9]+)?\/[^\s'"\\]*)\b/gi;
/**
 * Password hash patterns (bcrypt, argon2, sha512crypt, scrypt).
 */
export const PASSWORD_HASH_PATTERNS = [
    { name: 'bcrypt hash', regex: /\$2[aby]\$[0-9]{2}\$[A-Za-z0-9./]{53}/g },
    {
        name: 'argon2 hash',
        regex: /\$argon2(?:id|[di])\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+/g,
    },
    {
        name: 'sha512-crypt hash',
        regex: /\$6\$(?:rounds=[0-9]+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}/g,
    },
    {
        name: 'scrypt hash',
        regex: /\$scrypt\$ln=[0-9]+,r=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/=,]+\$[A-Za-z0-9+/=]+/g,
    },
];
