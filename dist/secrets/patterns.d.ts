/**
 * Standard environment/system keys that must NEVER be redacted as sensitive keys.
 */
export declare const SAFE_KEY_NAMES: Set<string>;
/**
 * Regex matching sensitive key names in key-value pairs (env, JSON, YAML).
 */
export declare const SENSITIVE_KEY_REGEX: RegExp;
/**
 * Checks whether a key name represents a sensitive credential name.
 */
export declare function isSensitiveKey(key: string, customKeys?: (string | RegExp)[]): boolean;
/**
 * Known autonomous credential format patterns (can match value even without key name).
 */
export declare const KNOWN_CREDENTIAL_PATTERNS: {
    name: string;
    regex: RegExp;
}[];
/**
 * PEM Private Key Block Regex (matches entire multi-line block).
 */
export declare const PEM_PRIVATE_KEY_REGEX: RegExp;
/**
 * Connection string with embedded password (Postgres, MySQL, Mongo, Redis, AMQP, MSSQL).
 */
export declare const CONNECTION_STRING_PASSWORD_REGEX: RegExp;
/**
 * Password hash patterns (bcrypt, argon2, sha512crypt, scrypt).
 */
export declare const PASSWORD_HASH_PATTERNS: {
    name: string;
    regex: RegExp;
}[];
