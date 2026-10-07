export interface SanitizerOptions {
  /**
   * Replacement text for redacted values. Defaults to '[REDACTED]'
   */
  replacement?: string | undefined;

  /**
   * Additional custom sensitive key patterns to match
   */
  customSensitiveKeys?: (string | RegExp)[] | undefined;

  /**
   * Additional custom literal secret values to redact
   */
  customSecretValues?: string[] | undefined;

  /**
   * Whether to include runtime-discovered process.env secrets. Defaults to true.
   */
  includeRuntimeEnv?: boolean | undefined;

  /**
   * Safe key names that should never be redacted by key-name matching
   */
  safeKeyNames?: string[] | undefined;

  /**
   * Safe values that should never be redacted
   */
  safeValues?: string[] | undefined;

  /**
   * Optional logger for non-sensitive diagnostics
   */
  logger?: ((msg: string) => void) | undefined;
}

export interface SecretFinding {
  kind: 'key-value' | 'known-pattern' | 'runtime-secret' | 'private-key' | 'connection-string' | 'password-hash';
  category: string;
  keyName?: string | undefined;
}

export interface SanitizeResult<T = unknown> {
  sanitized: T;
  redactedCount: number;
  findings: SecretFinding[];
}

export interface PreflightAssessment {
  isHighRiskEnvDump: boolean;
  command?: string | undefined;
  category?: 'docker-env' | 'printenv' | 'systemctl-env' | 'docker-inspect' | undefined;
  advisory?: string | undefined;
}
