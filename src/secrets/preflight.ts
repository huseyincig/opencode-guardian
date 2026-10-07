import type { PreflightAssessment } from './types.js';

const HIGH_RISK_COMMAND_PATTERNS: { category: 'docker-env' | 'printenv' | 'systemctl-env' | 'docker-inspect'; regex: RegExp; advisory: string }[] = [
  {
    category: 'docker-env',
    regex: /\bdocker(?:\.exe)?\s+exec\b.*?\s+(?:env|printenv)\b/i,
    advisory: 'Broad container environment dump detected (docker exec ... env).',
  },
  {
    category: 'printenv',
    regex: /^(?:\s*sudo\s+)?(?:printenv|env)(?:\s+-[a-zA-Z0-9]+)*\s*$/i,
    advisory: 'Broad process environment dump detected (env/printenv).',
  },
  {
    category: 'docker-inspect',
    regex: /\bdocker(?:\.exe)?\s+inspect\b/i,
    advisory: 'Docker inspect command may dump container environment variables.',
  },
  {
    category: 'systemctl-env',
    regex: /\bsystemctl\s+show\b.*?\b(?:Environment|EnvironmentFiles)\b/i,
    advisory: 'Systemctl service environment dump detected.',
  },
];

/**
 * Assesses a shell tool command input for high-risk broad environment dumps.
 */
export function assessCommandPreflight(command: unknown): PreflightAssessment {
  if (typeof command !== 'string') {
    return { isHighRiskEnvDump: false };
  }

  const trimmed = command.trim();
  for (const item of HIGH_RISK_COMMAND_PATTERNS) {
    if (item.regex.test(trimmed)) {
      return {
        isHighRiskEnvDump: true,
        command: trimmed,
        category: item.category,
        advisory: item.advisory,
      };
    }
  }

  return { isHighRiskEnvDump: false };
}
