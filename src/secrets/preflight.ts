import type { PreflightAssessment } from './types.js';
import {
  literalShellScripts,
  literalWindowsShellScripts,
  splitShellStages,
  stripShellWrappersAndPath,
} from '../shell-risk.js';

const HIGH_RISK_COMMAND_PATTERNS: { category: 'docker-env' | 'printenv' | 'systemctl-env' | 'docker-inspect'; regex: RegExp; advisory: string }[] = [
  {
    category: 'docker-env',
    regex: /^docker(?:\.exe)?\s+(?:container\s+)?exec\b.*?\s+(?:\/(?:[A-Za-z0-9._-]+\/)+)?(?:env|printenv)\b/i,
    advisory: 'Broad container environment dump detected (docker exec ... env).',
  },
  {
    category: 'printenv',
    regex: /^(?:printenv|env)(?:\s+(?:(?:-u|--unset|-C|--chdir|-[i0v]+[uC])\s+\S+|-[i0v]*[uC]\S+|--(?:unset|chdir|ignore-signal|default-signal|block-signal)=\S+|--?[a-zA-Z0-9-]*|[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S+)|(?:(?:\d*>>?|\d*<&|\d*>&|&>>?)\s*\S+|\d*>&\d+)))*\s*$/i,
    advisory: 'Broad process environment dump detected (env/printenv).',
  },
  {
    category: 'docker-inspect',
    regex: /^docker(?:\.exe)?\s+(?:container\s+)?inspect\b/i,
    advisory: 'Docker inspect command may dump container environment variables.',
  },
  {
    category: 'systemctl-env',
    regex: /^systemctl\s+show\b.*?\b(?:Environment|EnvironmentFiles)\b/i,
    advisory: 'Systemctl service environment dump detected.',
  },
];

function assessCommandPreflightRecursive(
  command: string,
  originalCommand: string,
  depth: number
): PreflightAssessment {
  const trimmed = command.trim();
  const stages = splitShellStages(trimmed).flat();
  const candidates = stages.length > 0 ? stages : [trimmed];
  for (const stage of candidates) {
    const stripped = stripShellWrappersAndPath(stage, { stripNegation: true });
    for (const item of HIGH_RISK_COMMAND_PATTERNS) {
      if (item.regex.test(stripped)) {
        return {
          isHighRiskEnvDump: true,
          command: originalCommand,
          category: item.category,
          advisory: item.advisory,
        };
      }
    }
  }
  if (depth < 4) {
    const nestedScripts = [
      ...literalShellScripts(trimmed),
      ...literalWindowsShellScripts(trimmed),
    ];
    for (const script of nestedScripts) {
      const nested = assessCommandPreflightRecursive(script, originalCommand, depth + 1);
      if (nested.isHighRiskEnvDump) return nested;
    }
  }
  return { isHighRiskEnvDump: false };
}

/**
 * Assesses a shell tool command input for high-risk broad environment dumps.
 */
export function assessCommandPreflight(command: unknown): PreflightAssessment {
  if (typeof command !== 'string') {
    return { isHighRiskEnvDump: false };
  }
  const trimmed = command.trim();
  return assessCommandPreflightRecursive(trimmed, trimmed, 0);
}
