import { splitShellStages } from '../shell-risk.js';
const HIGH_RISK_COMMAND_PATTERNS = [
    {
        category: 'docker-env',
        regex: /^\s*(?:sudo\s+)?docker(?:\.exe)?\s+exec\b.*?\s+(?:env|printenv)\b/i,
        advisory: 'Broad container environment dump detected (docker exec ... env).',
    },
    {
        category: 'printenv',
        regex: /^(?:\s*sudo\s+)?(?:printenv|env)(?:\s+-[a-zA-Z0-9]+)*\s*$/i,
        advisory: 'Broad process environment dump detected (env/printenv).',
    },
    {
        category: 'docker-inspect',
        regex: /^\s*(?:sudo\s+)?docker(?:\.exe)?\s+inspect\b/i,
        advisory: 'Docker inspect command may dump container environment variables.',
    },
    {
        category: 'systemctl-env',
        regex: /^\s*(?:sudo\s+)?systemctl\s+show\b.*?\b(?:Environment|EnvironmentFiles)\b/i,
        advisory: 'Systemctl service environment dump detected.',
    },
];
/**
 * Assesses a shell tool command input for high-risk broad environment dumps.
 */
export function assessCommandPreflight(command) {
    if (typeof command !== 'string') {
        return { isHighRiskEnvDump: false };
    }
    const trimmed = command.trim();
    const stages = splitShellStages(trimmed).flat();
    const candidates = stages.length > 0 ? stages : [trimmed];
    for (const stage of candidates) {
        for (const item of HIGH_RISK_COMMAND_PATTERNS) {
            if (item.regex.test(stage)) {
                return {
                    isHighRiskEnvDump: true,
                    command: trimmed,
                    category: item.category,
                    advisory: item.advisory,
                };
            }
        }
    }
    return { isHighRiskEnvDump: false };
}
