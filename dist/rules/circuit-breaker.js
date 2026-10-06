import { collectTurnEvidence } from "../evidence.js";
function commandFamily(record) {
    const command = record.command?.trim().toLowerCase() ?? "";
    if (!command)
        return record.toolName.toLowerCase();
    const cleaned = command
        .replace(/\s+2>&1\b/g, "")
        .replace(/\s+--verbose\b/g, "")
        .replace(/\s+-v\b/g, "")
        .trim();
    const patterns = [
        /\b(npm\s+(?:run\s+)?[a-z0-9:_-]+)/,
        /\b(pnpm\s+(?:run\s+)?[a-z0-9:_-]+)/,
        /\b(yarn\s+(?:run\s+)?[a-z0-9:_-]+)/,
        /\b(bun\s+(?:run\s+)?[a-z0-9:_-]+)/,
        /\b(git\s+[a-z-]+)/,
        /\b(cargo\s+[a-z-]+)/,
        /\b(go\s+[a-z-]+)/,
        /\b(python(?:3)?\s+-m\s+[a-z0-9_.-]+)/,
        /\b(pytest|curl|wget|node|tsc|eslint|ruff|mypy|pyright)\b/,
    ];
    for (const pattern of patterns) {
        const match = pattern.exec(cleaned);
        const family = match?.[1];
        if (family)
            return family;
    }
    return cleaned.split(/\s+/).slice(0, 2).join(" ");
}
function primaryRecords(context) {
    const evidence = context.evidence ?? collectTurnEvidence(context.currentTurn);
    const bySequence = new Map();
    for (const record of evidence.records) {
        if (record.kind === "file-mutation")
            continue;
        if (!bySequence.has(record.sequence)) {
            bySequence.set(record.sequence, record);
        }
    }
    return [...bySequence.values()];
}
export const circuitBreakerRule = {
    id: "runtime/circuit-breaker",
    description: "Detects repeated failing invocations and repeated root-cause error fingerprints without progress.",
    inspect: (context) => {
        const records = primaryRecords(context).sort((a, b) => a.sequence - b.sequence);
        const findings = [];
        const exactCounts = new Map();
        for (const record of records) {
            const family = commandFamily(record);
            if (record.status === "success") {
                for (const [signature, state] of exactCounts) {
                    if (commandFamily(state.last) === family) {
                        exactCounts.delete(signature);
                    }
                }
                continue;
            }
            if (record.status !== "failure")
                continue;
            const current = exactCounts.get(record.signature);
            exactCounts.set(record.signature, {
                count: (current?.count ?? 0) + 1,
                last: record,
            });
        }
        for (const [signature, data] of exactCounts) {
            if (data.count < 3)
                continue;
            findings.push({
                ruleId: "runtime/circuit-breaker",
                pattern: "Repeated error loop",
                messageSnippet: data.last.error ?? data.last.output ?? "tool invocation failed",
                description: `Same failing tool invocation repeated ${data.count} times without progress: "${signature.slice(0, 160)}"`,
                evidence: [
                    `error fingerprint: ${data.last.errorFingerprint ?? "unavailable"}`,
                ],
                confidence: "high",
            });
        }
        // Progress-aware semantic loop detection. Cosmetic argument changes should
        // not defeat the breaker when the same command family hits the same
        // normalized root-cause error repeatedly. A successful invocation in that
        // family resets the streak.
        const streaks = new Map();
        for (const record of records) {
            const family = commandFamily(record);
            if (record.status === "success") {
                for (const key of streaks.keys()) {
                    if (key.startsWith(`${family}::`))
                        streaks.delete(key);
                }
                continue;
            }
            if (record.status !== "failure" || !record.errorFingerprint)
                continue;
            const key = `${family}::${record.errorFingerprint}`;
            const current = streaks.get(key);
            streaks.set(key, {
                count: (current?.count ?? 0) + 1,
                last: record,
            });
        }
        for (const [key, data] of streaks) {
            if (data.count < 3)
                continue;
            const alreadyCovered = findings.some((finding) => finding.messageSnippet ===
                (data.last.error ?? data.last.output ?? "tool invocation failed"));
            if (alreadyCovered)
                continue;
            findings.push({
                ruleId: "runtime/circuit-breaker",
                pattern: "Repeated root-cause loop",
                messageSnippet: data.last.error ?? data.last.output ?? "tool invocation failed",
                description: `Same command family/root-cause failure repeated ${data.count} times despite argument changes: "${key.slice(0, 180)}"`,
                evidence: [
                    `normalized fingerprint: ${data.last.errorFingerprint}`,
                ],
                confidence: "high",
            });
        }
        if (findings.length === 0) {
            return {
                ruleId: "runtime/circuit-breaker",
                decision: "pass",
                findings: [],
            };
        }
        const list = findings
            .map((finding) => `  - ${finding.description}\n    Last error: ${finding.messageSnippet}`)
            .join("\n");
        const MISSING_INFO_PATTERN = /\b(?:auth|unauthorized|forbidden|401|403|credential|token|api[_-]?key|secret|password|missing\s+(?:env|environment\s+variable|input|file|config|permission))\b/i;
        const needsUserClarification = findings.some((f) => MISSING_INFO_PATTERN.test(f.messageSnippet) ||
            MISSING_INFO_PATTERN.test(f.description));
        return {
            ruleId: "runtime/circuit-breaker",
            decision: "block",
            findings,
            remediationPrompt: `Circuit breaker tripped! Repetitive error loop detected:\n${list}\n\n` +
                `Stop repeating the same failing approach. Reconsider the hypothesis, inspect the root cause, change strategy, or ask the user for genuinely missing information.`,
            ...(needsUserClarification
                ? {
                    handoff: {
                        required: true,
                        kind: "clarification",
                        autoSelect: "allowed",
                    },
                }
                : {}),
        };
    },
};
