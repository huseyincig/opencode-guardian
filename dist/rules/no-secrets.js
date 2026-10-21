import { extractLikelyShellMutation, extractStructuredEditTexts, splitFilePatches } from "../tool-input.js";
import { KNOWN_CREDENTIAL_PATTERNS } from "../secrets/patterns.js";
export const SECRET_PATTERNS = [
    // Clone regex instances so write scans cannot alter output redaction state.
    ...KNOWN_CREDENTIAL_PATTERNS.map(({ name, regex }) => ({ name, regex: new RegExp(regex.source, regex.flags) })),
    { regex: /-----BEGIN\s+(?:RSA\s+|OPENSSH\s+|EC\s+|DSA\s+|PGP\s+)?PRIVATE\s+KEY-----/, name: "Private Key Header (PEM/SSH)" },
    { regex: /\b(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[^:\s'"]+:([^@\s'"]+)@[a-zA-Z0-9.-]+(?::[0-9]+)?\/[a-zA-Z0-9_.-]+/, name: "Database Connection String with Password" },
    { regex: /\b(?:_authToken|npmAuthToken)\s*=\s*["']?([A-Za-z0-9._~-]{20,})["']?/i, name: "npm Registry Auth Token" },
    { regex: /\bAuthorization\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9._~-]{24,})["']?/i, name: "Bearer Authorization Token" },
];
export function extractFilePathFromPatch(patch) {
    if (typeof patch !== "string")
        return undefined;
    return splitFilePatches(patch)[0]?.filePath;
}
export function extractAddedLines(text) {
    if (typeof text !== "string")
        return "";
    return text.split("\n").filter((line) => line.startsWith("+") && !line.startsWith("+++")).map((line) => line.slice(1)).join("\n");
}
export function maskSecret(secret) {
    if (secret.length <= 8)
        return "********";
    return `${secret.slice(0, 4)}...${secret.slice(-4)}`;
}
export function isExplicitTemplateValue(secretValue, capturedPassword) {
    return [secretValue, capturedPassword ?? ""].some((value) => value.includes("${") ||
        value.includes("process.env") ||
        /^\$[A-Z_][A-Z0-9_]*$/i.test(value) ||
        /<(?:YOUR_[A-Z0-9_]+|PASSWORD|TOKEN|API_KEY)>/i.test(value));
}
/** Documented, local-only example credentials are not real deployment secrets.
 * Never exempt token-shaped strings or remote service credentials by filename. */
export function isDocumentedLocalPasswordSample(filePath, value, password) {
    if (!filePath || !password)
        return false;
    if (!/(?:^|[\/])(?:[^\/]+\.)?(?:env\.)?(?:example|sample|template|dist)$/i.test(filePath)) {
        return false;
    }
    if (!/^(?:pass|password|example|sample|dummy|test|changeme|your_password_here)$/i.test(password)) {
        return false;
    }
    // A plausible password on a real database host must still be reported.
    return /@(?:localhost|127\.0\.0\.1|\[::1\]|(?:db\.)?example\.(?:com|org|net))(?::[0-9]+)?\//i.test(value);
}
export function findAllSecretsInCode(code, filePath, alreadySeen) {
    if (!code || typeof code !== "string")
        return [];
    const results = [];
    const seen = alreadySeen ?? new Set();
    for (const pattern of SECRET_PATTERNS) {
        if (seen.has(pattern.name))
            continue;
        let remaining = code;
        let match = null;
        while (remaining.length > 0) {
            pattern.regex.lastIndex = 0;
            const next = pattern.regex.exec(remaining);
            if (!next)
                break;
            const value = next[0];
            const password = next[1];
            const isSample = password !== undefined
                ? isExplicitTemplateValue(password) ||
                    isDocumentedLocalPasswordSample(filePath, value, password)
                : isExplicitTemplateValue(value);
            if (!isSample) {
                match = next;
                break;
            }
            remaining = remaining.slice(next.index + value.length);
        }
        if (!match)
            continue;
        const secretValue = match[0];
        seen.add(pattern.name);
        results.push({ name: pattern.name, secretValue, masked: maskSecret(secretValue) });
    }
    return results;
}
export function findSecretInCode(code, filePath) {
    return findAllSecretsInCode(code, filePath)[0];
}
export const noSecretsRule = {
    id: "security/no-secrets",
    description: "Detects hardcoded secrets, API keys, credentials, and connection strings in code modifications.",
    inspect: (context) => {
        const findings = [];
        const seen = new Set();
        const checkCode = (code, filePath, source = "file") => {
            const detected = findAllSecretsInCode(code, filePath, seen);
            for (const item of detected) {
                findings.push({
                    ruleId: "security/no-secrets",
                    pattern: item.name,
                    messageSnippet: item.masked,
                    description: `Potential hardcoded secret detected in ${filePath ?? source}: ${item.name} (${item.masked})`,
                    ...(filePath ? { filePath } : {}),
                });
            }
        };
        for (const msg of context.currentTurn) {
            if (msg.info.role !== "assistant")
                continue;
            for (const part of msg.parts) {
                if (part.type !== "tool" || !part.state?.input)
                    continue;
                const input = part.state.input;
                const patchRaw = input.patchText ?? input.patch;
                const targetFile = input.path ??
                    input.targetFile ??
                    input.filePath ??
                    input.file ??
                    extractFilePathFromPatch(patchRaw);
                if (typeof input.content === "string")
                    checkCode(input.content, targetFile);
                if (typeof input.new_string === "string")
                    checkCode(input.new_string, targetFile);
                if (typeof input.newString === "string")
                    checkCode(input.newString, targetFile);
                for (const edit of extractStructuredEditTexts(input, targetFile)) {
                    checkCode(edit.text, edit.filePath);
                }
                for (const section of splitFilePatches(patchRaw)) {
                    const patchText = extractAddedLines(section.patch);
                    if (patchText)
                        checkCode(patchText, section.filePath ?? targetFile);
                }
                const shellMutation = extractLikelyShellMutation(input);
                if (shellMutation)
                    checkCode(shellMutation, undefined, "shell file mutation");
            }
        }
        if (findings.length === 0) {
            return { ruleId: "security/no-secrets", decision: "pass", findings: [] };
        }
        const list = findings.map((f) => `  - [${f.pattern}] → ${f.messageSnippet}`).join("\n");
        const remediationPrompt = `Hardcoded secret or credential detected in this turn:\n${list}\n\n` +
            `ACTION REQUIRED:\n` +
            `1. Remove the raw API key, token, or secret from the source code immediately.\n` +
            `2. Read the credential from an environment variable (e.g. process.env.KEY or configuration file) instead.\n` +
            `3. Verify the file no longer contains sensitive credentials before continuing.`;
        return { ruleId: "security/no-secrets", decision: "block", findings, remediationPrompt };
    },
};
