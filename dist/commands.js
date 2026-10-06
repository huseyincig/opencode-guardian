/** Shared, host-independent command reports; no SDK objects or raw log payloads. */
import fs from "node:fs";
import { BUILTIN_RULES, DEFAULT_CONFIG, loadConfig } from "./engine.js";
import { checkGuardianUpdate } from "./version-notice.js";
import { guardianEventPath, readGuardianActivity, readGuardianStatus, resetGuardianStatistics } from "./telemetry.js";
export const GUARDIAN_COMMANDS = [
    { id: "status", title: "Guardian: Status", description: "Project statistics and remediation outcomes" },
    { id: "activity", title: "Guardian: Activity", description: "Recent redacted security and quality events" },
    { id: "doctor", title: "Guardian: Diagnostics", description: "Configuration and last reported runtime health" },
    { id: "rules", title: "Guardian: Rules", description: "Built-in rules and configured severity overrides" },
    { id: "config", title: "Guardian: Configuration", description: "Effective settings without private configuration values" },
    { id: "version", title: "Guardian: Version", description: "Installed version and available npm update" },
    { id: "reset", title: "Guardian: Reset Statistics", description: "Reset counters without erasing the security audit trail" },
];
function option(value) { return value ? "enabled" : "disabled"; }
export async function guardianCommandReport(command, directory, installedVersion) {
    const status = readGuardianStatus(directory);
    switch (command) {
        case "status": {
            const sample = readGuardianActivity(directory, 25);
            const counts = new Map();
            for (const event of sample) {
                for (const rule of event.rules ?? [])
                    counts.set(rule, (counts.get(rule) ?? 0) + 1);
            }
            const popular = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3)
                .map(([rule, count]) => rule + " (" + count + ")").join(", ");
            return {
                title: "Guardian: Project Status",
                message: [
                    "Preflight (last start): " + status.preflight,
                    "Tool calls inspected: " + status.inspected,
                    "Blocked: " + status.blocked,
                    "Warnings: " + status.warnings,
                    "Remediation requests: " + status.remediations,
                    "Verified / failed / unverified: " +
                        status.verified + " / " + status.failed + " / " + status.unverified,
                    "Inspection errors: " + status.errors,
                    "Last event: " + (status.lastKind ?? "none"),
                    "Recent rule sample: " + (popular || "none"),
                    "History: " + (status.truncated ? "partial (bounded window)" : "retained log window"),
                ].join("\n"),
            };
        }
        case "activity": {
            const events = readGuardianActivity(directory, 12);
            return {
                title: "Guardian: Recent Activity",
                message: events.length
                    ? events.map((event) => event.at + "  " + event.kind +
                        (event.tool ? " [" + event.tool + "]" : "") +
                        (event.rules?.length ? "  " + event.rules.join(", ") : "")).join("\n")
                    : "No retained Guardian events.",
            };
        }
        case "doctor": {
            let config;
            try {
                config = loadConfig(directory);
            }
            catch {
                return { title: "Guardian: Diagnostics", message: "Configuration: invalid. Fix the Guardian configuration before continuing." };
            }
            const log = guardianEventPath(directory);
            const present = fs.existsSync(log);
            const match = config.preflight?.enabled === true && status.preflight !== "active";
            return {
                title: "Guardian: Diagnostics",
                message: [
                    "Configuration: valid",
                    "Guardian: " + option(config.enabled !== false),
                    "Strict preflight configured: " + option(config.preflight?.enabled === true),
                    "Protection mode: " + (config.preflight?.enabled === true ? "Autonomous (Strict)" : "Autonomous (Standard)"),
                    "Preflight at last recorded start: " + status.preflight,
                    "Audit log: " + (present ? "present" : "not created"),
                    "Audit window: " + (status.truncated ? "partial or unreadable" : "readable"),
                    "Last event: " + (status.lastKind ?? "none"),
                    match ? "Attention: configured preflight is not confirmed by the last start event." :
                        "Note: these are local records; live hook health requires a host test.",
                ].join("\n"),
            };
        }
        case "rules": {
            let config;
            try {
                config = loadConfig(directory);
            }
            catch {
                return { title: "Guardian: Rules", message: "Configuration is invalid; rule settings cannot be verified." };
            }
            return {
                title: "Guardian: Rules",
                message: Object.keys(BUILTIN_RULES).map((id) => {
                    const entry = config.rules?.[id] ?? DEFAULT_CONFIG.rules?.[id];
                    const severity = typeof entry === "string" ? entry :
                        entry?.severity ?? "built-in default";
                    return id + ": " + severity;
                }).join("\n"),
            };
        }
        case "config": {
            let config;
            try {
                config = loadConfig(directory);
            }
            catch {
                return { title: "Guardian: Configuration", message: "Configuration is invalid. No raw file contents will be displayed." };
            }
            return {
                title: "Guardian: Configuration",
                message: [
                    "Guardian: " + option(config.enabled !== false),
                    "Strict preflight: " + option(config.preflight?.enabled === true),
                    "Protection mode: " + (config.preflight?.enabled === true ? "Autonomous (Strict)" : "Autonomous (Standard)"),
                    "Custom shell tool entries: " + (config.preflight?.shellTools?.length ?? 0),
                    "Remediation budget: " + (config.remediationBudget ?? 1),
                    "Iteration budget: " + (config.iterationBudget ?? 3),
                    "Update notice: " + option(config.updateNotice?.enabled !== false),
                    "Configured rule overrides: " + Object.keys(config.rules ?? {}).length,
                    "Sensitive configuration values are not displayed.",
                ].join("\n"),
            };
        }
        case "version": {
            const update = await checkGuardianUpdate({ installedVersion, allowDevelopment: true });
            return {
                title: "Guardian: Version",
                message: "Installed: v" + installedVersion + "\n" +
                    (update ? "Update available: v" + update.latest + " (manual install)" :
                        "No newer stable version confirmed (offline or up to date)."),
            };
        }
    }
}
/** Must only be invoked after explicit UI confirmation. */
export function guardianResetReport(directory) {
    if (!resetGuardianStatistics(directory)) {
        return { title: "Guardian: Reset Statistics",
            message: "Reset failed. The audit log was not changed successfully." };
    }
    return { title: "Guardian: Reset Statistics",
        message: "Counters reset. No audit-log wipe was performed; normal log rotation still applies. Policy and preflight are unchanged." };
}
