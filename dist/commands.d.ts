export declare const GUARDIAN_COMMANDS: readonly [{
    readonly id: "status";
    readonly title: "Guardian: Status";
    readonly description: "Project statistics and remediation outcomes";
}, {
    readonly id: "activity";
    readonly title: "Guardian: Activity";
    readonly description: "Recent redacted security and quality events";
}, {
    readonly id: "doctor";
    readonly title: "Guardian: Diagnostics";
    readonly description: "Configuration and last reported runtime health";
}, {
    readonly id: "rules";
    readonly title: "Guardian: Rules";
    readonly description: "Built-in rules and configured severity overrides";
}, {
    readonly id: "config";
    readonly title: "Guardian: Configuration";
    readonly description: "Effective settings without private configuration values";
}, {
    readonly id: "version";
    readonly title: "Guardian: Version";
    readonly description: "Installed version and available npm update";
}, {
    readonly id: "reset";
    readonly title: "Guardian: Reset Statistics";
    readonly description: "Reset counters without erasing the security audit trail";
}];
export type GuardianCommand = (typeof GUARDIAN_COMMANDS)[number]["id"];
export interface GuardianReport {
    title: string;
    message: string;
}
export declare function guardianCommandReport(command: Exclude<GuardianCommand, "reset">, directory: string, installedVersion: string): Promise<GuardianReport>;
/** Must only be invoked after explicit UI confirmation. */
export declare function guardianResetReport(directory: string): GuardianReport;
