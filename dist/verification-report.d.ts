import type { OutcomeReason, TestSummary } from "./types.js";
/** Only complete, anchored aggregate summaries in bounded tool output. */
export declare function parseTestSummary(output: string): TestSummary | undefined;
/** A failed host result is never promoted by a passing text summary. */
export declare function testOutcomeReason(command: string, exitCode: number | undefined, counts?: TestSummary): OutcomeReason | undefined;
