/** Safe, finite audit codes. Never persist finding prose, patterns or tool inputs. */
import type { RuleResult } from "./types.js";
export declare const RULE_IDS: readonly ["discipline/no-evasion", "discipline/no-apology", "quality/no-shortcuts", "integrity/no-stubs", "integrity/no-unverified-claims", "integrity/no-silent-failure", "safety/no-truncation", "safety/destructive-operations", "testing/no-cheat", "security/no-secrets", "manifest/no-ghost-deps", "runtime/circuit-breaker", "task/completion-gate", "task/instruction-fidelity"];
export declare const SAFE_RULE_IDS: ReadonlySet<string>;
export declare const SAFE_REASON_CODES: ReadonlySet<string>;
export interface AuditReason {
    rule: string;
    code: string;
}
/** All output codes are hardcoded: untrusted finding.pattern is only compared, never logged. */
export declare function auditReasons(results: readonly RuleResult[]): AuditReason[];
