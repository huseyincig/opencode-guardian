/** Safe, finite audit codes. Never persist finding prose, patterns or tool inputs. */
import type { RuleResult } from "./types.js";

export const RULE_IDS = [
  "discipline/no-evasion", "discipline/no-apology",
  "quality/no-shortcuts", "integrity/no-stubs",
  "integrity/no-unverified-claims", "integrity/no-silent-failure",
  "safety/no-truncation", "safety/destructive-operations",
  "testing/no-cheat", "security/no-secrets",
  "manifest/no-ghost-deps", "runtime/circuit-breaker",
  "task/completion-gate", "task/instruction-fidelity",
] as const;

const RULE_CODES: Record<string, string> = {
  "discipline/no-evasion": "unsupported-failure-dismissal",
  "discipline/no-apology": "defensive-or-excessive-apology",
  "quality/no-shortcuts": "deferred-or-shortcut-work",
  "integrity/no-stubs": "incomplete-implementation",
  "integrity/no-unverified-claims": "claim-lacks-verification",
  "integrity/no-silent-failure": "swallowed-error",
  "safety/no-truncation": "possible-code-truncation",
  "safety/destructive-operations": "destructive-operation-not-authorized",
  "testing/no-cheat": "test-integrity-at-risk",
  "security/no-secrets": "potential-hardcoded-secret",
  "manifest/no-ghost-deps": "undeclared-dependency",
  "runtime/circuit-breaker": "repeated-failure-without-progress",
  "task/completion-gate": "required-verification-unconfirmed",
  "task/instruction-fidelity": "current-instruction-overridden",
};

export const SAFE_RULE_IDS: ReadonlySet<string> = new Set([
  ...RULE_IDS, "destructive-command", "opaque-shell-execution",
  "uninspectable-shell-input", "uninspectable-file-input", "v1-completion-probe",
  "hardcoded-secret-in-file-write", "lazy-commit-message", "hallucinated-or-malformed-package",
  "remediation-verified", "remediation-failed", "remediation-unverified",
  "prompt-delivery-failed", "message-fetch-failed", "engine-inspection-failed",
  "v2-event-stream-error", "verification-snapshot-unavailable",
]);

export const SAFE_REASON_CODES: ReadonlySet<string> = new Set([
  ...Object.values(RULE_CODES),
  "code-placeholder",
  "masked-verification-failure", "opaque-shell-execution",
  "missing-follow-up-review", "verification-not-confirmed",
  "destructive-command", "uninspectable-shell-input", "uninspectable-file-input", "v1-completion-probe",
  "hardcoded-secret-in-file-write", "lazy-commit-message", "hallucinated-or-malformed-package",
  "remediation-verified", "remediation-failed", "remediation-unverified",
  "prompt-delivery-failed", "message-fetch-failed", "engine-inspection-failed",
  "v2-event-stream-error", "verification-snapshot-unavailable",
]);

export interface AuditReason {
  rule: string;
  code: string;
}

/** All output codes are hardcoded: untrusted finding.pattern is only compared, never logged. */
export function auditReasons(results: readonly RuleResult[]): AuditReason[] {
  const reasons: AuditReason[] = [];
  const seen = new Set<string>();
  for (const result of results) {
    if (!result.findings.length || !Object.hasOwn(RULE_CODES, result.ruleId)) continue;
    for (const finding of result.findings) {
      const defaultCode = RULE_CODES[result.ruleId];
      if (!defaultCode) continue;
      let code = defaultCode;
      if (result.ruleId === "integrity/no-silent-failure" &&
          finding.pattern === "masked verification failure") {
        code = "masked-verification-failure";
      } else if (result.ruleId === "quality/no-shortcuts" &&
          ["TODO", "FIXME", "HACK"].includes(finding.pattern)) {
        code = "code-placeholder";
      } else if (result.ruleId === "safety/destructive-operations" &&
          finding.pattern === "opaque shell execution") {
        code = "opaque-shell-execution";
      } else if (result.ruleId === "task/completion-gate" &&
          finding.pattern === "iteration ended after a change without a new review") {
        code = "missing-follow-up-review";
      }
      const key = result.ruleId + ":" + code;
      if (!seen.has(key)) {
        seen.add(key);
        reasons.push({ rule: result.ruleId, code });
      }
    }
  }
  return reasons;
}
