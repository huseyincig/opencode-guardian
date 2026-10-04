# Security Benchmark & Synthetic Preflight Test Suite

Documentation for OpenCode Guardian **v0.5.1**.

Guardian includes a curated suite of synthetic benchmark tests that evaluate preflight shell-risk detection logic without executing destructive commands or mutating files.

---

## 17-Case Synthetic Benchmark Results

The frozen test suite defined in [`tests/security-benchmark.test.mjs`](../tests/security-benchmark.test.mjs) verifies `evaluatePreflight` against common risky, obfuscated, and legitimate shell patterns:

| Test Classification | Cases Evaluated | Observed Result | Accuracy |
| :--- | :---: | :---: | :---: |
| **Reject** (destructive commands, obfuscated pipelines, uninspectable inputs) | 10 | 10 Rejected | 100% |
| **Allow** (read-only queries, non-destructive tools, authorized workflows) | 7 | 7 Allowed | 100% |
| **Misclassifications** | — | 0 | 0% |

---

## Scope & Methodological Notes

- **Non-Executing Safety:** All test cases are evaluated deterministically in memory; no commands are dispatched to the operating system shell during testing.
- **Obfuscation Defense:** Tests evaluate GuardFall-inspired evasions including paired backtick substitution, quote splitting, Base64 pipelines, and shell wrapper decoupling.
- **Additional Regressions:**
  - [`tests/security-gap-regression.test.mjs`](../tests/security-gap-regression.test.mjs): Covers backticks, scoped `rm` authorization, and inert discussion text.
  - [`tests/security-audit-regression.test.mjs`](../tests/security-audit-regression.test.mjs): Verifies that user queries/clarifications do not grant implicit deletion permissions.
  - [`tests/full-audit-regressions.test.mjs`](../tests/full-audit-regressions.test.mjs): Covers scoped Git operations, recognized MCP shell tools, filesystem formatting signatures, literal fork bombs, and multiple Go dependency blocks.
  - [`sandbox/comprehensive-test.mjs`](../sandbox/comprehensive-test.mjs): Evaluates 18 end-to-end agent failure and recovery scenarios across all 14 rules.
