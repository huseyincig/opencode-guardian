# Security Benchmark & Synthetic Preflight Test Suite

Documentation for OpenCode Guardian **v0.18.2**.

Guardian includes a curated suite of synthetic benchmark tests that evaluate preflight shell-risk detection logic without executing destructive commands or mutating files.

---

## 17-Case Synthetic Benchmark Results

The frozen 17-case benchmark suite in [`tests/preflight.test.mjs`](../tests/preflight.test.mjs) verifies `evaluatePreflight` against common risky, obfuscated, and legitimate shell patterns:

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
  - [`tests/preflight.test.mjs`](../tests/preflight.test.mjs): Covers backticks, scoped `rm` authorization, inert discussion text, query-vs-authorization checks, GuardFall shell rewrites, and privileged MCP/Windows CMD/PowerShell preflight inputs.
  - [`tests/rules-discipline.test.mjs`](../tests/rules-discipline.test.mjs): Covers scoped Git operations, hook bypasses, recognized MCP shell tools, filesystem formatting signatures, literal fork bombs, and multiple Go dependency blocks.
  - [`tests/runtime-v2-lifecycle.test.mjs`](../tests/runtime-v2-lifecycle.test.mjs): Covers Error/cause/metadata redaction, serialization callbacks, reserved JSON keys, V2 session/prompt cancellation, `shell.hook("create.before")`, `StreamLoopWatcher`, `session.fork`/subagent isolation, and multi-stage `splitShellStages` preflight.
  - [`tests/secrets-and-redaction.test.mjs`](../tests/secrets-and-redaction.test.mjs): Covers production dependency policy, multi-layer secret output redaction, and consistent credential-format handling.
  - [`tests/rules-completion-and-evidence.test.mjs`](../tests/rules-completion-and-evidence.test.mjs): Covers source placeholder preflight, bounded before/after observations (including symlink escapes and absent hooks), and aborted/interrupted tool classification.
  - [`sandbox/comprehensive-test.mjs`](../sandbox/comprehensive-test.mjs): Evaluates 18 end-to-end agent failure and recovery scenarios across all 14 rules.

## Extended Preflight Regressions

The 17-case frozen benchmark above is a limited synthetic corpus, not universal shell protection. Extended cases in [`tests/preflight.test.mjs`](../tests/preflight.test.mjs) cover privileged MCP shell execution and structured `process_start` inputs, including literal Windows CMD/PowerShell deletion forms. Strict preflight remains opt-in and does not replace host permissions or OS sandboxing.

The v0.18.2 pure OpenCode V2 engine additions and low-I/O telemetry architecture are described in [discipline coverage](discipline-coverage.md). The 28-case discipline corpus and the frozen 17-case shell benchmark measure separate synthetic case sets; neither establishes real-world detection accuracy.
