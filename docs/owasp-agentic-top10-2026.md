# OWASP Agentic Top 10 (2026): Guardian Coverage and Safety Limits

Documentation for OpenCode Guardian **v0.12.0**.

This document maps OpenCode Guardian's architecture and guardrails to the **OWASP Top 10 for Agentic Applications (2026)** framework. It serves as an evidence-linked engineering mapping of current capabilities and explicit non-goals.

Sources:
- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- Erik Meijer, *"Guardians of the Agents"*, *Communications of the ACM*, December 2025 ([DOI: 10.1145/3777544](https://doi.org/10.1145/3777544))
- Adversa AI, *"GuardFall: Shell Command Security Flaws in Autonomous Agents"*, June 2026

---

## Risk-by-Risk Coverage Matrix

| OWASP Risk | Guardian Defense Mechanisms | Explicit Limitations & Non-Goals |
| :--- | :--- | :--- |
| **ASI01 – Agent Goal Hijack** | Task contracts extract supported human intent patterns. Quoted examples, code snippets and synthetic messages are filtered. Instruction-fidelity checks current instructions, including narrow English/Turkish research-only constraints. | Not a general prompt-injection filter; research-only checks run after the turn and cannot undo mutations. Other task-contract languages do not imply equivalent research-only coverage. |
| **ASI02 – Tool Misuse** | Post-turn inspection evaluates tool calls against 14 rules. Optional strict preflight intercepts recognized destructive shell forms, secret-bearing writes and source truncation placeholders. Destructive-operation inspection scopes supported authorization to literal paths, repositories and refspecs. | The destructive-operation rule defaults to `warn`; other rules may block remediation completion. Post-turn findings cannot undo commands. Static preflight is not a substitute for host sandboxing. |
| **ASI03 – Identity & Privilege Abuse** | Deletion authorization requires explicit, literal path matches. Consent to delete a file does not grant permission to escalate privileges via `sudo`. | Does not authenticate human identity or replace container/OS user privilege boundaries. |
| **ASI04 – Agentic Supply Chain** | `manifest/no-ghost-deps` cross-checks imports against supported manifests. Runtime JS/TS dev-only imports are advisory by default, with optional `productionOnly` enforcement. CI includes dependency audit gates. | File-role conventions do not establish complete production reachability. Does not verify cryptographic signatures or external plugin authenticity; audits were not rerun for v0.12.0. |
| **ASI05 – Unexpected Code Execution** | Strict preflight detects destructive shell forms, GuardFall obfuscations (quote removal, `$IFS`, active backticks), and decoded Base64 pipelines piped into shells. | Not a full shell interpreter; dynamic payloads and unknown custom tools fall outside static preflight checks. |
| **ASI06 – Memory & Context Poisoning** | Synthetic remediation turns are segregated. Normalized verification records come from observed assistant tool parts, not plain context memories or prose. | Does not attest tool-output authenticity or manage external vector databases and persistent third-party memory stores. |
| **ASI07 – Insecure Inter-Agent Communication** | OpenCode dual-mode message normalization validates structured tool parts before inspection. v0.6.5 also finalizes synchronous child-agent handoffs before the parent consumes the delegated result, so Guardian remediation can revise the child report before it becomes parent-visible. | Does not implement inter-agent TLS or cryptographic envelope signing between distributed agent sidecars; background-agent delivery remains governed by the host runtime. |
| **ASI08 – Cascading Failures** | `runtime/circuit-breaker` flags the same execution failure repeated 3 times without progress; explicit user cancellations are excluded. Bounded `remediationBudget` and `iterationBudget` limit automatic prompt loops. | Post-turn checks do not halt an already running process or provide distributed rollback across external APIs or microservices. |
| **ASI09 – Human-Agent Trust Exploitation** | `integrity/no-unverified-claims` correlates success claims with observed outcomes and explicit current passed counts with fresh supported summaries. Direct contradictions can trigger bounded remediation. | Limited output formats and lexical claim patterns; does not prove general truthfulness or prevent deceptive external UI/social engineering. |
| **ASI10 – Rogue Agents** | `task/completion-gate` checks required post-change verification. Recognized zero-test, skipped-only or conflicting summaries cannot satisfy a required test run. | Does not prove whole-repository review coverage or replace human confirmation for production deployment and destructive infrastructure actions. |

---

## Reproducible Test Regressions

The mappings above are continuously validated through automated test suites:
- [`tests/security-benchmark.test.mjs`](../tests/security-benchmark.test.mjs): 17-case synthetic preflight benchmark.
- [`tests/guardfall-regression.test.mjs`](../tests/guardfall-regression.test.mjs): Obfuscated shell rewrite regressions.
- [`tests/full-audit-regressions.test.mjs`](../tests/full-audit-regressions.test.mjs): Recognized MCP shell tools, scoped Git destructive operations, and literal format/fork-bomb signatures.
- [`tests/owasp-scope-regression.test.mjs`](../tests/owasp-scope-regression.test.mjs): Path scoping and `sudo` privilege escalation tests.
- [`tests/review-hardening.test.mjs`](../tests/review-hardening.test.mjs): Git authorization boundaries, executed-code/literal distinctions and collection-error handling.
- [`tests/verification-report.test.mjs`](../tests/verification-report.test.mjs): Supported counts, outcome semantics and verification claims.
- [`tests/discipline-coverage.test.mjs`](../tests/discipline-coverage.test.mjs): One violation and one legitimate-negative case for each rule; a synthetic baseline, not an OWASP certification or real-world accuracy estimate.
- [`sandbox/comprehensive-test.mjs`](../sandbox/comprehensive-test.mjs): 18 end-to-end failure mode and recovery scenarios.

## v0.8.0 Operational Visibility

The TUI adds project-scoped, redacted status, activity, diagnostics commands, and visible color-coded toast interventions. Reset requires confirmation and preserves audit events subject to normal rotation. These are operational features, not new cryptographic controls or proof of OWASP-wide protection; live-host V1/V2 acceptance is independently verified and documented in [Verification Report](verification-report.md).
