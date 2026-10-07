# OWASP Agentic Top 10 (2026): Guardian Coverage and Safety Limits

Documentation for OpenCode Guardian **v0.6.5**.

This document maps OpenCode Guardian's architecture and guardrails to the **OWASP Top 10 for Agentic Applications (2026)** framework. It serves as an evidence-linked engineering mapping of current capabilities and explicit non-goals.

Sources:
- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- Erik Meijer, *"Guardians of the Agents"*, *Communications of the ACM*, December 2025 ([DOI: 10.1145/3777544](https://doi.org/10.1145/3777544))
- Adversa AI, *"GuardFall: Shell Command Security Flaws in Autonomous Agents"*, June 2026

---

## Risk-by-Risk Coverage Matrix

| OWASP Risk | Guardian Defense Mechanisms | Explicit Limitations & Non-Goals |
| :--- | :--- | :--- |
| **ASI01 – Agent Goal Hijack** | Task contracts extract genuine human turn intent before model invocation. Quoted examples, code snippets, and synthetic messages are filtered to prevent indirect goal injection. Instruction-fidelity enforces that earlier user pauses do not cause the agent to disobey current explicit instructions. | Not a general prompt-injection filter; does not guarantee untrusted web or tool data cannot bias the model. |
| **ASI02 – Tool Misuse** | Post-turn inspection evaluates tool calls against 14 rules. Optional strict preflight intercepts destructive shell commands before they execute. Literal path scoping ensures permission to delete one file does not authorize deleting others. | Post-turn findings are advisory at default `warn`. Preflight applies to recognized shell execution tools and is not a substitute for host sandboxing. |
| **ASI03 – Identity & Privilege Abuse** | Deletion authorization requires explicit, literal path matches. Consent to delete a file does not grant permission to escalate privileges via `sudo`. | Does not authenticate human identity or replace container/OS user privilege boundaries. |
| **ASI04 – Agentic Supply Chain** | `manifest/no-ghost-deps` cross-checks imports against package manifests (`package.json`, `pyproject.toml`, `requirements.txt`, `go.mod`, `Cargo.toml`). CI enforces clean dependency audits. | Does not verify cryptographic signatures or external plugin authenticity. |
| **ASI05 – Unexpected Code Execution** | Strict preflight detects destructive shell forms, GuardFall obfuscations (quote removal, `$IFS`, active backticks), and decoded Base64 pipelines piped into shells. | Not a full shell interpreter; dynamic payloads and unknown custom tools fall outside static preflight checks. |
| **ASI06 – Memory & Context Poisoning** | Synthetic assistant remediation turns are segregated. The agent cannot fabricate verification evidence out of context memories. | Does not manage external vector databases or persistent third-party memory stores. |
| **ASI07 – Insecure Inter-Agent Communication** | OpenCode dual-mode message normalization validates structured tool parts before inspection. v0.6.5 also finalizes synchronous child-agent handoffs before the parent consumes the delegated result, so Guardian remediation can revise the child report before it becomes parent-visible. | Does not implement inter-agent TLS or cryptographic envelope signing between distributed agent sidecars; background-agent delivery remains governed by the host runtime. |
| **ASI08 – Cascading Failures** | `runtime/circuit-breaker` halts execution if an agent repeats the same failing command 3 times consecutively. Strict `remediationBudget` and `iterationBudget` prevent infinite prompt loops. | Does not provide distributed transactional rollback across external APIs or microservices. |
| **ASI09 – Human-Agent Trust Exploitation** | `integrity/no-unverified-claims` correlates claims ("all tests pass", "build succeeded") with recorded tool exit codes. Direct contradictions trigger immediate remediation. | Does not prevent deceptive external UI rendering or social engineering attacks outside the terminal. |
| **ASI10 – Rogue Agents** | `task/completion-gate` prevents agents from declaring tasks complete without observable post-change verification (test execution or fresh source inspection). | Does not replace human-in-the-loop confirmation for production deployment or destructive infrastructure actions. |

---

## Reproducible Test Regressions

The mappings above are continuously validated through automated test suites:
- [`tests/security-benchmark.test.mjs`](../tests/security-benchmark.test.mjs): 17-case synthetic preflight benchmark.
- [`tests/guardfall-regression.test.mjs`](../tests/guardfall-regression.test.mjs): Obfuscated shell rewrite regressions.
- [`tests/full-audit-regressions.test.mjs`](../tests/full-audit-regressions.test.mjs): Recognized MCP shell tools, scoped Git destructive operations, and literal format/fork-bomb signatures.
- [`tests/owasp-scope-regression.test.mjs`](../tests/owasp-scope-regression.test.mjs): Path scoping and `sudo` privilege escalation tests.
- [`sandbox/comprehensive-test.mjs`](../sandbox/comprehensive-test.mjs): 18 end-to-end failure mode and recovery scenarios.

## v0.6.8 Operational Visibility

The TUI adds project-scoped, redacted status, activity and diagnostics commands. Reset requires confirmation and preserves audit events subject to normal rotation. These are operational features, not new cryptographic controls or proof of OWASP-wide protection; live-host V1/V2 acceptance is independently verified and documented in [Verification Report](verification-report.md).
