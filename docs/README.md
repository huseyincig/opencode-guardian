# Documentation

[← OpenCode Guardian](../README.md)

Guides and verification records for OpenCode Guardian. The documentation is organized around **how the plugin works**, **what its security controls cover**, and **how the reported results were verified**.

| Start here | Purpose |
| :--- | :--- |
| [Verification & Live Acceptance Report](verification-report.md) | Commit-pinned results, V1/V2 acceptance matrix, fixture hash evidence, known limits, and reproduction commands |
| [Security Benchmark](security-benchmark.md) | Frozen in-memory preflight detector benchmark and test methodology |
| [Task Contract & Adapter Architecture](task-contract-v1-v2.md) | Lifecycle, host hook mapping, completion checks, and compatibility behavior |
| [OWASP Agentic Top 10 Mapping](owasp-agentic-top10-2026.md) | Mapping between rule capabilities, agentic risks, and their boundaries |

![Historical verification summary](assets/verification-overview.svg)

## Choosing the right evidence

- **Automated:** Run `npm test` for unit/regression coverage and the sandbox scripts for isolated scenarios.
- **Host acceptance:** Consult the commit-specific [verification report](verification-report.md). Real interactive behavior is not interchangeable with mock or SDK-model tests.
- **Current changes:** Check [GitHub Actions](../.github/workflows/ci.yml) for the CI definition and its most recent runs. The published acceptance graphic is a historical audit snapshot, not a continuously updated status indicator.

## Security note

Strict shell preflight is opt-in; post-turn findings cannot undo commands that already executed. Example files do not receive a blanket secrets exemption. Retain operating-system permissions, disposable testing environments, and human review for high-impact work.
