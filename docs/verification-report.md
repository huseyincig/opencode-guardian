# Verification and Acceptance Report

This document reports the **v0.18.6 automated verification suite and live OpenCode v2.4.1 + Bun 1.4.4 host acceptance**, evaluated on **26 November 2026** with **Node 26.13.1**, **Bun 1.4.4**, and **OpenCode v2.4.1**. (OpenCode V1 support ended in `v0.14.0`; historical release notes are preserved in [CHANGELOG.md](../CHANGELOG.md).)

---

## Executive Summary

- **Package Version:** OpenCode Guardian `v0.18.6` (Pure OpenCode V2 `>=2.3.0`)
- **Automated Source Suite:** **980 / 980 tests passed** across 24 domain test files (`81` suites, `tests/*.test.mjs`), zero failed, cancelled, or skipped
- **Sandbox Scenarios:** **21 / 21 isolated end-to-end scenarios passed** (including 4-rule and 3-rule single-remediation batching and redundant-handoff fidelity)
- **Live V2 Host Acceptance & DB Replay:** **10 / 10 checks passed** on installed OpenCode `v2.4.1` (`/usr/bin/opencode`) + Bun `1.4.4` + packed `.tgz`, plus live OpenCode `v2.4.1` standalone pre-idle interception proof, live replay across 223 real V2 worker sessions (`351` turns) in `opencode.db`, and **21 / 21** real-LLM live scenarios across all 14 rules, preflight, secret redaction, and multi-rule batching
- **Static & Supply-Chain Gates:** Strict TypeScript, Oxlint (`0 warnings, 0 errors` across 76 files), Markdown/SVG link validation, and `npm audit --omit=dev` (`0 vulnerabilities`)

> v0.18.6 eliminates worker-session false positives surfaced across 223 live V2 worker sessions (`lint | tail -N`, multi-word quoted `PIPESTATUS[0]` echoes, `git stash` baseline verification, negated/technical placeholder & Markdown doc exemptions, read `invalid_range` & host scope/allowlist refusal filtering, errored-tool secret skipping) and adds concrete failure details to `task/completion-gate` remediation prompts.

---

## Automated Source Verification Results — v0.18.6

| Verification Suite | Target & Description | Result |
| :--- | :--- | :---: |
| **Unit & Regression Suite** | 980 tests across 24 test files (`81` suites) covering all 14 rules, 223-worker-session live `opencode.db` false-positive & actionable-remediation closure (`tests/live-2026-11-26-fp-closure.test.mjs`, `tests/live-production-fp-closure.test.mjs`), 6-pass adversarial debug sweep hardening, V2 `setup(ctx)` hooks including zero-race pre-idle `experimental.idle` inspection & same-execution subagent remediation, OpenCode `v2.4.1` `edit` `appendContent`/`prependContent` inspection, token-aware `env`/`sudo`/`flock`/`bash -c`/`process_start` preflight, heredoc/subshell-depth `pipefail` & compound exit-echo verification (`lint`/`typecheck`/`build`/`test`), porcelain `git status` & subagent verification relay handling, >2 MiB YAML/single-line secret chunking & dotted-secret redaction, cross-bundle `opencode-mesh.state` RPC standby failover, project scope isolation & `allowProjectOverrides: false` security floor, `"critical"` vs `"strict"` preflight modes, `./tui`, `./rpc`, `shell.hook("create.before")`, `StreamLoopWatcher`, edit integrity, and external low-I/O telemetry | **980 / 980 PASS** |
| **End-to-End Sandbox** | 21 multi-turn failure, combined multi-rule batching, and recovery scenarios across all rules (`sandbox/comprehensive-test.mjs`) | **21 / 21 PASS** |
| **Smoke Test** | V2 `setup(ctx)` plugin initialization, idle inspection, and expected remediation (`sandbox/smoke-test.mjs`) | **PASS** |
| **Typecheck** | Standard TypeScript + strict hardening (`noUnusedLocals`, `noUnusedParameters`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`) | **PASS** |
| **Lint** | Oxlint (`src` + `tests`, warnings denied; 76 files) | **PASS** |
| **Documentation & Links** | Markdown navigation, local link resolution, and SVG validator (`scripts/check-docs.mjs`) | **PASS** |
| **Production Audit** | `npm audit --omit=dev` | **PASS** (0 vulnerabilities) |
| **Development Audit** | `node scripts/check-dev-audit.mjs` (Full lockfile dev dependency audit) | **PASS** |
| **Packaging Dry Run** | `npm pack --dry-run` (`v0.18.6` metadata) | **PASS** |
| **Live OpenCode V2 Acceptance** | Packed `.tgz` in Node `26.13.1` + Bun `1.4.4`, V2.4.1 server/RPC/TUI, credentialed URL redaction, and real `/usr/bin/opencode` (`v2.4.1`) (`sandbox/v2-live-acceptance.mjs`) | **10 / 10 PASS** |

---

## Methodological Boundaries & Limitations

1. **Opt-In Preflight:** Strict preflight is an opt-in safety net (`preflight.enabled: true`) designed to catch common accidental destructive commands and obvious secrets before execution. It is pattern-based and does not replace operating system user permissions, containers, or sandboxing.
2. **Post-Turn Scope:** Post-turn rule violations guide agent behavior and trigger automated remediation, but cannot retroactively reverse an operation that already completed.
3. **Log Rotation & Low-I/O Telemetry:** The per-project event log (`~/.local/state/opencode-guardian/projects/<projectHash>/guardian-events.jsonl`) is bounded by default to 512 KiB (configurable via `telemetry.maxBytes` or `OPENCODE_GUARDIAN_MAX_LOG_BYTES`), with one rotated archive (`guardian-events.jsonl.1`). In default `violations` mode, benign preflight-allowed and clean-turn events bypass disk I/O entirely without creating files inside `<project>/.opencode/`.

---

## Reproducing the Verification Suite

Run all local verification checks from the repository root:

```bash
# Install dependencies
npm ci

# Combined typecheck, lint, tests, and docs gate
npm run verify

# Sandbox scenarios and live host acceptance
node sandbox/smoke-test.mjs
node sandbox/comprehensive-test.mjs
node sandbox/v2-live-acceptance.mjs

# Security and package integrity audits
npm audit --omit=dev
node scripts/check-dev-audit.mjs
npm pack --dry-run
```
