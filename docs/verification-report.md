# Verification and Acceptance Report

This document reports the **v0.18.1 automated verification suite and live OpenCode v2.4.1 + Bun 1.4.4 host acceptance**, evaluated on **25 November 2026** with **Node 26.13.1**, **Bun 1.4.4**, and **OpenCode v2.4.1**. (OpenCode V1 support ended in `v0.14.0`; historical release notes are preserved in [CHANGELOG.md](../CHANGELOG.md).)

---

## Executive Summary

- **Package Version:** OpenCode Guardian `v0.18.1` (Pure OpenCode V2 `>=2.3.0`)
- **Automated Source Suite:** **914 / 914 tests passed** across 14 domain suites (`tests/*.test.mjs`), zero failed, cancelled, or skipped
- **Sandbox Scenarios:** **21 / 21 isolated end-to-end scenarios passed** (including 4-rule and 3-rule single-remediation batching and redundant-handoff fidelity)
- **Live V2 Host Acceptance:** **10 / 10 checks passed** on installed OpenCode `v2.4.1` (`/usr/bin/opencode`) + Bun `1.4.4` + packed `.tgz`, plus **21 / 21** real-LLM live scenarios across all 14 rules, preflight, secret redaction, and multi-rule batching
- **Static & Supply-Chain Gates:** Strict TypeScript, Oxlint (`0 warnings, 0 errors` across 65 files), Markdown/SVG link validation, and `npm audit --omit=dev` (`0 vulnerabilities`)

> v0.18.1 adds synchronous pre-inspection `active_remediation` leases on turn completion (eliminating orchestrator task-completion race windows), surfaces blocking read-only subagent and failed-remediation findings via the V2 plugin mesh, and aligns bidirectional `claimDigest` provenance verification across sibling plugins.

---

## Automated Source Verification Results — v0.18.1

| Verification Suite | Target & Description | Result |
| :--- | :--- | :---: |
| **Unit & Regression Suite** | 914 tests across 14 domain suites covering all 14 rules, V2 `setup(ctx)` hooks (`experimental.idle` included), synchronous pre-inspection `active_remediation` leases & read-only subagent mesh visibility, cross-revision `claimDigest` provenance compatibility, provider-agnostic MCP inspection, lease-token & per-round subagent capability checks, credentialed URL & object-key redaction, snapshot overlap & disk hash verification, remote TUI RPC status/reset & `RpcTimeoutError` handling, aborted/interrupted tool & `opencode service restart` classification (#4), attachment-only user turn boundary hardening, peer-wake turn scoping & restart-safe persisted remediation budget accounting, crash-free detailed TUI conversation banners (`notifications.transcript: true` via `session.composer.top` RPC), multi-location single-owner event arbitration, OpenCode `v2.4.1` execution lifecycle, Universal V2 Plugin Mesh Bridge (`src/bridge.ts`), project scope isolation & `allowProjectOverrides: false` security floor, `"critical"` vs `"strict"` preflight modes, `./tui`, `./rpc`, `shell.hook("create.before")`, `StreamLoopWatcher`, edit integrity, and external low-I/O telemetry | **914 / 914 PASS** |
| **End-to-End Sandbox** | 21 multi-turn failure, combined multi-rule batching, and recovery scenarios across all rules (`sandbox/comprehensive-test.mjs`) | **21 / 21 PASS** |
| **Smoke Test** | V2 `setup(ctx)` plugin initialization, idle inspection, and expected remediation (`sandbox/smoke-test.mjs`) | **PASS** |
| **Typecheck** | Standard TypeScript + strict hardening (`noUnusedLocals`, `noUnusedParameters`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`) | **PASS** |
| **Lint** | Oxlint (`src` + `tests`, warnings denied; 65 files) | **PASS** |
| **Documentation & Links** | Markdown navigation, local link resolution, and SVG validator (`scripts/check-docs.mjs`) | **PASS** |
| **Production Audit** | `npm audit --omit=dev` | **PASS** (0 vulnerabilities) |
| **Development Audit** | `node scripts/check-dev-audit.mjs` (Full lockfile dev dependency audit) | **PASS** |
| **Packaging Dry Run** | `npm pack --dry-run` (`v0.18.1` metadata) | **PASS** |
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
