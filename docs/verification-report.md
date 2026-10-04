# Verification and Acceptance Report

This document reports the **v0.6.0 verification suite** and **dual-mode live-host acceptance** across OpenCode V1 and OpenCode V2 host environments.

---

## Executive Summary

- **Package Version:** OpenCode Guardian `v0.6.0`
- **Release Baseline:** `v0.6.0` (Live-host verified on commit [`0eebe8b`](https://github.com/huseyincig/opencode-guardian/commit/0eebe8bc3057ba52f705c8d3d5f8ace2eb2e423e), consolidated for release)
- **Automated Test Suite:** **429 / 429 unit and regression tests passed**
- **Sandbox Scenarios:** **18 / 18 isolated end-to-end scenarios passed**
- **Dependency Audits:** **0 vulnerabilities** across production and development lockfiles
- **Live-Host Dual Acceptance Verdict:** **4 / 4 — ACCEPTED** on both OpenCode V1 (`1.18.34`) and OpenCode V2 (`2.0.22`)

---

## Live-Host Dual Acceptance Matrix (v0.6.0)

Independent live-host acceptance tests were conducted on real host environments without mocks or simulated tool calls:

| Acceptance Section | OpenCode V1 (`1.18.34`) | OpenCode V2 (`2.0.22`) | Verified Behavior |
| :--- | :---: | :---: | :--- |
| **1. Post-Turn & Remediation** | **PASS** | **PASS** | Automated violation interception, structured remediation injection, three-way classification (`verified` / `failed` / `unverified`), and budget capping preventing runaway loops. |
| **2. Preflight & Security** | **PASS** | **PASS** | Pre-execution interception of destructive shell operations (`rm`), bit-level SHA-256 target preservation (0-byte modification), audit logging, and secret write blocking. |
| **3. TUI & Commands** | **PASS** | **PASS** | Live sidebar slot registration (V1 order 600 / V2 append), reactive counters from JSONL telemetry, 7 Command Palette actions, slash dispatcher, and confirmed reset. |
| **4. Lifecycle & Cleanup** | **PASS** | **PASS** | Clean teardown via `dispose()` and `AbortController`, reload idempotence without double registrations, timer leaks, or unhandled rejections. |
| **Final Result** | **4/4 — ACCEPTED** | **4/4 — ACCEPTED** | **Dual-Mode Contract Fully Verified** |

### Environment Details

1. **OpenCode V1 Host Environment:**
   - **Host Binary:** OpenCode `1.18.34` (`/usr/local/bin/opencode`)
   - **Runtime:** Linux x86_64, Node.js `v24.21.0`
   - **SDK Contract:** `@opencode-ai/plugin` (`1.18.34`)
   - **Test Workspace:** Isolated sandbox (`/root/guard-live-sandbox`)

2. **OpenCode V2 Host Environment:**
   - **Host Binary:** OpenCode `2.0.22`
   - **Runtime:** Linux x86_64, Node.js `v24.13.1`, Bun `1.3.10`
   - **SDK Contract:** `@opencode/plugin` (`2.0.22`), `@opencode/plugin/tui`
   - **Test Workspace:** Isolated sandbox (`/root/guardian_v2_audit_sandbox/test-project`)

---

## Concrete Live-Host Acceptance Evidence

### Section 1: Post-Turn & Remediation

1. **Violation Interception & Automated Prompt:**
   - In active agent turns, rules (`quality/no-shortcuts`, `discipline/no-apology`, `security/no-secrets`, `task/completion-gate`) triggered `decision: "block"` upon `session.idle`.
   - Structured remediation message starting with `[opencode-guardian remediation]` was dispatched to the agent session via host synthetic/prompt APIs.
   - Audit trail recorded `post-remediation` events in `.opencode/guardian-events.jsonl`.

2. **Three-Way Re-Inspection Classification (`verified` / `failed` / `unverified`):**
   - **`remediation-verified`:** When the agent modified disk files to correct the issue and supplied required execution proof (e.g. clean test run with exit code 0), re-inspection confirmed resolution (`remediationStatus: "verified"`, `status.verified++`).
   - **`remediation-failed`:** When the agent acknowledged the prompt but repeated the violation or failed to remove shortcuts, re-inspection caught the remaining issue (`remediationStatus: "failed"`, `status.failed++`).
   - **`remediation-unverified`:** When the agent claimed completion in text but produced no substantive tool-level proof for rules requiring verifiable evidence (`integrity/no-unverified-claims`), Guardian classified the outcome as unverified (`remediationStatus: "unverified"`, `status.unverified++`).

3. **Loop Guard & Budget Capping:**
   - Remediation turns (`isRemediationResponse: true`) enforce `remediationBudget` (default `1`).
   - When the budget is exhausted, the engine yields `decision: "pass"` with the determined remediation status, preventing recursive remediation cycles and infinite prompt loops.

### Section 2: Preflight & Security

1. **Pre-Execution Shell Interception:**
   - Under `preflight.enabled: true`, destructive shell actions (`rm canli_kabul_target.txt`, `rm -rf sensitive-target.txt`) were intercepted before process execution via `tool.execute.before` (V1) and `ctx.tool.hook("execute.before")` (V2).
   - In both environments, `providerCall.executed` remained `false`.
   - `GuardianPreflightError("destructive-command")` was thrown before the OS shell received the command.

2. **Bit-Level Target File Integrity:**
   - Target files retained bit-by-bit identical SHA-256 hashes before and after the attempted destructive execution:
     - Sandbox V1 target: `85451b5326dd5932...` $\rightarrow$ Unchanged (0 byte drift)
     - Sandbox V2 target: `1febda3694823474dbbbf4b4f78ce2086d7b5c4092200914a582b4588f4bb230` $\rightarrow$ Unchanged (0 byte drift)
   - Files remained intact on the host filesystem.

3. **Security Audit Logging & Safe Commands:**
   - Audit entry recorded with POSIX permissions `0600`:
     ```json
     {"at":"2026-10-04T20:28:51.592Z","id":"e724f80f-dad0-4201-a4b4-0141f35eb4a7","kind":"preflight-blocked","action":"blocked-before-execution","outcome":"prevented","session":"1636fe8f151c4746","tool":"shell","rules":["destructive-command"],"reasons":[{"rule":"preflight","code":"destructive-command"}]}
     ```
   - Safe operations (`npm test`, `echo SAFE_PREFLIGHT_VERIFIED`) executed without impedance and were recorded as `preflight-allowed`.
   - Supported file write tools (`write_to_file`, `replace_file_content`, MCP file mutators) attempting to persist hardcoded credentials (`sk-proj-...`) were blocked prior to disk mutation with `hardcoded-secret-in-file-write`.

### Section 3: TUI & Commands

1. **Sidebar Extension & Reactive Telemetry:**
   - V1 host mounted the widget via `api.slots.register({ order: 600, slots: { sidebar_content } })`.
   - V2 host mounted the widget via `ctx.ui.slot({ append: "sidebar.content" })`.
   - Sidebar poll timer (2500 ms) and Solid signals reactively displayed counters from `.opencode/guardian-events.jsonl`.
   - Header click smoothly toggled between collapsed (`▶ Guardian`) and expanded (`▼ Guardian`) diagnostic views.

2. **7 Guardian Commands (Ctrl+P / Command Palette):**
   - All 7 commands registered and produced validated, privacy-safe reports:
     - `status` (`opencode-guardian.status`): Live counters, latest event, verified/failed/unverified totals.
     - `activity` (`opencode-guardian.activity`): Redacted recent audit events.
     - `doctor` (`opencode-guardian.doctor`): Configuration validation and event log health.
     - `rules` (`opencode-guardian.rules`): Active severity configuration for all 14 rules.
     - `config` (`opencode-guardian.config`): Safe, redacted configuration overview.
     - `version` (`opencode-guardian.version`): Current v0.6.0 version and update status.
     - `reset` (`opencode-guardian.reset`): Confirmed counter reset dialog.

3. **Slash Commands & Dispatcher:**
   - Direct slash shortcuts (`/guardian-status`, `/guardian-activity`, etc.) registered in both palettes.
   - V2 general dispatcher (`/guardian <command>`) correctly executed subcommands and provided interactive guidance for invalid arguments.

4. **Statistics Reset Safety:**
   - Dialog cancellation left all counters and audit files unmodified.
   - Confirmation appended a `statistics-reset` record to the audit log: live counters reset to 0, while all prior audit history remained intact subject to normal log rotation.

### Section 4: Lifecycle & Cleanup

1. **Graceful Teardown:**
   - V1: `Guardian.server().dispose()` terminated active turn watchers and cleared verification caches.
   - V2: `setup()` disposer triggered `controller.abort()`, releasing tool hooks, event subscriptions, and keymap layers in reverse registration order.
   - TUI: `onCleanup` cleared background polling intervals (`clearInterval`), preventing memory and timer leaks.

2. **Reload Idempotence:**
   - Host reloads (`opencode reload`, service restart, and plugin re-instantiation) executed without duplicate event listeners, redundant interventions, or unhandled promise rejections.

---

## Automated Source Verification Results

| Verification Suite | Target & Description | Result |
| :--- | :--- | :---: |
| **Unit & Regression Suite** | 429 tests across all 14 rules, adapters, telemetry, and preflight | **429 / 429 PASS** |
| **End-to-End Sandbox** | 18 multi-turn failure and recovery scenarios across all rules | **18 / 18 PASS** |
| **Smoke Test** | Package entrypoints, exports, and status CLI | **PASS** |
| **Typecheck** | Strict TypeScript compilation (`tsc --noEmit`) | **PASS** |
| **Documentation & Links** | Markdown navigation, local link resolution, and SVG validator | **PASS (5 MD, 19 links, 1 SVG)** |
| **Production Audit** | `npm audit --omit=dev` | **0 vulnerabilities** |
| **Development Audit** | Full lockfile dependency audit | **0 vulnerabilities** |
| **Packaging Dry Run** | `npm pack --dry-run` (78 files, complete entrypoint bundle) | **PASS** |

---

## Methodological Boundaries & Limitations

1. **Opt-In Preflight:** Strict preflight is an opt-in safety net (`preflight.enabled: true`) designed to catch common accidental destructive commands and obvious secrets before execution. It is pattern-based and does not replace operating system user permissions, containers, or sandboxing.
2. **Post-Turn Scope:** Post-turn rule violations guide agent behavior and trigger automated remediation, but cannot retroactively reverse an operation that already completed.
3. **Log Rotation:** The event log (`.opencode/guardian-events.jsonl`) is bounded to 2 MiB with one rotated archive (`.opencode/guardian-events.jsonl.1`). Historical events older than the rotation window are aged out normally.

---

## Reproducing the Verification Suite

Run all local verification checks from the repository root:

```bash
# Install dependencies
npm ci

# Typecheck and test suite
npm run typecheck
npm test

# Sandbox scenarios and smoke test
node sandbox/smoke-test.mjs
node sandbox/comprehensive-test.mjs

# Documentation link validation
node scripts/check-docs.mjs

# Security and package integrity audits
npm audit --omit=dev
node scripts/check-dev-audit.mjs
npm pack --dry-run
```
