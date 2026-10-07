# Verification and Acceptance Report

This document reports the **v0.8.0 automated verification suite** and preserves the latest completed **dual-mode live-host acceptance baseline from v0.6.0** across OpenCode V1 and OpenCode V2 host environments.

---

## Executive Summary

- **Package Version:** OpenCode Guardian `v0.8.0`
- **Previous Release Baseline:** `v0.6.0` (dual-host acceptance evidence retained below)
- **Current Automated Source Suite:** **534 / 534 unit, security, toast notification, and regression tests passed**
- **Sandbox Scenarios:** **18 / 18 isolated end-to-end scenarios passed**
- **Dependency Audits:** **0 vulnerabilities** across production and development lockfiles
- **Historical Live-Host Dual Acceptance:** **4 / 4 — ACCEPTED** on both OpenCode V1 (`1.18.34`) and OpenCode V2 (`2.0.22`) for v0.6.0

> v0.8.0 introduces visible color-coded user-facing toast notifications across V1 and V2 host channels, strict rule sanitization preventing code/secret leaks, and maintains strict concrete failure remediation invariants, high-confidence instruction fidelity without mutation downgrades, per-rule fingerprint remediation budgeting, lifecycle reverse-splice disposal, and multi-layer secret protection & output redaction across OpenCode V1 and V2. The complete dual-host matrix below is historical v0.6.0 evidence and is not relabeled as a fresh v0.8.0 V1/V2 acceptance run.

---

## Historical Live-Host Dual Acceptance Matrix (v0.6.0)

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
     - `version` (`opencode-guardian.version`): Current v0.6.5 version and update status.
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

## v0.8.0 Visible Color-Coded Toast Interventions, Rule Sanitization, and Multi-Channel Parity

The v0.8.0 release restores immediate user visibility for Guardian runtime interventions:

- **Visible Color-Coded Toast Notifications (`toast`):**
  - **Red / Error:** Preflight blocks (`preflight-blocked`) and synthetic remediations (`remediation`), providing immediate notification that an unsafe action was prevented or agent corrected.
  - **Yellow / Warning:** Advisory warnings (`warning`) on non-blocking policy findings.
  - **Info:** Version announcements and system notices.
- **Strict Rule Sanitization & Privacy Safety:**
  - `sanitizeToastRuleId` whitelist-checks rule names, preventing raw terminal commands, code snippets, or secrets from being reflected in UI toasts.
- **Dual-Host V1 & V2 Parity:**
  - Dispatches across V1 `client.tui.showToast`, V2 `context.ui.toast.show`, `context.client.tui.showToast`, and active TUI in-memory listeners.
  - 600ms deduplication window prevents spam during rapid tool calls.

## v0.7.0 Lifecycle Reverse-Splice Disposal, Turn Budget Scope, and Preflight Parity

The v0.7.0 release addresses line-by-line plugin contract findings and hardens runtime safety:

- **Lifecycle Reverse-Splice Idempotent Disposal (`index`):**
  - Replaced all in-place `registrations.reverse()` calls with `registrations.splice(0).reverse()` across all error and teardown blocks, adhering to the verified OpenCode plugin lifecycle specification.
- **Accurately Scoped Turn Remediation Budgeting (`engine` & `state`):**
  - Scoped the `remediationMessagesCount >= budget` check strictly behind `isRemediationResponse`, preventing premature `pass` decisions on new/unexhausted rules occurring later in the turn while preserving loop guard when retrying identical failures.
  - Removed premature `state.fingerprints.has(fingerprint)` early-return in `canRemediate()`, allowing multi-attempt budgeting (`budget > 1`) to function properly.
- **V2 Preflight Safety Parity (`index`):**
  - Integrated `assessCommandPreflight` checks into V2 `execute.before` hook when `!strictPreflight`, ensuring shell safety evaluation parity with V1.

## v0.6.9 Concrete Failure Invariants, Instruction Fidelity, and Fingerprint Remediation Budgeting

The v0.6.9 release resolves softening regressions and restores uncompromising runtime safety:

- **Concrete Failure Invariant (`task-completion`):**
  - Completely eliminated the `(hasToolFailure && !report.isClosing)` early pass bypass. Write-capable agents with concrete tool errors or failed verification checks (`isFailedCheck`) must block and remediate; admitting failure without claiming completion is no longer a loophole.
  - Read-only, approval-required, and unknown child subagents continue to fail-safe by reporting unresolved blockers to the parent without un-executable synthetic loops.
- **Instruction Fidelity Confidence (`instruction-fidelity`):**
  - Removed automatic downgrading to `advisory` (`pass`) when file mutations were observed. Refusals contradicting explicit user instructions consistently trigger `block` decisions with high confidence.
- **Fingerprint and Rule Remediation Budgeting (`engine` & `state`):**
  - Replaced flat global turn cutoffs (`remediationMessagesCount >= budget`) with per-rule fingerprint budget counters (`getRuleRemediationCount`, `hasExhaustedRule`).
  - Repetition of the same violation continues to be bounded to avoid infinite loops, but new and distinct substantive errors occurring later in the same turn receive remediation up to the turn ceiling.

## v0.6.8 Multi-Layer Secret Protection, Language-Agnostic Policy, and Subagent Topology Hardening

The v0.6.8 release integrates comprehensive secret redaction and runtime safety:

- **Multi-layer secret protection and post-execution redaction:** implements deterministic redaction across all surfaces:
  - **PRE:** Command preflight flags high-risk environment dump commands (`docker exec ... env`, `printenv`, `docker inspect`).
  - **POST:** Sanitizes tool results (`output`, `metadata`, `stdout`, `stderr`) and `Tool.Error` shapes (`message`, `stack`, `error`/raw defect, `metadata`) immediately upon execution.
  - **FINAL:** Context gates intercept outgoing `messages` and `system` transforms before model context.
  - **Fail-Closed:** Errors during sanitization suppress sensitive content (`[OUTPUT REDACTED: sanitization failure]`); missing V2 security hooks fail closed to ensure raw outputs never leak.
- **Language-agnostic policy & verification:** policy decisions are made through structured runtime evidence, execution traces, and protocol markers rather than expanding brittle natural-language regexes.
- **Authoritative subagent topology:** root vs subagent decisions rely exclusively on actual session parent relations (`parentID`), never inferring topology from agent names. Unknown topology fails safe without unauthorized root remediation.

## v0.6.7 Handoff, Quality, and Capability-Aware Hardening

The v0.6.7 source adds the following verified behaviors on top of the v0.6.0 release baseline:

- **Capability-aware subagent remediation policy:** resolves host-evaluated agent mutation profiles (`read_only`, `write_allowed`, `write_requires_approval`, `unknown`). Read-only subagents (reviewers, oracles, explorers) receive zero synthetic remediation prompts (`remediationCount: 0`) and never enter redundant review loops upon completing their analysis; write-allowed subagents (fixers, editors) retain bounded remediation support with controlled retry limits (`maxRounds: 6`).
- **Foreground subagent finalization barrier:** synchronous V1 `task` and V2 `subagent` calls are tracked from execute-before through execute-after. Parent-facing results are withheld while required Guardian remediation runs on the child, and the latest child report replaces the stale first-pass result.
- **Smart Questions handoff protocol:** decoupled, versioned `[OPENCODE_HANDOFF:v1]` protocol integration with strict native question tool validation and rule-delegated handoff requirements.
- **Background behavior preserved:** background subagents remain on the independent idle-remediation path and are not converted into blocking foreground handoffs.
- **Authoritative child identity:** when supported by the host, child classification uses `session.parentID` instead of relying only on agent-name heuristics.
- **Redundant-confirmation guard:** an explicit current user action is no longer handed back as an unnecessary "should I proceed?" decision when no concrete blocker exists.
- **Stricter static gates:** `noUnusedLocals`, `noUnusedParameters`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, and Oxlint warnings-as-errors are part of the repository verification flow.
- **Dependency audit hardening:** the lockfile resolves patched Seroval `1.6.8`; production and development audits report zero vulnerabilities.

## Automated Source Verification Results

| Verification Suite | Target & Description | Result |
| :--- | :--- | :---: |
| **Unit & Regression Suite** | 521 tests across all 14 rules, secret redaction, adapters, telemetry, handoff protocol and preflight | **521 / 521 PASS** |
| **End-to-End Sandbox** | 18 multi-turn failure and recovery scenarios across all rules | **18 / 18 PASS** |
| **Smoke Test** | Package entrypoints, exports, and status CLI | **PASS** |
| **Typecheck** | Project TypeScript plus strict hardening (`noUnused`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`) | **PASS** |
| **Lint** | Oxlint (`src` + `tests`, warnings denied) | **PASS** |
| **Documentation & Links** | Markdown navigation, local link resolution, and SVG validator | **PASS (5 MD, 22 links, 1 SVG)** |
| **Production Audit** | `npm audit --omit=dev` | **0 vulnerabilities** |
| **Development Audit** | Full lockfile dependency audit | **0 vulnerabilities** |
| **Packaging Dry Run** | `npm pack --dry-run` (complete entrypoint bundle) | **PASS** |

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

# Typecheck, strict type safety, lint and test suite
npm run typecheck
npm run typecheck:strict
npm run lint
npm test

# Sandbox scenarios and smoke test
node sandbox/smoke-test.mjs
node sandbox/comprehensive-test.mjs

# Documentation link validation
node scripts/check-docs.mjs

# Security and package integrity audits
npm audit --omit=dev
npm audit
node scripts/check-dev-audit.mjs
npm pack --dry-run
```
