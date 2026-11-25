# OpenCode V2 Acceptance Result

## v0.18.2 Live OpenCode v2.4.1 + Bun 1.4.4 Host Acceptance

> **Verification Date:** 25 November 2026  
> **Host Environment:** OpenCode `v2.4.1` (`/usr/bin/opencode`), Node `v26.13.1`, Bun `1.4.4`, Linux x86_64  
> **Plugin Under Test:** `opencode-guardian@0.18.2` (Pure OpenCode V2)  
> **Acceptance Script:** [`sandbox/v2-live-acceptance.mjs`](../sandbox/v2-live-acceptance.mjs)  
> **Result:** **10 / 10 CHECKS PASS — ZERO DEFECTS** (+ **21 / 21** live real-LLM scenarios on `opencode serve` across all 14 rules, preflight, secret redaction, and multi-rule batching)

| Check | Scenario | Expected Behavior | Observed Result |
| :--- | :--- | :--- | :---: |
| **Check 1** | Packed `.tgz` in Node `v26.13.1` | Import `.`, `./tui`, and `./rpc` from packed tarball | **PASS** |
| **Check 2** | Packed `.tgz` in Bun `1.4.4` | Import `.`, `./tui`, `./rpc` & `dist/tui.js` standalone fallback without `ResolveMessage` crash | **PASS** |
| **Check 3** | V2.4.1 Server Hook & RPC Registration | All V2.4.1 hooks (`experimental.idle` included) & `./rpc` methods registered via `setup(ctx)` | **PASS** |
| **Check 4** | Preflight in `tool.execute.before` & `shell.create.before` | Blocks destructive commands across both tool and shell creation hooks | **PASS** |
| **Check 5** | Error Secret Redaction | Nested Error credentials redacted before visibility | **PASS** |
| **Check 6** | Post-Turn Remediation & Clean-Turn RPC Clear | Remediation dispatched on `session.execution.succeeded` violation; RPC state cleared on clean turn | **PASS** |
| **Check 7** | Low-I/O Telemetry Filtering | Default `violations` mode filters benign events while preserving violations | **PASS** |
| **Check 8** | Clean Server Disposal | `setup(ctx)` disposer tears down listeners, hooks, and timers cleanly | **PASS** |
| **Check 9** | V2 TUI Verification | Additive `sidebar.content` / `session.composer.top` slots, 7 commands + `/guardian`, `plugin.updated`/`config.updated` refresh, and `enabled: false` hide | **PASS** |
| **Check 10** | Real OpenCode `v2.4.1` CLI Host | `/usr/bin/opencode` (`v2.4.1`) isolated workspace with plugin config | **PASS** |

---

## Multi-Plugin Mesh & Handoff Verification

Coexistence and handoff security between Guardian and sibling V2 plugins (such as `opencode-smart-questions` and `opencode-hi`) are verified via [`tests/mesh-and-handoff.test.mjs`](../tests/mesh-and-handoff.test.mjs) and [`tests/subagent-and-capability.test.mjs`](../tests/subagent-and-capability.test.mjs):

- **Protocol & Provenance:** `Symbol.for("opencode.mesh.v2")`, `opencode-mesh.state` RPC (with directory-scoped authorization, bounded lease TTLs up to 10 minutes, and standby RPC failover on primary failure), `[OPENCODE_HANDOFF:v1]` compatibility, and per-session cryptographic provenance tokens (`metadata["opencode-mesh"].token`) verify all trust-critical envelope fields (`owner`, `kind`, `synthetic`, `protected`, `sanitizedBy`, `boundedBy`, `taskID`, `requiredSkills`) against the immutable ledger without falling back to unsigned synthetic flags when a token is tampered, and isolate plugin-local cleanup (`forgetMeshOwnerSession`) from full session deletion (`forgetMeshSession`).
- **Session Leases & Handoffs:** `active_remediation` leases automatically renew via heartbeat during long foreground subagent and idle remediations, track per-instance ownership for clean disposal, and respect `user_interaction` priority; `question_presented` handoffs pause re-blocking until a human reply arrives.
- **Subagent Isolation:** Host `session.permissions` and host-assigned `session.agent` profiles always intersect and override permissive peer mesh role profiles (including `write-requires-approval`); read-only, approval-required, unknown, and `ses_aut_*` automation subagents never receive root self-remediation prompts.
- **Host Compatibility & Supply-Chain Gates:** Live host acceptance is verified on OpenCode `v2.4.1`; `>=2.3.0` peer compatibility (including legacy `session.idle` / `session.status` fallbacks and optional `experimental.idle` / `shell.create.before` hooks) is covered by automated V2 lifecycle tests. Dev-dependency auditing (`scripts/check-dev-audit.mjs`) pins exact upstream advisory IDs and fails closed on any unpinned or high/critical advisory. Historical V1 support ended in `v0.14.0` (see [CHANGELOG.md](../CHANGELOG.md)).
