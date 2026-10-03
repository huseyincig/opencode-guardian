# Verification report

OpenCode Guardian was evaluated through automated tests, isolated security scenarios, and separate acceptance checks for both supported OpenCode hosts.

## Results

| Verification | Reported result |
| :--- | ---: |
| Automated unit and regression tests | **374 / 374 passed** |
| Isolated end-to-end scenarios | **18 / 18 passed** |
| OpenCode V1 acceptance | **4 / 4 criteria passed** |
| OpenCode V2 acceptance | **4 / 4 criteria passed** |
| Production dependency audit | **0 reported vulnerabilities** |

These are results from a specific evaluation, not live metrics or a blanket security guarantee. The automated tests, sandbox scenarios, and host acceptance checks are separate measurements.

## Host acceptance

| Check | OpenCode V1 | OpenCode V2 |
| :--- | :--- | :--- |
| Turn completion and remediation | PASS | PASS |
| Pre-execution security interception | PASS | PASS |
| TUI integration and counters | PASS | PASS |
| Teardown and reload | PASS | PASS |

### Turn completion and remediation

**V1:** The host adapter was tested with OpenCode 1.18.34. A completed-turn scenario using the real SDK message format and simulated assistant output generated one remediation; a duplicate idle event generated none. The fallback watcher also passed six regression tests covering missing idle events, completed-response detection, stable idle observations, cancellation, and SDK failures. The simulated assistant scenario is not a recorded live-model remediation.

**V2:** OpenCode 2.0.22 was tested in a live model session. Guardian detected a rule violation, sent a remediation prompt, and the agent processed it. The loop guard prevented a duplicate remediation response.

### Pre-execution protection

Destructive commands were submitted against disposable sandbox fixtures. Guardian reported blocking four V1 command variants and one V2 live-host deletion request before tool execution.

| Integrity check | V1 fixture | V2 fixture |
| :--- | :--- | :--- |
| Blocked requests | 4 | 1 |
| SHA-256 before | `1c3c3ef3fcd8d528b9d75b3644f1c327299f1961ee4ee3ef5c88019a1ec09dd6` | `3ce42425d0e843a5290dd4508665dabf12290fbb89128214f234d355430f55cf` |
| SHA-256 after | Unchanged | Unchanged |
| File integrity | Preserved | Preserved |

The V1 checks covered direct deletion, command substitution, backticks, and `find -delete`. The V2 report included a live-host `preflight-blocked` event and confirmed that the targeted tool call did not execute. These results establish protection for the tested inputs, not complete shell-language coverage.

### TUI and lifecycle

**V1:** The QA report confirmed sidebar registration, status counters, theme integration, disabled mode, and cleanup of pending watchers on disposal. Terminal-based checks were reported; no screenshot or pixel-comparison artifact was supplied.

**V2:** The live-host report confirmed sidebar expand/collapse, reactive status counters, theme integration, and clean hook/event teardown. No crash or unhandled rejection was observed in the reviewed logs.

## Security and dependency findings

- The security regression suite passed cases for destructive shell patterns, dynamic command names, and opaque command execution.
- Local example credentials in template files were accepted; realistic tokens and remote credentials remained blocked.
- The production-only dependency audit reported **0 vulnerabilities**.
- The full development dependency audit reported **12 high-severity upstream findings**, associated with the development SDK dependency chain. They remain unresolved.

**Protection boundary:** Strict preflight is opt-in and applies to recognized or explicitly configured shell tools. Post-turn inspection cannot reverse a tool operation. Host permissions and isolated environments remain necessary for sensitive workflows.

## Run the checks

```bash
npm ci
npm run typecheck
npm test
node sandbox/smoke-test.mjs
node sandbox/comprehensive-test.mjs
npm audit --omit=dev
node scripts/check-dev-audit.mjs
npm pack --dry-run
```

The commands reproduce automated checks, not interactive host acceptance. Live acceptance requires the corresponding OpenCode host and an isolated test environment.

---

**Evaluation record:** 03 October 2026 · Guardian 0.5.0 · OpenCode V1 1.18.34 / V2 2.0.22 · Baseline commit `b86b08e`.
