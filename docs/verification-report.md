# Verification report

This report distinguishes the **04 October 2026 v0.5.1 automated evaluation** from the **03 October 2026 v0.5.0 host acceptance**. Results are point-in-time evidence, not live telemetry or a guarantee against all errors.

## v0.5.1 automated evaluation — 04 October 2026

| Verification | Observed result |
| :--- | ---: |
| Automated unit and regression tests | **397 / 397 passed** |
| Isolated end-to-end sandbox scenarios | **18 / 18 passed** |
| Smoke test | **Passed** |
| TypeScript typecheck | **Passed** |
| Documentation check | **5 Markdown files, 19 local links, 1 SVG passed** |
| npm package dry run | **76 files; required entrypoints present** |
| Production dependency audit | **0 reported vulnerabilities** |
| Full development dependency audit | **0 reported vulnerabilities** |
| OpenCode V1 / V2 interactive host acceptance on v0.5.1 | **Not re-run** |

The v0.5.1 package uses `@opencode-ai/plugin` **1.18.34** for V1 and `@opencode/plugin` **2.0.22** for V2 in development. The indirect `http-cache-semantics` dependency is **4.3.0**. Both dependency audits report zero vulnerabilities for this evaluated lockfile.

Changes since the published `v0.5.0` tag include privacy-safe, size-bounded audit events; safer V1 completion polling and remediation delivery checks; redacted inspection errors; expanded recognized MCP-shell and scoped Git preflight checks; literal filesystem formatting and fork-bomb signatures; corrected Go multi-block dependency parsing; and safer CI merged-branch cleanup. Regression tests cover these changes.

## Historical v0.5.0 host acceptance — 03 October 2026

The following **4/4 V1 and 4/4 V2** acceptance criteria were reported for the earlier v0.5.0 evaluation. They have **not been independently re-run on the v0.5.1 source**, so they must not be presented as current live-host acceptance.

| Check | OpenCode V1 | OpenCode V2 |
| :--- | :--- | :--- |
| Turn completion and remediation | Reported PASS | Reported PASS |
| Pre-execution security interception | Reported PASS | Reported PASS |
| TUI integration and counters | Reported PASS | Reported PASS |
| Teardown and reload | Reported PASS | Reported PASS |

### Turn completion and remediation

**V1:** The historical host adapter evaluation used OpenCode 1.18.34. A completed-turn scenario using the real SDK message format and simulated assistant output generated one remediation; a duplicate idle event generated none. The simulated scenario is not a recorded live-model remediation.

**V2:** The historical host report described a live model session with OpenCode 2.0.22. Guardian detected a violation, requested remediation, and the agent processed it without a duplicate remediation response.

### Pre-execution protection and file integrity

The historical report described blocking four V1 command variants and one V2 live-host deletion request before tool execution against disposable sandbox fixtures.

| Integrity check | V1 fixture | V2 fixture |
| :--- | :--- | :--- |
| Blocked requests | 4 | 1 |
| SHA-256 before | `1c3c3ef3fcd8d528b9d75b3644f1c327299f1961ee4ee3ef5c88019a1ec09dd6` | `3ce42425d0e843a5290dd4508665dabf12290fbb89128214f234d355430f55cf` |
| SHA-256 after | Unchanged | Unchanged |
| File integrity | Preserved | Preserved |

The V1 scenarios covered direct deletion, command substitution, backticks, and `find -delete`. The V2 report included a live-host `preflight-blocked` event and a non-executed tool call. This establishes protection for the reported inputs, not complete shell-language coverage.

### TUI and lifecycle

The earlier V1 report confirmed sidebar registration, counters, theme integration, disabled mode and watcher cleanup. No screenshot or pixel-comparison artifact was supplied. The earlier V2 report confirmed sidebar expand/collapse, reactive counters, theme integration and clean hook/event teardown, with no crash or unhandled rejection observed in reviewed logs.

### Previous development-audit finding

The older v0.5.0 evaluation recorded **12 upstream high-severity development-dependency findings**. That is a historical result, **not the current v0.5.1 status**: after updating the V2 development SDK and the indirect HTTP cache dependency, the v0.5.1 full and production audits each reported **0 vulnerabilities**.

## Limits and reproduction

Strict preflight is **opt-in**. It inspects recognized or explicitly configured shell tools and is not a full shell interpreter. Post-turn findings cannot reverse a completed operation. Host permissions and isolated environments remain necessary.

```bash
npm ci
npm run typecheck
npm test
node sandbox/smoke-test.mjs
node sandbox/comprehensive-test.mjs
node scripts/check-docs.mjs
npm audit --omit=dev
node scripts/check-dev-audit.mjs
npm pack --dry-run
```

These commands reproduce the automated checks, not interactive host acceptance. Live acceptance requires the corresponding OpenCode host and an isolated test environment.

**Evaluation records:** v0.5.1 automated checks — 04 October 2026, based on the verified release-candidate working tree. Historical v0.5.0 host report — 03 October 2026 (original reported baseline `b86b08e`); published `v0.5.0` tag points to `119e93a`.
