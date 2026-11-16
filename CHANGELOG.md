# Changelog

## 0.15.0 — 2026-11-17

- **BREAKING CHANGE — Pure OpenCode V2 (`>=2.3.0`) & OpenTUI (`>=0.8.4`) Alignment:**
  - Removed OpenCode V1 (`1.x` / `@opencode-ai/plugin` / `./server` / `sidebar_content` / V1 idle fallback) support. Users on OpenCode 1.x should pin `opencode-guardian@0.14.0`.
  - Updated `peerDependencies` floors to `@opencode/plugin >=2.3.0`, `@opentui/core >=0.8.4`, `@opentui/solid >=0.8.4`, and `solid-js >=1.9.0`.
- **New `./rpc` Export (`dist/intervention-rpc.js`):**
  - Added typed `opencode-guardian/rpc` entrypoint (`src/intervention-rpc.ts`) implementing `Rpc.define` (`@opencode/plugin/rpc`) for `guardian.interventions.get` and `guardian.interventions.clear` with `sessionID` `maxLength: 256` validation and project-directory-scoped `{}` clearing.
- **V2 Server, Hook & Subagent Hardening:**
  - Registered `context.shell?.hook("create.before")` preflight with LIFO hook rollback on setup failure.
  - Updated `StreamLoopWatcher` to treat `{ interrupted: false }` as a rejected interruption without emitting warning toasts or entering a stopped state.
  - V2 `prompt` hook cancels in-flight `idleQueue` inspection and clears stale `TaskContract` state (including empty/attachment-only prompts).
  - Treated `session.fork` / `session.forked` as independent root sessions, honored top-level `location.directory` before `ctx.session.get()`, and isolated `background === true` subagents in `execute.after` so sibling background subagents are never starved.
  - Normalized V2 `Error` instances and `{ type, message }` tool error objects in `src/evidence.ts`, and normalized V2 `shell` and `agent-switched` context entries.
  - Handled array, `{ data }`, and null/throwing list responses in `resolveV2AgentCapability`, and bounded capability caches and per-session Maps/Sets with `.unref?.()` timers.
  - Cleaned up `telemetryConfigRegistry` on early throw in `setup()`.
- **Security, Preflight & Sanitizer Fixes:**
  - Preserved `Uint8Array` / `ArrayBuffer` views and non-plain object prototypes (e.g., `Message` class) in `sanitizeObject` and `sanitizeMessages`.
  - Split multi-stage shell commands via `splitShellStages` in `extractGitCommitMessage`, `isLazyCommitMessage`, and `isHallucinatedOrMalformedPackageInstall` for both `tool.execute.before` and `shell.create.before`.
  - Fixed `task/completion-gate` so `"in progress"` replies with file mutations are not falsely marked `"remediation-verified"`.
  - Updated `VerificationSnapshotStore.observe` to preserve both `editIntegrity` and `fingerprint` on the same `callID`.
  - Re-verified state directory permissions with `lstatSync` in `verifiedStateDirs`.
- **TUI Reactivity, RPC Race & Bun Compatibility Fixes:**
  - Fixed reactive `GuardianSidebar` prop updates (avoiding frozen destructured `sessionID`), subscribed to `session.moved`, and added per-session generation/epoch gating so in-flight 500ms RPC polls cannot resurrect cleared interventions.
  - Fixed `version-notice.ts` `ftruncateSync` safety on cache writes.
  - Fixed `scripts/emit-tui.mjs` adaptive loader catch block so `dist/tui.js` cleanly falls back to `./tui-standalone.js` in Bun (`1.4.4`) without throwing `ResolveMessage`.
- **Test, Sandbox & Live Host Acceptance:**
  - Migrated all test and sandbox suites to pure V2 `setup(ctx)` and added `tests/v2-stage2a-regressions.test.mjs`.
  - Verified **765/765** unit/regression tests, **18/18** sandbox scenarios, and **10/10** live OpenCode `v2.3.0` + Bun `1.4.4` + packed `.tgz` acceptance checks.

## 0.14.0 — 2026-11-16

- **Low-I/O Telemetry & Bounded Audit Log (`telemetry.level`):**
  - Introduce configurable audit log granularity (`"violations" | "all" | "off"`) with a safe, performance-first default of `"violations"`.
  - In `"violations"` mode, high-frequency benign events (`preflight-allowed` on every shell command and `post-inspected` on clean turns) are eliminated, reducing disk I/O operations by 90–95% during active development and multi-command agent executions.
  - Retain full audit trail for security-critical actions: blocks (`preflight-blocked`), warnings (`post-warning`), remediation requests (`post-remediation`), verification outcomes (`remediation-verified`, `remediation-failed`), errors (`inspection-error`), statistics resets, and runtime bootstrap.
  - In `"off"` mode, suppresses all audit file operations (zero I/O) for headless CI/CD runs and resource-constrained environments.
  - Lower default bounded rotation limit from 2 MiB to 512 KiB per archive (`512 * 1024` bytes), configurable via `telemetry.maxBytes`.
  - Cache verified state directory permissions in-process (`verifiedStateDirs`) to eliminate redundant `mkdirSync` and `lstatSync` filesystem calls on every event write.
- **Environment Variable Controls for Test Runners & Pipelines:**
  - Add `OPENCODE_GUARDIAN_LOG_LEVEL=violations|all|off` to dynamically control log verbosity without touching project configuration files.
  - Add `OPENCODE_GUARDIAN_TELEMETRY=off|0|false` to immediately silence disk I/O when running automated test suites (`npm test`, Jest, Vitest, pytest).
  - Add `OPENCODE_GUARDIAN_MAX_LOG_BYTES=<number>` for dynamic log size threshold overrides.
- **OpenCode v2.2.7+ – v2.3.0 Standardized Shell Output & Signal Termination:**
  - Parse standardized `"Exit code: N"` lines at the end of shell outputs directly in `src/evidence.ts` when metadata is absent or stripped.
  - Detect signal terminations (`Command killed by signal`) and timeouts (`Command timed out`) from v2.2.7+ CLI outputs and classify them accurately as verification failures rather than unexpected exceptions.
- **Expanded Read-Only VCS Tools:**
  - Register `diff`, `git_diff`, `log`, `git_log`, `show`, `git_show` in `KNOWN_READ_ONLY_TOOLS` in `src/agent-capability.ts`, preventing read-only git inspection commands from being misclassified as mutation channels.
- **Engine, Lifecycle & TUI Hardening:**
  - Fix temporal dead zone (TDZ) initialization order of `runtimeByDirectory` in V2 `setup` abort listeners.
  - Fix syntax error in `src/index.ts` handler closing brace.
  - Standardize condition statements in `src/tui.tsx` reset action to satisfy strict oxlint checks.
- **Test Suite Expansion & Real OpenCode v2.3.0 Verification:**
  - Add 16 new automated tests across `tests/telemetry-config-validation.test.mjs`, `tests/telemetry-optimization.test.mjs`, and `tests/plugin-telemetry-integration.test.mjs`, bringing test suite total to **797 tests** (100% passing).
  - Verified with live OpenCode v2.3.0 CLI standalone server execution and 6/6 host acceptance security checks.

Validation on Node 26.13.1 / OpenCode v2.3.0: 797 tests, strict TypeScript checks (`--strict --exactOptionalPropertyTypes`), Oxlint (0 warnings, 0 errors), smoke test, 18 simulated multi-turn scenarios, and live V2 host acceptance passed.

## 0.13.0 — 2026-10-23

- Introduce hardened, bounded streaming loop watcher (`StreamLoopWatcher` in `src/stream-loop.ts`) shared across both OpenCode V1 and V2 host adapters.
- V1 stream tracking: inspects `message.part.updated` strictly for active assistant messages; automatically disables inspection upon user turn start, assistant completion, or session idle/interruption.
- V2 stream tracking: natively consumes `session.text.started|delta|ended` and `session.reasoning.started|delta|ended` events with incremental delta concatenation (2,048-char bounded tail).
- Support full rule configuration semantics (`error`, `warn`, `off`) in both string and object formats (`{ severity: "warn" }`); `warn` mode logs warnings and dispatches advisory toast notifications without interrupting output.
- Concurrency & project isolation: per-response mutex locks prevent duplicate interrupt calls on simultaneous parts; V2 event ingestion continues non-blocking during asynchronous project resolution.
- Timeout & retry gating: adds 3-second interrupt timeout (`AbortSignal.timeout(3000)`); bounded retry allows at most three attempts per response on continued stream growth, suppressing overlapping retries on ambiguous timeouts.
- Quoted literal fixture protection: excludes short quoted numeric and hex literals (15–128 characters) from low-entropy and cycle false positives, preventing legitimate test hashes from triggering blocks.
- Extended period support: detects longer periodic sentence structures up to 512 UTF-16 code units within the 2,048-character inspection window.
- Telemetry & TUI status: introduces `stream-interrupt-requested` audit event, toast notifications, and TUI status indicator (`▲ stream stop requested`).
- Add regression coverage in `tests/stream-loop-hardening.test.mjs` (16 new tests, bringing total suite to 781 tests).

Validation on Node 24.22.0: 781 tests, standard/strict TypeScript checks, lint, smoke test and 18 simulated scenarios passed. Package metadata and documentation identify v0.13.0.

## 0.12.5 — 2026-10-22

- Introduce language-agnostic **degenerative reasoning and text loop breaker** (`detectDegenerativeLoop` in `src/degeneration.ts`) stopping runaway token loops (such as DeepSeek V4.1 Flash *"Hmm..."*, Kimi 2.7 Chinese/Japanese repeating token cascades, runaway punctuation, or code repeats like *"None, None, None..."*).
- Integrate post-turn degenerative loop detection into `runtime/circuit-breaker` rule (`src/rules/circuit-breaker.ts`), checking assistant reasoning and text parts in the current turn and generating targeted remediation prompts.
- Implement **live in-flight streaming abort** in both V1 and V2 host adapters (`src/index.ts`) on `message.part.updated` events with a strided tail check ($\ge 40$ chars growth) running in $< 0.02$ ms, immediately invoking `client.session.abort` or `context.session.interrupt` to preserve the user's token budget and prevent wasted generation.
- Add negative false-positive exemptions for Markdown table rows (`|---|---|`), banner comment dividers (`// ===`), hash dividers, small test array fixtures, and normal code loops.
- Add regression coverage in `tests/degenerative-loops.test.mjs` (24 new tests covering English, Chinese, Japanese, Turkish, code tokens, low-entropy collapse, circuit breaker integration, and V1/V2 in-flight stream aborts).

Validation on Node 24.22.0: 765 tests, standard/strict TypeScript checks, lint, smoke test and 18 simulated scenarios passed. Package metadata and documentation identify v0.12.5.

## 0.12.4 — 2026-10-22

- Recognize native `write` tool payloads in preflight and telemetry categories; reject hardcoded credentials and source truncation placeholders while allowing safe file writes.
- Resolve the active session directory before V2 tool preflight and before-edit observation, ensuring multi-project environments evaluate strict per-project configuration without guessing directories from incomplete creation events.
- Install V2 auxiliary model guards independently of the initial project's secret setting and evaluate effective settings per request; support dynamic config updates and clean disposer teardown.
- Redact connection-string passwords with empty usernames or absent paths (including Redis, MySQL, Postgres URLs) while preserving URI structure and surrounding punctuation.
- Record structured replacement edits (including empty replacement and deletion operations) and individual affected paths as mutations in evidence tracking, ensuring stale test executions cannot satisfy post-change verification requirements.
- Inspect each patch file independently for undeclared dependencies (`no-ghost-deps`), retaining each file's language and nearest manifest boundaries across mixed-language and documentation edits.
- Add regression coverage in `tests/source-audit-fixes.test.mjs` (10 new tests).

Validation on Node 24.22.0: 741 tests, standard/strict TypeScript checks, lint, smoke test and 18 simulated scenarios passed. Package metadata and documentation identify v0.12.4.

## 0.12.3 — 2026-10-21

- Expand in-progress and ongoing work reporting detection across all 13 supported international locales (English, Turkish, Spanish, Portuguese, French, German, Russian, Arabic, Hindi, Chinese, Japanese, Korean, Indonesian).
- Subagents reporting ongoing progress in any supported language (e.g., *"en progreso"*, *"trabajo en curso"*, *"en cours"*, *"in Bearbeitung"*, *"в процессе"*, *"قيد التنفيذ"*, *"काम जारी है"*, *"进行中"*, *"進行中"*, *"진행 중"*, *"sedang berlangsung"*) are recognized with `isInProgress === true` and never falsely blocked by `task/completion-gate`.
- Wire `REPORT_TERMS` in `locale-intents.ts` with explicit `inProgress` phrases and connect `classifyAgentReport` to `classifyInternationalAgentReport`.
- Add test coverage across all 11 international languages in `tests/multilingual-task.test.mjs` and `tests/subagent-progress-completion-gate.test.mjs`.

Validation on Node 24.22.0: 731 tests, standard/strict TypeScript checks, lint, smoke test and 18 simulated scenarios passed. Package metadata and documentation identify v0.12.3.

## 0.12.2 — 2026-10-21

- Protect subagents and in-progress execution turns from false-positive completion gate blocking. Subagents reporting progress, step outcomes or communicating with their parent orchestrator without claiming task completion (`!report.isClosing`) pass through cleanly.
- Add `IN_PROGRESS_REGEX` and Unicode/Turkish-aware (`normalizeReportText`) classification in `locale-intents.ts` supporting Turkish and English ongoing work statements (*"işlem devam ediyor"*, *"çalışmaya devam ediyorum"*, *"ara rapor"*, *"durum güncellemesi"*, *"devredildi"*, *"work in progress"*, *"ongoing"*, *"investigating"*, etc.).
- Prevent false-positive completion-gate triggers when an orchestrator delegates work to a subagent or pauses for child execution.
- Retain strict verification enforcement when an agent explicitly claims completion (`report.isClosing === true`): required test checks and unresolved tool failures continue to be strictly gated.
- Add `ANTI_DISTRACTION_DIRECTIVE` in the remediation engine preventing agents from inspecting Guardian's plugin source code or audit logs.
- Standardize actionable remediation prompts across all 14 rules with numbered `ACTION REQUIRED:` directives.
- Add regression tests covering subagent progress reporting, orchestrator delegation, and completion validation.

Validation on Node 24.22.0: 730 tests, standard/strict TypeScript checks, lint, smoke test and 18 simulated scenarios passed. Package metadata and documentation identify v0.12.2.

## 0.12.1 — 2026-10-20

- Documentation alignment and verification reporting maintenance.
- Maintain full 14-discipline rule coverage and bounded edit integrity heuristics.

Validation on Node 24.22.0: 725 tests, standard/strict TypeScript checks, lint, smoke test and 18 simulated scenarios passed. Package metadata and documentation identify v0.12.1.

## 0.12.0 — 2026-10-20

- Normalize supported test counts and outcome reasons; reject zero-test, skipped-only and conflicting summaries as proof of required verification.
- Compare explicit current passed-test counts with fresh observations and distinguish user cancellation from test collection failures.
- Observe bounded whole-file edits through V1/V2 hooks; report suspicious content loss as advisory and reject source truncation placeholders in strict preflight.
- Add production dependency advisories and optional `productionOnly` enforcement; preserve test, build-tool and type-only imports.
- Share credential formats between file-write detection and output redaction.
- Improve lexical checks for stubs, swallowed errors and test bypasses; retain JS private fields/template execution and trusted prose exceptions.
- Enforce research-only constraints and tighten baseline, Git repository/refspec and hook-bypass authorization.
- Add a fourteen-discipline positive/negative corpus and focused regressions. See [coverage and limitations](docs/discipline-coverage.md); no new real-host or interactive TUI acceptance is claimed.

Validation on Node 24.22.0: 725 tests, standard/strict TypeScript checks, lint, smoke test and 18 simulated scenarios passed. Package metadata and documentation identify v0.12.0; historical live-host acceptance retains its original versions and results.

## 0.11.2 — 2026-10-20

- Sanitize all own `Error` properties recursively, including non-enumerable `cause`, aggregate errors and provider metadata, without modifying the original error.
- Remove executable serialization callbacks such as `toJSON` from sanitized values, and preserve reserved JSON keys without changing object prototypes.
- Read native V1 `session.deleted` events through `properties.info.id` and clear the associated task and capability state.
- Cancel stale V1 idle inspections on session deletion, plugin disposal and new human prompts, including attachment-only prompts.
- Prevent cancelled capability queries from repopulating deleted-session caches; clear previous task guidance on a new human turn.
- Honor V1 mutation-tool `deny`/`ask` rules and shared file-edit restrictions when deciding whether a child may remediate automatically.
- Add 19 debugging regressions and correct the capability test that treated enabled `apply_patch` as an override for an edit denial.

Validation on Node 24.22.0: 619 tests, strict TypeScript checks, lint, smoke test and 18 simulated scenarios passed. See the [Verification and Acceptance Report](docs/verification-report.md) for packaging checks and historical host-acceptance boundaries.
