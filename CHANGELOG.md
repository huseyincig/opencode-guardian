# Changelog

## 0.17.3 — 2026-11-24

- **Server & TUI Runtime Performance Optimizations (`src/secrets/sanitizer.ts`, `src/index.ts`, `src/telemetry.ts`, `src/tui.tsx`):**
  - **Single-Pass Tool Result Sanitization (`sanitizeToolResultWithMeta` & `sanitizeV2ToolErrorWithMeta`):** Collapsed OpenCode V2 `{ content, metadata }` tool output redaction from 3 redundant regex passes to a single pass, and removed double `JSON.stringify` diffing in `tool.hook("execute.after")` by counting redactions directly from `redactedCount > 0`.
  - **`lstatSync` Nanosecond Telemetry Cache & Equality-Guarded Sidebar:** Added a bounded `statusFileCache` (`ino + size + mtimeNs + ctimeNs + mode`, immediately invalidated on `recordGuardianEvent` and `clearGuardianTelemetryConfig`) to `readGuardianStatus` so unchanged logs skip `openSync`/`readSync`/`JSON.parse`. Added `guardianStatusEqual` to `GuardianSidebar` to prevent redundant Solid re-renders and relaxed the idle sidebar poll interval from `2500ms` to `5000ms`.
  - **Adaptive Event-Driven TUI RPC Polling:** Replaced fixed `500ms` `setInterval` RPC polling with an adaptive `setTimeout` schedule (`500ms` while a session is `running` or an intervention banner is active, `5000ms` while `idle` with no active banner — 10x lower idle RPC traffic) paired with immediate event-driven wakeups on `session.status` and `session.idle`.
- **Verification:**
  - Added 3 regression tests in `tests/v0173-perf-optimizations.test.mjs` (**830 / 830** tests passing, **18 / 18** sandbox scenarios, **10 / 10** live OpenCode `v2.4.1` + Bun `1.4.4` acceptance checks, Oxlint 0 warnings / 0 errors across 119 files).

## 0.17.2 — 2026-11-24

- **OpenCode `v2.4.1` SDK & Runtime Alignment (`package.json`, `src/index.ts`, `src/tui.tsx`):**
  - Updated `devDependencies` to `@opencode/plugin` `^2.4.1`, `@opentui/core` `^0.9.9`, and `@opentui/solid` `^0.9.9` while keeping `peerDependencies` backward-compatible (`@opencode/plugin >=2.3.0`, `@opentui/* >=0.8.4`).
  - **Canonical Background Job Key Reconciliation:** Updated `backgroundJobKey` in `src/index.ts` to prefer shared semantic job identifiers (`jobID` → `shellID` → `childSessionID` → `kind:path` → `id`) so `experimental.idle` (`SessionIdleBackground`) and `experimental.job.updated` (`Job.Info`) map to identical keys across all 5 job kinds (`codemode`, `shell`, `subagent`, `image`, `video`).
  - **TUI Non-Blocking Startup & Hot-Reload Recovery:** Subscribed `src/tui.tsx` to `plugin.updated` and `config.updated` (guarded defensively for minimal hosts) to refresh RPC interventions and sidebar state on `v2.4.x` background plugin load and 24h auto-reload, and cleared `dismissedInterventionSignatures` on teardown.
  - **Abort & Teardown Hygiene (`v2.4.1` `#65441`):** Added immediate `controller.signal.aborted` exit inside `eventLoop` and cleared `lastTranscriptNotice` on `session.deleted`, `session.moved`, and plugin disposal.
- **Opt-in Chat Transcript Notices (`notifications.transcript`, `src/index.ts`, `src/engine.ts`, `src/types.ts`):**
  - With `{ "notifications": { "transcript": true } }`, every intervention also posts a `[Guardian] <title>: <message>` line into the chat as a model-invisible `visible` synthetic message (`resume: false`, de-duplicated for 10 s per session), restoring the V1 scrolling chat record. Default off.
- **Telemetry Level Display Fix (`src/telemetry.ts`, `src/commands.ts`, `scripts/guardian-status.mjs`):**
  - Processes that never ran the server `setup()` (TUI, `/guardian-status`, `opencode-guardian-status`) now fall back to the documented `violations` default instead of `all`, and status commands report the project's effective `telemetry` setting.
- **Stream Stop Verification & Visibility (`src/stream-loop.ts`, `src/telemetry.ts`, `src/tui.tsx`, `src/commands.ts`, `scripts/guardian-status.mjs`):**
  - After an accepted `session.interrupt`, the watcher checks host events: `session.execution.interrupted` / `session.idle` records `stream-interrupt-verified`; deltas still arriving when the window closes (`OPENCODE_GUARDIAN_STREAM_VERIFY_MS`, default 4000 ms) record `stream-interrupt-ineffective` and re-enable another interrupt attempt.
  - Added `streamStops`, `streamVerified`, and `streamIneffective` counters to `readGuardianStatus`, sidebar (`Interventions` `Ns` suffix and `Stream Stops` row), `/guardian-status`, and `opencode-guardian-status`.
- **Verification:**
  - Added 12 regression tests across `tests/v0172-stream-verify.test.mjs`, `tests/v0172-telemetry-level.test.mjs`, `tests/v0172-transcript-notice.test.mjs`, and `tests/v0172-v241-audit.test.mjs` (**827 / 827** tests passing, **18 / 18** sandbox scenarios, **10 / 10** live OpenCode `v2.4.1` + Bun `1.4.4` acceptance checks, Oxlint 0 warnings / 0 errors across 118 files).

## 0.17.1 — 2026-11-23

- **OpenCode `v2.4.0` Runtime & SDK Compatibility (`src/index.ts`, `src/evidence.ts`, `package.json`):**
  - Updated `devDependencies` to `@opencode/plugin` `^2.4.0`, `@opentui/core` `^0.9.7`, and `@opentui/solid` `^0.9.7` (matching `@opencode/plugin@2.4.0`'s OpenTUI `>=0.9.4` floor while preserving `peerDependencies` `>=2.3.0` / `>=0.8.4` compatibility).
  - **Code Mode Background Timeout & Dotted Tool Calls:** Treated `v2.4.0` backgrounded Code Mode `execute` calls (`metadata.jobID`, `metadata.status === "running"`, `"Execution moved to the background"`) as unfinished/`"unknown"` in `hasUnfinishedBackgroundTool` and `statusFromPart` until `type: "synthetic"` (`source: "codemode"`, `jobID`) completion arrives. Extracted nested `metadata.toolCalls` from top-level dotted Code Mode calls (`tools.ns.fn`).
  - **Background Job Lifecycle (`experimental.job.updated` & `"video"`):** Tracked per-session active background jobs from `experimental.idle` (`"codemode" | "shell" | "subagent" | "image" | "video"`) and cleared `backgroundSessions` locks when `experimental.job.updated` reports `completed`, `error`, or `cancelled` and no remaining jobs are active.
  - **Automations (`ses_aut_*`) & Hot-Reload (`plugin.updated`):** Classified `ses_aut_` automation child run sessions (`Automation.isRunSession`) as subagents so read-only automation runs never receive root remediation prompts, and invalidated agent capability caches on `plugin.updated` alongside clean `backgroundSessions`/`sessionBackgroundJobs` teardown for `v2.4.0` hot-reload.
- **Verification:**
  - Added 5 OpenCode `v2.4.0` compatibility regression tests in `tests/v0171-v240-compat.test.mjs` (**815 / 815** tests passing, **18 / 18** sandbox scenarios, **10 / 10** live OpenCode `v2.4.0` + Bun `1.4.4` acceptance checks, Oxlint 0 warnings / 0 errors across 114 files).

## 0.17.0 — 2026-11-23

- **Frictionless `"critical"` vs `"strict"` Preflight Protection Modes (`src/preflight.ts`, `src/types.ts`, `src/index.ts`, `src/commands.ts`):**
  - Added `preflight.mode?: "critical" | "strict"` (`"strict"` remains the default when `preflight.enabled: true` for backward compatibility).
  - **`"critical"` Mode (`{ "preflight": { "enabled": true, "mode": "critical" } }`):** Blocks catastrophic destructive shell operations (`rm -rf`, `git reset --hard`, `git push --force`, `git clean -f`, `mkfs`, fork bombs, `DROP DATABASE`, `terraform destroy`, `kubectl delete ns`, `docker system prune -a`, `npm unpublish`, `gh repo delete`, `find -delete`), opaque decoded shell execution (`base64 -d | sh`, `powershell -enc`), dynamic command names, hardcoded secrets and truncation placeholders in file writes, and hallucinated/malformed npm packages — while allowing everyday developer actions (`rm <single-file>`, `printenv`/`env`/`docker inspect`, and short/WIP git commit messages).
- **Global-to-Project Config Hierarchy & Untrusted Repo Downgrade Protection (`src/engine.ts`, `src/types.ts`, `src/commands.ts`):**
  - Updated `loadConfig(directory)` to read and merge both the global configuration (`~/.config/opencode/opencode-guardian.json`, `$OPENCODE_CONFIG_DIR`, or `$XDG_CONFIG_HOME/opencode`) and the project configuration (`<project>/opencode-guardian.json` or `.opencode/opencode-guardian.json`) so project configs inherit global settings.
  - Added `allowProjectOverrides?: boolean` to `GuardConfig`: when `"allowProjectOverrides": false` is set in the global configuration, untrusted project repositories cannot disable Guardian (`enabled: false`), disable `preflight.enabled`, downgrade `preflight.mode` from `"strict"` to `"critical"`, disable `secrets.enabled`, reduce remediation/iteration budgets, or weaken rule severities (`error` → `warn`/`off`, `warn` → `off`).
- **In-Memory Live Telemetry Counters & `violations` Mode Transparency (`src/telemetry.ts`, `src/commands.ts`, `scripts/guardian-status.mjs`, `src/index.ts`):**
  - Tracked per-project in-memory inspection (`inspectedSkippedDisk`) and secret redaction (`recordGuardianRedaction` / `status.redacted`) counters even when `telemetry.level === "violations"` skips disk writes for benign `preflight-allowed` and `post-inspected` events.
  - Updated `/guardian-status` and `opencode-guardian-status` to display `Telemetry mode: violations (clean turns omit disk I/O)` and `Secret redactions (in-memory)`.
- **Verification:**
  - Added 3 comprehensive feature suites in `tests/v0162-deep-debug.test.mjs` (**810 / 810** tests passing, **18 / 18** sandbox scenarios, **10 / 10** live OpenCode `v2.3.2` + Bun `1.4.4` acceptance checks, Oxlint 0 warnings / 0 errors across 113 files).

## 0.16.3 — 2026-11-22

- **XDG State Directory Compliance (`src/telemetry.ts`):**
  - Updated `guardianStateDirectory` to honor an absolute `XDG_STATE_HOME` path (when `OPENCODE_GUARDIAN_STATE_DIR` and `NODE_TEST_CONTEXT` are unset), falling back to `~/.local/state/opencode-guardian` when `XDG_STATE_HOME` is unset or relative per the XDG Base Directory Specification.
- **Test & Verification Alignment:**
  - Added `XDG_STATE_HOME` resolution coverage in `tests/project-scope-and-state-isolation.test.mjs` and standardized the deep-debug regression suite name to `tests/v0162-deep-debug.test.mjs` (**807 / 807** tests passing, **18 / 18** sandbox scenarios, **10 / 10** live OpenCode `v2.3.2` + Bun `1.4.4` acceptance checks, Oxlint 0 warnings / 0 errors across 113 files).

## 0.16.2 — 2026-11-22

- **TUI Banner Lifecycle & Polling Precision (`src/tui.tsx`):**
  - Preserved local TTL expiration and click-to-dismiss state across 500ms `guardian.interventions.current` RPC polling so expired or dismissed banners are never resurrected or have their TTL reset.
- **V2 Mesh, Idle & Remediation Lifecycle Hardening (`src/index.ts`, `src/bridge.ts`, `src/engine.ts`):**
  - Prevented paired V2 idle events (`session.status: idle` + `session.idle`) from clearing active remediation leases or mesh interventions, keeping `active_remediation` leases active across the remediation turn and releasing them on pass, new human prompt, failure, or teardown.
  - Ensured `remediationStatus: "verified"` followed by a new post-warning on the same turn still clears cleanly on the next human prompt.
  - Kept `question_presented` handoffs waiting for a real user reply without falling through to re-block, consumed the handoff on user reply, and ignored trusted mesh messages during `question_presented`.
  - Filtered lazy skill tags and trusted mesh messages out of task contract extraction and destructive command authorization.
  - Cleared preflight-blocked interventions on allowed follow-up tools or RPC clear, preserved `[TASK OUTCOME]` in subagent `execute.after`, and avoided caching unknown agent capabilities.
- **V2 Hooks, Shell Creation & Code Mode Visibility (`src/index.ts`):**
  - Updated `shell.hook("create.before")` to resolve `env.OPENCODE_SESSION_ID` and prevent scope bypass via `cwd: "/tmp"`.
  - Ignored descendant-owned background jobs in `experimental.idle`, detected `v2.3.1` timed-out-to-background shells in `hasUnfinishedBackgroundTool`, preserved `callID`, `output`, `error`, and non-zero `exitCode` in Code Mode `execute` nested `toolCalls`, and preferred `meta.command` over `description` for synthetic shell normalization.
- **Preflight, Sanitizer & Rule Precision:**
  - Fixed `splitShellStages` so `2>&1` redirections are not split, and blocked `git 2>&1 reset --hard`, PowerShell `-ec`, and multi-stage `true && printenv` in `evaluatePreflight`.
  - Allowed deletion-only patches and respected per-file markdown exemptions in `apply_patch` preflight; prevented Rust lifetimes from masking stubs or truncation.
  - Handled circular references, preserved `Error` subclasses and `Date` instances, protected valid mesh tokens, and redacted forged mesh tokens in JSON strings in `sanitizeObject` / `sanitizeMessages`.
  - Fixed edit-resolution false positives (`unresolved generic failure`), checked every stage of multi-stage destructive command authorization, avoided `'no changes to public API'` false positives under research-only constraints, reported all multi-file secrets, added Go `t.SkipNow()` detection and file-scoped deletion authorization in `testing/no-cheat`, checked subsequent matches in `no-evasion`, and resolved default severity for option-only rule overrides in `guardianCommandReport("rules")`.
- **Verification:**
  - Added 12 deep-debug regression tests in `tests/v0162-deep-debug.test.mjs` and 4 mesh audit tests in `tests/mesh-audit-fixes.test.mjs` (**806 / 806** tests passing, **18 / 18** sandbox scenarios, **10 / 10** live OpenCode `v2.3.2` + Bun `1.4.4` acceptance checks, Oxlint 0 warnings / 0 errors across 113 files).

## 0.16.1 — 2026-11-22

- **TUI Conversation Intervention Banner (`session.composer.top`) Lifecycle & Dismissal Fix:**
  - **TTL Auto-Expiry (`payload.duration`):** Server-side `interventionSnapshots` (`src/index.ts`) and TUI-side `storeIntervention` (`src/tui.tsx`) now automatically expire and clear intervention banners after `payload.duration` (`4000ms` for warnings, `5000ms` for errors/blocks, configurable in tests via `OPENCODE_GUARDIAN_INTERVENTION_TTL_MS`). The 500ms TUI RPC polling loop (`guardian.interventions.current`) checks `Date.now() >= entry.expiresAt` so expired banners are never resurrected.
  - **Immediate Clear on New User Prompt:** Submitting a new human prompt (`session.hook("prompt")` → `noteHumanPrompt(sessionID)`) immediately clears any previous turn's lingering intervention banner (`base.clear?.(sessionID)`) without waiting for `/guardian reset` or clean-turn idle completion.
  - **Click-to-Dismiss (`onMouseDown`):** Added `onDismiss` / `onMouseDown` support to `<GuardianConversationIntervention>` in `src/tui.tsx` so clicking the bottom conversation banner immediately clears both local TUI state and the server snapshot via `guardian.interventions.clear` RPC.
- **Local vs. Global Project Scope Precedence (`isDirectoryInGuardianScope`):**
  - Evaluated `isProjectLocalPluginInstall(startupDirectory)` before `hasGlobalGuardianInstall()` so a project-local Guardian instance never supervises foreign projects even on a host machine that also has a global `~/.config/opencode` configuration.
- **Verification:**
  - Added TDD regression tests in `tests/issue3-intervention-clear.test.mjs` and isolated `OPENCODE_CONFIG_DIR` in `tests/project-scope-and-state-isolation.test.mjs` (**791 / 791** tests passing, **18 / 18** sandbox scenarios, **10 / 10** live OpenCode `v2.3.2` + Bun `1.4.4` acceptance checks, Oxlint 0 warnings / 0 errors across 112 files).

## 0.16.0 — 2026-11-20

- **Universal OpenCode V2 Plugin Mesh Bridge (`src/bridge.ts` v2.2.0):**
  - Added zero-dependency N-way interoperability across `opencode-guardian`, `opencode-hi`, `opencode-smart-questions`, and sibling OpenCode V2 plugins via `Symbol.for("opencode.mesh.v2")` and the shared `opencode-mesh.state` RPC contract (`registerMeshStateRpc`).
  - **Cryptographic Provenance & Sanitizer Protection:** Stamped and verified session-scoped provenance tokens (`stampMeshMetadata`, `verifyMeshMetadata`, `isTrustedMeshMessage`) with legacy `opencode-guardian-provenance` fallback; exempted `metadata["opencode-mesh"].token` from key-name redaction in `sanitizeObject` while preserving secret-pattern scanning.
  - **Coordinated Session Leases & Deterministic Interventions:** Wired `acquireSessionLease` / `getBlockingSessionLease` (`user_interaction`, `active_remediation`, `orchestration_dispatch`) and `recordMeshIntervention` / `clearMeshIntervention` across idle inspection and `finalizeSubagentHandoff` so sibling orchestrators never retry or model-switch deterministic policy blocks or time out subagents during active Guardian remediation.
  - **Subagent Role Resolution & N-Way Handoffs:** Consulted `resolveMeshAgentProfile` in `handleSessionIdle` and `finalizeSubagentHandoff` to honor orchestrator-provided write/read-only capabilities; synchronized active handoffs with `setActiveMeshHandoff` / `clearActiveMeshHandoff` and accepted known mesh sources (`guardian`, `opencode-guardian`, `opencode-hi`, `opencode-smart-questions`, `opencode-trim`, `opencode-lazy-skill-engine`) in `parseOpenCodeHandoff`.
  - **Trusted Mesh Prompt & Turn Filtering:** Updated the V2 `prompt` hook, `normalizeV2Messages`, and `GuardEngine` (`isSyntheticUserMessage` and `question_presented` reply checks) to treat trusted non-delegation mesh messages (`remediation`, `visible`, `handoff`, `wake`, `skill-injection`) as synthetic rather than new human turns.
  - **Session & Lease Hygiene:** Released `remoteInteractionLeases` on `forgetMeshSession(sessionID)`, called `forgetGuardianProvenance(oldest)` on 512-session LRU eviction in `v2GuardianMetadata`, and preserved `"running"` status for synthetic `shell` messages with `metadata.state === "running"`.
- **External Per-Project State Directory & Local-vs-Global Scope Isolation:**
  - **Zero `.opencode/` Repository Pollution:** Updated `guardianStateDirectory(directory)` to store per-project audit logs under `~/.local/state/opencode-guardian/projects/<projectHash>/guardian-events.jsonl` (or `$OPENCODE_GUARDIAN_STATE_DIR` when explicitly overridden, and `os.tmpdir()/opencode-guardian-tests-<pid>/projects/<projectHash>/` with automatic process-exit cleanup under `NODE_TEST_CONTEXT`). Guardian never writes `guardian-events.jsonl` inside `<project>/.opencode/`, preventing untracked git files and read-only `.opencode/` sandbox lockouts in `opencode-hi`.
  - **Local vs. Global Project Scope Isolation (`isDirectoryInGuardianScope`):** Scoped project-local Guardian installations (`.opencode/plugins/opencode-guardian`, `.opencode/node_modules/opencode-guardian`, or project-only config) strictly to their own workspace directory (and subdirectories) so a locally installed Guardian never intercepts streams, blocks tools, mutates model context, or writes logs for unrelated projects sharing the OpenCode background server. Global installations (`~/.config/opencode/opencode.json`, `~/.config/opencode/plugins/opencode-guardian`, or `~/.config/opencode/opencode-guardian.json`) automatically supervise all projects while honoring per-project overrides.
- **Documentation & Verification:**
  - Expanded `README.md` installation guide to cover Global, Project-Local, `.opencode/plugins` Wrapper/Symlink, Local Development (`file://`), and Remote CLI/TUI (`cli.json`) setups.
  - Added `tests/mesh-audit-fixes.test.mjs` and `tests/project-scope-and-state-isolation.test.mjs` (**789 / 789** tests passing, **18 / 18** sandbox scenarios, **10 / 10** live OpenCode `v2.3.2` + Bun `1.4.4` acceptance checks, Oxlint 0 warnings / 0 errors across 112 files).

## 0.15.2 — 2026-11-19

- **OpenCode V2.3.1–V2.3.2 Runtime Compatibility:**
  - **Background & Timed-Out `shell` Handling:** Treated `metadata.status === "running"`, exitless `shellID` returns, and `v2.3.1` `"Command moved to the background"` / timeout-to-background outputs as `"unknown"` rather than completed success or completed file mutations. Normalized `type: "synthetic"` (`metadata.source === "shell"`) completion notifications into assistant `shell` tool evidence, and normalized `type: "shell"` (`status: "running"`) messages as `"running"` instead of `"error"`.
  - **Code Mode (`execute`) Visibility:** Expanded `execute` `state.metadata.toolCalls` into inspectable tool parts during `normalizeV2Messages` (exposing nested `write`/`edit`/`patch`/`shell` calls to rules and evidence tracking) and treated `state.metadata.error === true` as `"failure"`.
  - **`experimental.idle` & Background Isolation:** Registered optional `ctx.session.hook("experimental.idle", ...)` to track active `"codemode" | "shell" | "subagent" | "image"` background jobs, added `hasUnfinishedBackgroundTool` guarding in `handleSessionIdle`, and expanded `IN_PROGRESS_REGEX` for background wait phrasing.
  - **Structured `read` Output & Directory Review Guard:** Added string `Tool.Result.content` and structured `{ type: "text" | "directory", ... }` `output` extraction in `stringifyV2ToolContent` / `extractV2OutputText`, and excluded `"Read directory ..."` and `"Read file ..., 0 lines"` outputs from `isSourceReviewEvidence`.
  - **Permission Merging (`Permission.merge`):** Updated `resolveV2AgentCapability` to merge `context.agent.list()` base permissions with `session.permissions` overrides instead of returning early on partial session permission entries.
- **Secret Redaction Precision:**
  - Refined `SENSITIVE_KEY_REGEX` (`PASS(?:WORD|WD|PHRASE)`) so test summary counters like `pass` are not treated as secret keys, and preserved `null`, `undefined`, `boolean`, `number`, and empty string values in `sanitizeObject`.
- **Verification:**
  - Added 8 regression tests in `tests/v232-compatibility-regressions.test.mjs` (**781 / 781** passing), **18 / 18** sandbox scenarios, and live **OpenCode `v2.3.2` + Bun `1.4.4`** acceptance checks.

## 0.15.1 — 2026-11-17

- **Security & V2 Context Hardening:**
  - Preserved `Message` and `Part` class prototypes in `sanitizeMessages` when `parts` arrays are present, and sanitized `reasoning` parts, top-level `tool` part fields, and message metadata fields.
  - Implemented `SanitizerOptions.safeValues` (and `GuardConfig.secrets.safeValues`) end-to-end across string, key-value, credential-pattern, Bearer, hash, runtime-secret, and object sanitization.
- **Multi-Project Isolation & V2 Hook Alignment:**
  - Updated `context.shell.hook("create.before")` to inspect `event.cwd` when `sessionID` and `location.directory` are absent.
  - Updated `guardian.interventions.clear` (`./rpc` & `src/index.ts`) to accept optional `directory` input / `rpcContext.location.directory` and asynchronously resolve uncached session directories before clearing interventions.
  - Wired runtime `Rpc.define` (`@opencode/plugin/rpc`) in `src/intervention-rpc.ts`.
  - Cleared `telemetryConfigRegistry` on early return when `enabled: false` in `setup()`.
  - Aligned `resolveTelemetrySettings` default `maxBytes` for unregistered directories to `DEFAULT_GUARDIAN_LOG_BYTES` (`512 KiB`) while retaining `GUARDIAN_MAX_LOG_BYTES` (`2 MiB`) as the rotation ceiling.
- **TUI & Command Reporting Fixes:**
  - Passed `context.options` into `guardianCommandReport` (`doctor`, `rules`, `config`) so `/guardian-doctor`, `/guardian-rules`, and `/guardian-config` reflect `opencode.json` plugin options.
  - Fixed `ownsInterventionScope` in `src/tui.tsx` so same-directory preflight toasts are delivered even before `context.data.session` syncs, and added safe fallback strings to `SidebarColors`.
- **Documentation & Regression Coverage:**
  - Added 8 dedicated regression tests in `tests/v0151-audit-regressions.test.mjs` (**773 / 773** passing).
  - Aligned `README.md` and `docs/task-contract-v2.md` timer descriptions (`setInterval` `.unref?.()` vs. one-shot coalesce/retry timers).

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
