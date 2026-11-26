# Task Contract and OpenCode V2 Adapter Architecture

Documentation for OpenCode Guardian **v0.18.6**.

Guardian implements a pure **OpenCode V2** (`@opencode/plugin >=2.3.0`) architecture across its server entry (`.`), terminal UI entry (`./tui`), and typed intervention RPC contract (`./rpc`) using standard, non-invasive V2 plugin hooks.

---

## Host Hook & Export Mapping

| Capability | OpenCode V2 (`@opencode/plugin >=2.3.0`) |
| :--- | :--- |
| **Server Entry (`.`)** | `setup(ctx)` returning `Promise<void \| (() => void \| Promise<void>)>` |
| **TUI Entry (`./tui`)** | `setup(ctx)` → `ctx.ui.slot({ append: "sidebar.content" })` & `ctx.ui.slot({ append: "session.composer.top" })` |
| **Typed RPC Contract (`./rpc`)** | `Rpc.define` (`opencode-guardian/rpc`, `dist/intervention-rpc.js`) — `guardian.interventions.get` & `guardian.interventions.clear` |
| **Capture User Prompt** | `ctx.session.hook("prompt", ...)` |
| **Inject Task Guidance** | `ctx.session.hook("context", ...)` (normalizes V2 `shell` and `agent-switched` context entries) |
| **Inspect Completed Turn** | `ctx.event.subscribe({ signal })` async iterable (`session.idle`) and `ctx.session.context(...)` |
| **Dispatch Remediation** | `ctx.session.synthetic({ sessionID, text, ... })` |
| **Stream Loop Detection** | `StreamLoopWatcher` (`ctx.stream.hook(...)`) — treats `{ interrupted: false }` as rejected without warning toast or stopped state |
| **Pre-Execution Tool & Shell Checks** | `ctx.tool.hook("execute.before")` + `ctx.shell?.hook("create.before")` (rolled back cleanly if a later hook fails) |
| **Whole-File Edit Observations** | `ctx.tool.hook("execute.before")` / `ctx.tool.hook("execute.after")` with `VerificationSnapshotStore` dual `editIntegrity` & `fingerprint` tracking |
| **Foreground Subagent Finalization** | `subagent` execute-before/after coordination + `ctx.session.synthetic(...)` + `ctx.session.wait(...)` |
| **Background Subagent Isolation** | `background === true` in `execute.after` skips foreground handoff wait and prevents starving sibling background subagents |
| **Forked & Moved Sessions** | `session.fork` / `session.forked` treated as independent root sessions; `session.moved` clears stale TUI intervention state |
| **Resolve Project Directory** | Top-level `location.directory` → `ctx.session.get().location.directory` → instance `ctx.location.directory` |
| **Plugin Teardown** | `AbortController` signal + LIFO disposer rollback on partial setup failure + `.unref?.()` on periodic cleanup intervals |
| **TUI Commands & Keymaps** | `ctx.command.register(...)` (7 `/guardian-*` palette/slash commands + `/guardian` dispatcher) and global `ctx.keymap.layer` |

---

## Task Contract Lifecycle

A new human prompt via `ctx.session.hook("prompt", ...)` cancels any in-flight `idleQueue` inspection and clears stale `TaskContract` guidance before extracting the new text contract. Attachment-only or empty prompts also end the prior task. Native `session.deleted` clears cached capabilities, contracts, and pending idle work; cancelled capability queries cannot revive a deleted session's cache. These paths are verified in [`tests/runtime-v2-lifecycle.test.mjs`](../tests/runtime-v2-lifecycle.test.mjs).

1. **Extraction on Human Turn:**
   - Filters out synthetic prompts and previous remediation cycles.
   - Identifies actionable requests, repeated review loops, source verification obligations, and individual verification commands (`test`, `build`, `typecheck`, `lint`, `audit`).
2. **Context Guidance:**
   - Injects structured guidance via `ctx.session.hook("context", ...)` before the model turn, preventing the agent from prioritizing earlier deferrals or hallucinating completion.
   - Normalizes V2 `shell` and `agent-switched` context entries alongside standard message parts.
3. **Evidence Collection after `session.idle`:**
   - Normalizes recorded tool invocations through `collectTurnEvidence` into shared evidence records, including V2 `Error` instances and `{ type, message }` tool error objects.
   - Supported complete Node/pytest/Jest/Vitest summaries add reconciled counts and outcome reasons. Unknown formats do not invent counts; host failures cannot become success because output prints a passing summary.
   - Validates chronological order: verifications run *before* the latest file edit are marked stale.
   - Substantive source inspections (file reads, line-bearing search/diff matches) are distinguished from superficial filename listings. Note that observable inspection of modified files confirms post-change re-inspection but cannot prove exhaustive whole-repository coverage (`reviewProvesFullCoverage: false`).
4. **Completion Evaluation:**
   - If an explicit iterative review task terminates without observing the required post-change verification, an automated remediation is triggered.
   - An `"in progress"` reply with a mutation does not falsely mark `task/completion-gate` as `"remediation-verified"`.
   - A required test run cannot be satisfied by a recognized zero-test, skipped-only or conflicting summary.
   - Continues up to `iterationBudget` (default `3`, max `5`), requiring observable progress on each turn.
5. **Circuit Breaking:**
   - Detects explicit blockers (unmet dependencies, missing credentials, system errors) and halts automatic retry loops to present a transparent report to the user.
   - Explicit user cancellation is distinguished from repeated execution failures. Pytest exit 2 alone is not cancellation evidence because collection errors also use it.
6. **Foreground & Background Subagent Coordination:**
   - Synchronous V2 `subagent` calls (`background !== true`) are tracked from `execute.before` to `execute.after`.
   - If the child session has blocking Guardian findings, the parent-facing tool result is held while Guardian sends bounded remediation to the child and waits for that turn to finish.
   - The child is re-inspected before release. When remediation produces a revised final report, that report replaces the stale first-pass child output returned to the parent.
   - Background subagents (`background === true`) do not enter the blocking handoff path and are isolated so they neither starve sibling background subagents nor block the parent turn.
   - Forked sessions (`session.fork` / `session.forked`) are treated as independent root sessions.

---

## Evidence, Standardized Shell Output, and Telemetry Boundaries

Evidence normalization in `src/evidence.ts` recognizes standardized `"Exit code: N"` outputs and tracks explicit signal kill or timeout errors (`SIGTERM`, `SIGKILL`, `SIGINT`) as well as V2 `Error` and `{ type, message }` error shapes. Read-only Git inspection tools (`diff`, `git_diff`, `log`, `git_log`, `show`, `git_show`) are recognized without triggering destructive warnings.

The Low-I/O Telemetry architecture (`src/telemetry.ts`) provides `telemetry.level` (`"violations" | "all" | "off"`, default: `"violations"`), filtering out high-frequency benign events (`preflight-allowed`, `post-inspected`) to eliminate 90–95% of disk I/O and prevent test and benchmark freezes. Verified state directory permissions are re-verified via `lstatSync` and cached in-memory, `telemetryConfigRegistry` is cleaned up on early setup errors, and event logs are strictly bounded to 512 KiB by default (configurable via `telemetry.maxBytes`). Supported whole-file writes carry before/after hashes, sizes, and declaration-name loss into idle inspection via `VerificationSnapshotStore`. See [edit observation limits](discipline-coverage.md#edit-observations-and-safety) for project confinement and memory bounds.

Research-only enforcement recognizes narrow English/Turkish phrases and checks observed writes, installs and pushes after the turn. It does not cover every language supported by task-contract extraction and cannot undo a completed mutation. File-specific baseline claims need matching comparison targets; quoted examples cannot grant destructive-operation permission.

---

## Error Handling & Resiliency

- **Graceful Fallbacks:** Missing optional hooks in transition environments fail open without breaking the core inspection pipeline. `resolveV2AgentCapability` safely handles array, `{ data }`, and null/throwing list responses.
- **Fail-Fast Security:** When strict preflight (`preflight.enabled: true`) is explicitly configured, setup requires valid tool/shell hook registration and rolls back any earlier hooks if a later registration fails.
- **Configuration Integrity:** Explicit configuration files (`opencode-guardian.json`, `.opencode/opencode-guardian.json`) must be valid JSON objects. Corrupt or malformed files throw a visible `GuardianConfigError` rather than silently degrading to insecure defaults.
- **Bounded Session State & Timers:** Per-session Maps/Sets and capability caches are bounded and evicted on `session.deleted` or teardown; periodic background cleanup/polling intervals call `.unref?.()`, while active one-shot coalesce and retry timers keep the event loop alive until completion or abort.

---

## V2 Instance, Session Scope, and RPC Surface

V2 `ctx.location.directory` identifies the plugin instance; it is not guaranteed to be the working directory of every session. Guardian resolves top-level `location.directory` first, then `ctx.session.get({ sessionID }).location.directory` when available, falling back to `event.cwd` (on `shell.hook("create.before")`) or the instance directory. Tool-before and `shell.hook("create.before")` checks use the known session/cwd directory or fall back to the instance directory. Hook registration and fail-fast strict-preflight availability checks happen at instance setup; another project's configuration cannot supply a missing host hook. Use independent plugin instances for projects requiring different strict policies.

When an event subscription unexpectedly ends or fails, Guardian records an inspection error and makes up to three bounded stream attempts. Teardown aborts pending reconnects. Failure to restore the stream is logged visibly; this is not a substitute for monitoring host health.

The typed `./rpc` export (`src/intervention-rpc.ts`) exposes `guardian.interventions.get` and `guardian.interventions.clear` using `Rpc.define` (`@opencode/plugin/rpc`):
- `sessionID` inputs enforce `maxLength: 256`.
- `guardian.interventions.clear` with `{}` is strictly scoped to the requested project `directory` / `location.directory` (falling back to the plugin instance's `directory` and resolving uncached session directories asynchronously), preventing cross-project intervention clearing.
- In `src/tui.tsx`, per-session generation/epoch tracking prevents in-flight 500ms RPC polls from resurrecting interventions cleared by `/guardian-reset`, clean turns, `session.moved`, or `session.deleted`.

---

## Strict Command Resolution and Example Credentials

Multi-stage shell commands are split via `splitShellStages` so preflight inspects every stage for destructive operations, hallucinated or typosquatted package installs, and lazy commit messages in both `tool.execute.before` and `shell.create.before`.

Literal backtick substitutions that construct a destructive executable name are classified before execution. Unknown executable names generated through dynamic substitution are denied in strict preflight. Passive documentation examples and echo output remain permitted. Standard MCP shell-tool IDs (such as `mcp__provider__shell_exec`), scoped Git operations, and common literal `mkfs`/fork-bomb signatures are also recognized. The shell-pattern detector is not a full shell interpreter.

All example and template files remain subject to secret scanning. A narrowly defined local database example password is tolerated only in an example file and only on localhost or a reserved example host. Real-looking API tokens, strong passwords, and remote credentials are never exempted by filename. `sanitizeObject` and `sanitizeMessages` preserve `Uint8Array` / `ArrayBuffer` buffers and non-plain object prototypes (`Message` class).

---

## Guardian TUI, Commands, and Handoff Lifecycle

`src/tui.tsx` targets pure OpenCode V2 (`setup(ctx)`) and exports an adaptive `dist/tui.js` entry that safely falls back to `./tui-standalone.js` in standalone Bun or Node runtimes without crashing on `opentui:runtime-module` resolution.

Both server and TUI share SDK-independent, redacted reporting in `src/commands.ts`. TUI registers 7 `/guardian-*` palette/slash commands plus the `/guardian` dispatcher and a global keymap layer alongside the additive `sidebar.content` and `session.composer.top` slots. Minimal TUI contexts without optional `data`/`command` APIs fail safe without throwing.

`/guardian-reset` requires confirmation and appends a `statistics-reset` event. Counters restart while security history remains subject to normal bounded rotation; protection and configuration are unchanged.
