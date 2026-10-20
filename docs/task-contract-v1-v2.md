# Task Contract and OpenCode V1/V2 Adapter Architecture

Documentation for OpenCode Guardian **v0.12.0**.

Guardian implements a robust dual-mode architecture that connects to both **OpenCode v1** (`@opencode-ai/plugin`) and **OpenCode v2** (`@opencode/plugin`) runtime environments using standard, non-invasive plugin hooks.

---

## Host Hook Mapping

| Capability | OpenCode v1 (`@opencode-ai/plugin`) | OpenCode v2 (`@opencode/plugin`) |
| :--- | :--- | :--- |
| **Capture User Prompt** | `chat.message` hook | `ctx.session.hook("prompt", ...)` |
| **Inject Task Guidance** | `experimental.chat.system.transform` | `ctx.session.hook("context", ...)` |
| **Inspect Completed Turn** | Native idle event, or bounded session.status() and completed-message fallback | ctx.event.subscribe() and session.context() |
| **Dispatch Remediation** | `client.session.promptAsync(...)` | `ctx.session.synthetic({ sessionID, text, ... })` |
| **Lifecycle Events** | Native event callback when delivered; otherwise prompt-scoped status probing | ctx.event.subscribe({ signal }) async iterable |
| **Resolve Project Directory** | Plugin load directory argument | `ctx.session.get().location.directory` / `ctx.location.directory` |
| **Plugin Teardown** | V1 dispose() cancels outstanding probes and per-session idle work | AbortController signal and disposer handles |
| **Pre-Execution Shell Check** | `tool.execute.before` | `ctx.tool.hook("execute.before")` |
| **Whole-File Edit Observations** | Existing `tool.execute.before` / `tool.execute.after` | Optional `execute.before` / `execute.after` hooks; no old-content reconstruction without before evidence |
| **Foreground Subagent Finalization** | `task` execute-before/after coordination + `client.session.prompt(...)` | `subagent` execute-before/after coordination + `ctx.session.synthetic(...)` + `ctx.session.wait(...)` |
| **TUI Sidebar Extension** | `tui(api)` → `api.slots.register({ sidebar_content })` | `setup(ctx)` → `ctx.ui.slot({ append: "sidebar.content" })` |
| **TUI Commands / Slash** | `api.command.register` (when available) and `/guardian-status` | Global `ctx.keymap.layer` and `/guardian status` dispatcher |

---

## Task Contract Lifecycle

In v0.11.2, a new V1 human prompt cancels prior idle inspection and clears previous task guidance before extracting its text contract. Attachment-only prompts also end the prior task. Native `session.deleted` uses `properties.info.id`; cancelled capability queries cannot restore that session's cache. These paths have dedicated [debugging regressions](../tests/debug-regressions.test.mjs).

1. **Extraction on Human Turn:**
   - Filters out synthetic prompts and previous remediation cycles.
   - Identifies actionable requests, repeated review loops, source verification obligations, and individual verification commands (`test`, `build`, `typecheck`, `lint`, `audit`).
2. **Context Guidance:**
   - Injects structured guidance before the agent calls the model, preventing it from prioritizing earlier deferrals or hallucinating completion.
3. **Evidence Collection after `session.idle`:**
   - Normalizes recorded tool invocations through `collectTurnEvidence` into shared evidence records.
   - Supported complete Node/pytest/Jest/Vitest summaries add reconciled counts and outcome reasons. Unknown formats do not invent counts; host failures cannot become success because output prints a passing summary.
   - Validates chronological order: verifications run *before* the latest file edit are marked stale.
   - Substantive source inspections (file reads, line-bearing search/diff matches) are distinguished from superficial filename listings. Note that observable inspection of modified files confirms post-change re-inspection but cannot prove exhaustive whole-repository coverage (`reviewProvesFullCoverage: false`).
4. **Completion Evaluation:**
   - If an explicit iterative review task terminates without observing the required post-change verification, an automated remediation is triggered.
   - A required test run cannot be satisfied by a recognized zero-test, skipped-only or conflicting summary.
   - Continues up to `iterationBudget` (default `3`, max `5`), requiring observable progress on each turn.
5. **Circuit Breaking:**
   - Detects explicit blockers (unmet dependencies, missing credentials, system errors) and halts automatic retry loops to present a transparent report to the user.
   - Explicit user cancellation is distinguished from repeated execution failures. Pytest exit 2 alone is not cancellation evidence because collection errors also use it.
6. **Foreground Subagent Handoff Finalization:**
   - A synchronous V1 `task` or V2 `subagent` call is tracked from execute-before to execute-after.
   - If the child session has blocking Guardian findings, the parent-facing tool result is held while Guardian sends bounded remediation to the child and waits for that turn to finish.
   - The child is re-inspected before release. When remediation produces a revised final report, that report replaces the stale first-pass child output returned to the parent.
   - Background subagents do not enter this blocking handoff path; their existing idle-remediation behavior remains independent.

---

## v0.12.0 Evidence and Constraint Boundaries

Supported whole-file writes can carry before/after hashes, sizes and declaration-name loss into idle inspection. Suspicious content loss remains advisory, and a missing before hook cannot establish old file content. Source truncation placeholders can be rejected by strict preflight. See [edit observation limits](discipline-coverage.md#edit-observations-and-safety) for project confinement and memory bounds.

Research-only enforcement recognizes narrow English/Turkish phrases and checks observed writes, installs and pushes after the turn. It does not cover every language supported by task-contract extraction and cannot undo a completed mutation. File-specific baseline claims need matching comparison targets; quoted examples cannot grant destructive-operation permission.

---

## Error Handling & Resiliency

- **Graceful Fallbacks:** Missing optional hooks in transition environments fail open without breaking the core inspection pipeline.
- **Fail-Fast Security:** When strict preflight (`preflight.enabled: true`) is explicitly configured, setup requires valid tool hook registration and will fail visibly if the host cannot provide pre-execution guarantees.
- **Configuration Integrity:** Explicit configuration files (`opencode-guardian.json`, `.opencode/opencode-guardian.json`) must be valid JSON objects. Corrupt or malformed files throw a visible `GuardianConfigError` rather than silently degrading to insecure defaults.


## V2 Instance and Session Scope

V2 `ctx.location.directory` identifies the plugin instance; it is not guaranteed to be the working directory of every session. Guardian uses `ctx.session.get({ sessionID })` when available to route post-turn inspection, engine configuration and local telemetry to the resolved session directory. Tool-before checks use the already-known session directory, falling back to the instance directory if it is not yet known. Hook registration and fail-fast strict-preflight availability checks happen at instance setup; another project's configuration cannot supply a missing host hook. Use independent plugin instances for projects requiring different strict policies.

When an event subscription unexpectedly ends or fails, Guardian records an inspection error and makes up to three bounded stream attempts. Teardown aborts pending reconnects. Failure to restore the stream is logged visibly; this is not a substitute for monitoring host health.


## V1 1.x Idle-Event Compatibility

Some V1 builds (reported with 1.18.34) discard session.idle in the
location-filtered plugin event bus. Guardian prefers a native idle event when
delivered. For each newly prompted session, an optional compatibility watcher
uses the V1 SDK session.status() and session.messages() APIs; it does not scan
unrelated sessions or treat tool completion as turn completion.

The session must be idle (or absent from the SDK active-status map), the
latest assistant message must have time.completed, and the same completed
message must remain stable across two polls. The default interval is 750 ms,
bounded to 2,400 idle checks (approximately 30 minutes); active busy/retry states use a separate orphan-watcher safety limit.

A native idle event, session deletion, or V1 dispose() cancels the watcher.
Repeated SDK failures and expiration produce redacted inspection-error audit events rather than terminal stack traces. A V1 remediation is recorded only after the SDK confirms delivery; rejected responses do not exhaust the retry budget. When
session.status() is unavailable, native idle events remain the only trigger.
Actual host behavior must be verified on each targeted V1 release. Post-turn
findings cannot undo already-executed commands.

## Strict Command Resolution and Example Credentials

Literal backtick substitutions that construct a destructive executable name
are classified before execution. Unknown executable names generated through
dynamic substitution are denied in strict preflight. Passive documentation
examples and echo output remain permitted. Standard MCP shell-tool IDs (such as `mcp__provider__shell_exec`), scoped Git operations, and common literal `mkfs`/fork-bomb signatures are also recognized. The shell-pattern detector is not
a full shell interpreter.

All example and template files remain subject to secret scanning. A narrowly
defined local database example password is tolerated only in an example file
and only on localhost or a reserved example host. Real-looking API tokens,
strong passwords, and remote credentials are never exempted by filename.

## v0.6.5 Guardian Command and Handoff Lifecycle

Both adapters share SDK-independent, redacted reporting in `src/commands.ts`. V1 registers palette and slash actions via `api.command.register` when supported and ties disposal to `api.lifecycle.onDispose`. V2 registers a global keymap layer during TUI setup, separate from the additive sidebar slot.

`/guardian-reset` requires confirmation and appends a `statistics-reset` event. Counters restart while security history remains subject to normal bounded rotation; protection and configuration are unchanged. V2 resolves the active project when invoking a command. Unit tests exercise registrations, handoff races, failure paths and cleanup. The historical dual-host TUI acceptance baseline for released v0.6.0 remains documented in [`verification-report.md`](verification-report.md); v0.6.5 automated verification covers the new handoff barrier independently of that historical baseline.
