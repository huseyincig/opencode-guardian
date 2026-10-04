# Task Contract and OpenCode V1/V2 Adapter Architecture

Documentation for OpenCode Guardian **v0.6.0**.

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
| **Plugin Teardown** | V1 dispose() cancels outstanding completion probes | AbortController signal and disposer handles |
| **Pre-Execution Shell Check** | `tool.execute.before` | `ctx.tool.hook("execute.before")` |
| **TUI Sidebar Extension** | `tui(api)` → `api.slots.register({ sidebar_content })` | `setup(ctx)` → `ctx.ui.slot({ append: "sidebar.content" })` |
| **TUI Commands / Slash** | `api.command.register` (when available) and `/guardian-status` | Global `ctx.keymap.layer` and `/guardian status` dispatcher |

---

## Task Contract Lifecycle

1. **Extraction on Human Turn:**
   - Filters out synthetic prompts and previous remediation cycles.
   - Identifies actionable requests, repeated review loops, source verification obligations, and individual verification commands (`test`, `build`, `typecheck`, `lint`, `audit`).
2. **Context Guidance:**
   - Injects structured guidance before the agent calls the model, preventing it from prioritizing earlier deferrals or hallucinating completion.
3. **Evidence Collection after `session.idle`:**
   - Gathers recorded tool invocations into a unified `EvidenceCollector` snapshot.
   - Validates chronological order: verifications run *before* the latest file edit are marked stale.
   - Substantive source inspections (file reads, line-bearing search/diff matches) are distinguished from superficial filename listings. Note that observable inspection of modified files confirms post-change re-inspection but cannot prove exhaustive whole-repository coverage (`reviewProvesFullCoverage: false`).
4. **Completion Evaluation:**
   - If an explicit iterative review task terminates without observing the required post-change verification, an automated remediation is triggered.
   - Continues up to `iterationBudget` (default `3`, max `5`), requiring observable progress on each turn.
5. **Circuit Breaking:**
   - Detects explicit blockers (unmet dependencies, missing credentials, system errors) and halts automatic retry loops to present a transparent report to the user.

---

## Error Handling & Resiliency

- **Graceful Fallbacks:** Missing optional hooks in transition environments fail open without breaking the core inspection pipeline.
- **Fail-Fast Security:** When strict preflight (`preflight.enabled: true`) is explicitly configured, setup requires valid tool hook registration and will fail visibly if the host cannot provide pre-execution guarantees.
- **Configuration Integrity:** Explicit configuration files (`opencode-guardian.json`, `.opencode/opencode-guardian.json`) must be valid JSON objects. Corrupt or malformed files throw a visible `GuardianConfigError` rather than silently degrading to insecure defaults.


## V2 Instance and Session Scope

V2 `ctx.location.directory` identifies the plugin instance; it is not guaranteed to be the working directory of every session. Guardian uses `ctx.session.get({ sessionID })` when available to route post-turn inspection and local telemetry to the session directory. The rule engine and strict preflight hook are configured at plugin setup from the instance directory; a session in a different project does not dynamically enable a new pre-execution hook. Use independent plugin instances for projects requiring different strict policies.

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

## v0.6.0 Guardian Command Lifecycle

Both adapters share SDK-independent, redacted reporting in `src/commands.ts`. V1 registers palette and slash actions via `api.command.register` when supported and ties disposal to `api.lifecycle.onDispose`. V2 registers a global keymap layer during TUI setup, separate from the additive sidebar slot.

`/guardian-reset` requires confirmation and appends a `statistics-reset` event. Counters restart while security history remains subject to normal bounded rotation; protection and configuration are unchanged. V2 resolves the active project when invoking a command. Unit tests exercise registrations and failure paths; real-host TUI acceptance is verified for both OpenCode V1 and OpenCode V2 host environments (documented in [`verification-report.md`](verification-report.md)).
