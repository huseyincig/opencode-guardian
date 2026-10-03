# Task Contract and OpenCode V1/V2 Adapter Architecture

Documentation for OpenCode Guardian **v0.5.0**.

Guardian implements a robust dual-mode architecture that connects to both **OpenCode v1** (`@opencode-ai/plugin`) and **OpenCode v2** (`@opencode/plugin`) runtime environments using standard, non-invasive plugin hooks.

---

## Host Hook Mapping

| Capability | OpenCode v1 (`@opencode-ai/plugin`) | OpenCode v2 (`@opencode/plugin`) |
| :--- | :--- | :--- |
| **Capture User Prompt** | `chat.message` hook | `ctx.session.hook("prompt", ...)` |
| **Inject Task Guidance** | `experimental.chat.system.transform` | `ctx.session.hook("context", ...)` |
| **Inspect Messages on Idle** | `client.session.messages(...)` | `ctx.session.context({ sessionID })` |
| **Dispatch Remediation** | `client.session.promptAsync(...)` | `ctx.session.synthetic({ sessionID, text, ... })` |
| **Lifecycle Events** | `event` callback (`session.idle`) | `ctx.event.subscribe({ signal })` async iterable |
| **Resolve Project Directory** | Plugin load directory argument | `ctx.session.get().location.directory` / `ctx.location.directory` |
| **Plugin Teardown** | Host engine unloads hooks | AbortController signal + disposer handles |
| **Pre-Execution Shell Check** | `tool.execute.before` | `ctx.tool.hook("execute.before")` |
| **TUI Sidebar Extension** | `tui(api)` → `api.slots.register({ sidebar_content })` | `setup(ctx)` → `ctx.ui.slot({ append: "sidebar.content" })` |

---

## Task Contract Lifecycle

1. **Extraction on Human Turn:**
   - Filters out synthetic prompts and previous remediation cycles.
   - Identifies actionable requests, repeated review loops, source verification obligations, and individual verification commands (`test`, `build`, `typecheck`, `lint`, `audit`).
2. **Context Guidance:**
   - Injects structured guidance before the agent calls the model, preventing it from prioritizing earlier deferrals or hallucinating completion.
3. **Evidence Collection at `session.idle`:**
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
