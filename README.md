# opencode-guardian 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version: 0.5.0](https://img.shields.io/badge/version-0.5.0-blue.svg)](https://www.npmjs.com/package/opencode-guardian)
[![OpenCode: v1 & v2](https://img.shields.io/badge/OpenCode-v1%20%7C%20v2%20Dual--Mode-emerald.svg)](https://opencode.ai)
[![TypeScript: 5.x](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![CI](https://github.com/huseyincig/opencode-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/huseyincig/opencode-guardian/actions/workflows/ci.yml)

A high-performance, deterministic quality, safety, and verification plugin for **OpenCode** AI coding agents.

OpenCode Guardian continuously supervises agent turns: guiding model execution before calls, correlating tool results at session idle, intercepting destructive shell actions, and enforcing that agents verify their work with genuine post-change evidence before declaring tasks complete.

---

## Key Highlights

- **Dual-Mode Architecture:** Seamlessly supports both **OpenCode v1** (`@opencode-ai/plugin`) and **OpenCode v2** (`@opencode/plugin`) with unified runtime adapters.
- **Compact TUI Sidebar:** Modern 2-column key-value widget matching the clean aesthetic of CortexKit and OMO-Slim. Expands with a single click.
- **In-App Update Indicator:** Automatically notifies you directly in the TUI header with a green `(↑)` indicator when a newer version is published to npm.
- **Project-Scoped Telemetry:** Stores event metrics locally inside `<project>/.opencode/guardian-events.jsonl` with secure `0600` POSIX permissions, keeping each project's statistics independent across sessions.
- **Evidence-Based Task Contracts:** Analyzes human requests across 13 languages to extract required verifications (tests, builds, source reviews) and prevents premature task exits without proof.
- **14 Deterministic Rules:** Blocks shortcuts, empty stubs, unverified claims, masked errors, test weakening, leaked secrets, undeclared dependencies, and repetitive execution loops.
- **Zero Configuration:** Works instantly out of the box with production-tested defaults. Fully configurable via `opencode-guardian.json`.
- **Server Runtime:** Precompiled JavaScript (`dist/`) has no mandatory third-party server dependencies. The optional TUI uses the host's OpenTUI/Solid runtime (declared as optional peers).

---

## Installation

Add `opencode-guardian` to your OpenCode configuration (`opencode.json` in your project or `~/.config/opencode/opencode.json`):

### OpenCode v1 (1.x)

Use the v1 `plugin` key in your project's `opencode.json` or `~/.config/opencode/opencode.json`:

```json
{
  "plugin": ["opencode-guardian@latest"]
}
```

For local development with v1, use `"plugin": ["file:///path/to/opencode-guardian"]`.

### OpenCode v2 (2.x beta)

Use the v2 **`plugins`** key in `opencode.json` or `opencode.jsonc`:

```json
{
  "plugins": ["opencode-guardian@latest"]
}
```

For local development with v2, use `"plugins": ["file:///path/to/opencode-guardian"]`. The package exposes separate server and TUI entrypoints; the host must load the corresponding runtime.

Refer to the [v1 plugin documentation](https://opencode.ai/docs/plugins/) and [v2 plugin documentation](https://opencode.ai/v2/docs/build/plugins/) for version-specific loading behavior.

---

## TUI Sidebar Interface

OpenCode Guardian includes a dedicated TUI extension that mounts into OpenCode's sidebar. It displays live status, intervention counters, and update notices.

### Collapsed View (Default)

```text
▶ Guardian                 v0.5.0 (↑)
Status                       ● Active
Interventions                 0w · 0r
```

- **Header:** Clickable header displaying the Guardian brand, current version, and an optional green `(↑)` update badge when a newer npm release is detected.
- **Status:** Real-time health (`● Active`, `● 1 warn`, or `● 1 blocked`).
- **Interventions:** Compact summary of warnings (`w`) and automatic remediations (`r`).

### Expanded View (Click to Toggle)

```text
▼ Guardian                 v0.5.0 (↑)
Preflight                  ○ disabled
Inspected                           0
Blocked                             0
Warnings                            0
Remediations                        0
Update                         v0.5.1
```

- **Preflight:** Current shell protection mode (`○ disabled` or `● active`).
- **Inspected / Blocked:** Real-time count of commands evaluated and prevented.
- **Warnings / Remediations:** Detailed intervention statistics for the active project.
- **Update:** Displays the newest available version from the npm registry.

---

## The 14 Guardrail Rules

OpenCode Guardian evaluates assistant turns against 14 deterministic rules. Rules can be configured as `error`, `warn`, or `off`; remediation is bounded and post-turn findings cannot undo an already-executed command:

| Category | Rule ID | Default | What It Enforces |
| :--- | :--- | :---: | :--- |
| **Discipline** | `discipline/no-evasion` | `error` | Blocks unsupported dismissals such as claiming a test failure is "pre-existing" or "out of scope" unless verified by baseline checks. |
| **Discipline** | `discipline/no-apology` | `error` | Blocks sycophantic, defensive, or repetitive apology language across multiple languages. |
| **Quality** | `quality/no-shortcuts` | `error` | Blocks concrete deferred-work phrases (`TODO`, `FIXME`, `HACK`, "will do later"). Ambiguous hedging phrases are flagged as advisory warnings. |
| **Integrity** | `integrity/no-stubs` | `error` | Blocks `NotImplementedError`, empty function stubs, Rust `todo!()`/`unimplemented!()`, and placeholder returns. |
| **Integrity** | `integrity/no-unverified-claims` | `error` | Correlates statements like "tests pass" or "build succeeded" against recorded tool exit codes. Direct contradictions block. |
| **Integrity** | `integrity/no-silent-failure` | `error` | Blocks test, build, lint, typecheck, or audit commands masked with `\|\| true`, `exit 0`, or suppressed exit codes. |
| **Safety** | `safety/no-truncation` | `error` | Blocks lazy edit placeholders (e.g. `// ... rest of code unchanged ...`) that can accidentally truncate production code. |
| **Safety** | `safety/destructive-operations` | `warn` | Inspects hard resets, force pushes, recursive deletion (`rm -rf`), database drops, and unpublish actions. Plain `rm` requires explicit scoped user consent. |
| **Testing** | `testing/no-cheat` | `error` | Blocks malicious test tampering: targeted `describe.skip`, `it.skip`, `test.skip`, `fit`, or assertion stripping in test files. |
| **Security** | `security/no-secrets` | `error` | Blocks hardcoded API keys (OpenAI, Anthropic, Google, AWS, GitHub, Slack, Stripe, JWTs, private keys, database URLs with passwords). |
| **Manifest** | `manifest/no-ghost-deps` | `error` | Blocks undeclared third-party imports not found in `package.json`, `pyproject.toml`, `requirements.txt`, `go.mod`, or `Cargo.toml`. Local modules and stdlib are recognized. |
| **Runtime** | `runtime/circuit-breaker` | `error` | Blocks repetitive failing commands hitting identical errors 3 times consecutively without progress, breaking runaway agent loops. |
| **Task** | `task/instruction-fidelity` | `error` | Prevents the agent from refusing an explicit task solely because the user previously paused or deferred it in an earlier turn. |
| **Task** | `task/completion-gate` | `error` | Ensures requested verifications (fresh test execution, post-change source inspection) are observed before the agent declares completion. |

---

## Configuration (`opencode-guardian.json`)

Guardian works out of the box with zero configuration. You can customize rules and thresholds by placing `opencode-guardian.json` in your project root, `.opencode/`, or `~/.config/opencode/`:

```json
{
  "enabled": true,
  "remediationBudget": 1,
  "iterationBudget": 3,
  "updateNotice": {
    "enabled": true
  },
  "preflight": {
    "enabled": false
  },
  "rules": {
    "discipline/no-evasion": "error",
    "discipline/no-apology": "error",
    "quality/no-shortcuts": {
      "severity": "error",
      "customPhrases": ["not my job", "out of scope for me"],
      "exceptions": ["tempdir", "temporaryfile"]
    },
    "integrity/no-stubs": "error",
    "integrity/no-unverified-claims": "error",
    "integrity/no-silent-failure": "error",
    "safety/no-truncation": "error",
    "safety/destructive-operations": "warn",
    "testing/no-cheat": "error",
    "security/no-secrets": "error",
    "manifest/no-ghost-deps": "error",
    "runtime/circuit-breaker": "error",
    "task/instruction-fidelity": "error",
    "task/completion-gate": "error"
  }
}
```

### Severity Options:
- `"error"`: High-confidence violation triggers an automatic remediation prompt (bounded by `remediationBudget`).
- `"warn"`: Recorded in telemetry and displayed in TUI, but does not interrupt agent flow.
- `"off"`: Completely disables the rule.

---

## Task Contracts & Multilingual Support

When a user submits an instruction, Guardian extracts a deterministic task contract before model execution. Supported intent patterns include:
- **Languages Supported:** English, Turkish, Spanish, Portuguese, French, German, Russian, Arabic, Hindi, Chinese, Japanese, Korean, and Indonesian.
- **Verification Modes:** Requires observable evidence (e.g. running tests, building, typechecking, or performing a fresh post-change file inspection).
- **Explicit Header Directive (Optional):** For deterministic contract specification regardless of natural language phrasing:

```text
@guardian-task {"mode":"iterative-review","review":"source","verify":["test"]}
Please refactor the authentication service and verify all tests pass.
```

---

## Preflight Shell Protection (Opt-In)

By default, Guardian analyzes operations after tool execution. If you want **pre-execution blocking** that intercepts dangerous shell commands *before* they are sent to the terminal, enable preflight:

```json
{
  "preflight": {
    "enabled": true
  }
}
```

- Intercepts destructive commands (`rm -rf /`, `git reset --hard`, `DROP DATABASE`, `mkfs`, fork bombs, encoded base64 pipelines).
- Operates at the host hook level (`tool.execute.before` in v1, `ctx.tool.hook("execute.before")` in v2). Only recognized shell tools are inspected; custom tools and runtime-generated payloads also require host permissions and sandboxing.

For an MCP/custom tool that really executes shell commands but does not have a recognized tool name, explicitly opt it in:

```json
{
  "preflight": {
    "enabled": true,
    "shellTools": ["mcp.remote.exec_task"]
  }
}
```

The listed tool must expose one unambiguous string `command`, `cmd`, or `script` argument. Unknown/malformed input is rejected **for recognized or explicitly listed shell tools**. Guardian cannot inspect arbitrary custom tool internals, script files loaded at execution, or dynamically decoded commands; retain OpenCode permissions and OS isolation.

**V1 idle compatibility:** For OpenCode V1 builds that drop session.idle,
Guardian probes only newly prompted sessions using the SDK status and
message endpoints. It requires a stable, completed assistant response;
native idle events and teardown cancel the probe. Repeated API failures
or a bounded timeout are logged. When the status API is unavailable,
native idle events remain the only trigger. The fallback introduces
approximately two 750 ms polls and cannot undo an already-executed command.

**Secret scanning:** Example files are still inspected. Obvious sample
passwords on localhost or reserved example database hosts have a narrow
allowance; real-looking API tokens and remote credentials are still blocked.

**V2 project scope:** `ctx.location.directory` is where a plugin instance loads, not necessarily the location of each session. Guardian resolves session directories for post-turn inspection and local event logs, while strict preflight registration and configuration are determined at plugin setup. For distinct per-project preflight policies, load a separate plugin instance for each project.


---

## Telemetry & CLI Status

Guardian maintains a private, redacted log of local events:
- **Project Log:** `<project>/.opencode/guardian-events.jsonl` (mode `0600`).
- **Global Fallback:** `~/.local/state/opencode-guardian/guardian-events.jsonl`.
- **Privacy:** Contains only rule codes and SHA-256 session fingerprints. **Never** stores commands, file contents, secrets, or prompts.

### Command Line Interface

Check Guardian's status at any time from your terminal:

```bash
# Check status for the current project
opencode-guardian-status

# Or specify a target directory
opencode-guardian-status /path/to/project
```

Example output:
```text
Guardian | preflight at last start: disabled
Shell inspected: 14 | blocked: 0
Post-turn warnings: 2 | remediations: 1 | errors: 0
Event log: /path/to/project/.opencode/guardian-events.jsonl
```

---

## Architecture & Turn Lifecycle

```mermaid
flowchart TD
    User([User Prompt]) --> PreHook[V1 chat.message / V2 prompt hook]
    PreHook --> Contract[Extract Task Contract & Guidance]
    Contract --> Agent[Agent Model Execution & Tool Calls]
    
    subgraph Preflight [Optional Preflight Interception]
        Agent -->|Shell Tool Request| PreflightCheck{Strict Preflight Enabled?}
        PreflightCheck -->|Yes & Risky| BlockPreflight[Block Before Execution]
        PreflightCheck -->|No or Safe| ExecTool[Execute Tool Command]
    end
    
    ExecTool --> IdleEvent[Session Idle Event]
    IdleEvent --> Collector[EvidenceCollector: Normalize Events, Diffs & Exit Codes]
    Collector --> Evaluator[Evaluate 14 Guardrail Rules]
    
    Evaluator --> Decision{Violations Detected?}
    Decision -->|No| Pass([Pass Turn Cleanly])
    Decision -->|Yes| Budget{Remediation Budget > 0?}
    Budget -->|Yes| Remediate[Inject Synthetic Remediation Prompt]
    Budget -->|Exhausted| Pass
    Remediate --> Agent
```

---

## 🔬 Scientific Foundation & Academic Research

OpenCode Guardian's architecture and security models are grounded in peer-reviewed computer science literature and industry security frameworks:

1. **"Guardians of the Agents" (Erik Meijer, Communications of the ACM, Dec 2025):**
   - **Theoretical Foundation:** In [*Guardians of the Agents*](https://doi.org/10.1145/3777544) (*Communications of the ACM*, DOI: [`10.1145/3777544`](https://doi.org/10.1145/3777544)), Erik Meijer formalized the paradigm of using independent, host-level supervisory software ("Guardians") that monitor and enforce behavioral invariants over autonomous AI agents before and after tool execution, without requiring prompt-level instructions or modifying model weights.
   - **Guardian Implementation:** OpenCode Guardian directly realizes this paradigm through its dual-mode engine, evaluating preflight invariants before execution and correlating multi-step evidence at `session.idle`.

2. **The GuardFall Vulnerability Research (Adversa AI, June 2026):**
   - **Vulnerability Context:** Discovered by Adversa AI in June 2026, the *GuardFall* research revealed systemic flaws across 10 out of 11 popular coding agents where string-matching blocklists failed to detect obfuscated shell commands (such as quote removal `r''m`, variable expansion `$IFS`, paired backtick substitution, and encoded Base64 pipelines).
   - **Guardian Defense:** OpenCode Guardian incorporates dedicated conservative shell-pattern analysis ([`src/shell-risk.ts`](src/shell-risk.ts)) and regression suites ([`tests/guardfall-regression.test.mjs`](tests/guardfall-regression.test.mjs)) to recognize documented GuardFall-style patterns during post-turn inspection and opt-in strict preflight. This is not a complete shell interpreter or a general permission boundary.

3. **OWASP Top 10 for Agentic Applications (2026):**
   - OpenCode Guardian is architected to address critical vulnerabilities defined in the OWASP Agentic Top 10 framework, including **ASI01** (Agent Goal Hijacking), **ASI02** (Tool Misuse), **ASI03** (Identity & Privilege Abuse), **ASI05** (Unexpected Code Execution), and **ASI08** (Cascading Failures).
   - Detailed mapping and capability boundaries are documented in [`docs/owasp-agentic-top10-2026.md`](docs/owasp-agentic-top10-2026.md).

---

## Verification & Testing

OpenCode Guardian is backed by a comprehensive automated test suite:

```bash
# Run unit and regression tests (the suite count is reported by the runner)
npm test

# Run TypeScript typechecks
npm run typecheck

# Run end-to-end scenario test suite (18 scenarios)
node sandbox/comprehensive-test.mjs

# Verify package contents
npm pack --dry-run
```

---

## License

MIT © [Hüseyin Hadi Çığ](https://github.com/huseyincig)
