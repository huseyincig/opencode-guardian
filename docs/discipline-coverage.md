# Engine discipline coverage and evidence boundaries

Guardian v0.12.0 strengthens the shared engine. It keeps the existing fourteen rule IDs, host adapters and remediation budgets, and adds no runtime dependencies or installed skills.

## Evidence

`EvidenceRecord` now optionally carries `testSummary`, `outcomeReason` and observed `editIntegrity`. The original host exit code is preserved. Only assistant tool parts produce evidence; prose, user examples and system text do not.

Supported complete aggregate summaries: Node TAP/spec, pytest, Jest and Vitest. Counts are bounded and must reconcile. Known pytest warning/deselection fields are ignored rather than counted as executed tests. Unknown formats retain the host outcome without inventing counts. Missing exit codes, masked pipelines and ambiguous compound commands retain the existing conservative handling.

- Zero-test and skipped-only runs cannot satisfy required verification.
- Failed host execution cannot be promoted by a passing summary.
- A failing summary paired with exit zero is ambiguous, not successful verification.
- Host cancellation metadata or narrow explicit user-cancellation evidence is distinct from an execution failure. Pytest exit 2 alone is **not** proof of user cancellation; collection errors use it too.
- Explicit English passed-test count claims are compared with fresh observed totals; historical and uncertain statements are excluded.

The output parser supports selected observed formats, not all runner versions. Node itself recommends test stream events for programmatic consumers; Guardian does not silently replace users' runners or force a reporter. A green exit without recognized counts preserves legacy verification behavior, not a claim that every test was discovered.

## Rule coverage

| Rule | Improvement or preserved guarantee | Boundary |
| --- | --- | --- |
| `discipline/no-evasion` | File-specific baseline claims need matching comparison targets. | Generic baseline compatibility remains; reading source alone is not proof that a failing test existed previously. |
| `discipline/no-apology` | Explicit project-configured exceptions apply only to their matching span. | No universal semantic sycophancy detector; useful uncertainty and factual correction remain valid. |
| `quality/no-shortcuts` | Existing scoped placeholder authorization and phrase exceptions have legitimate-negative coverage. | No new broad style bans or inferred documentation requirements. |
| `integrity/no-stubs` | Quoted examples are masked; actual empty named JS/TS implementations are detected. | Lexical analysis, not a complete AST; intentional callbacks/constructors, fixture paths and declarations have exemptions. Complex return types remain conservative. |
| `integrity/no-unverified-claims` | Fresh observed passed counts support or contradict explicit current count claims. | Unsupported output formats and unavailable facts do not manufacture verification. |
| `integrity/no-silent-failure` | Literal examples are excluded; constant error fallbacks are advisory; hidden verification substitutions are inspected. | Static shell subset; an intentional recovery is not automatically a failure. |
| `safety/no-truncation` | Before/after whole-file observations detect suspicious definition loss. Strict file preflight rejects source placeholders. | Content-loss findings are advisory; missing observations are not reconstructed from current disk. No rollback. |
| `safety/destructive-operations` | Hook bypasses require explicit authorization; literal repositories, push refspecs and reset targets remain scoped. | Static shell subset; existing strict preflight is still opt-in and host permissions remain necessary. |
| `testing/no-cheat` | Quoted examples are inert; conditional assertions are advisory. | Assertion quality cannot be proven from syntax alone; legitimate test edits keep existing scoped authorization. |
| `security/no-secrets` | File-write and output checks share known credential formats, including GitHub variants and JWTs. | No entropy-only hard block, external credential verification or new network requests. |
| `manifest/no-ghost-deps` | Runtime dev-only imports are advisory; strict production mode is available. | File roles use conventions, not complete bundler/reachability analysis. Type-only imports and test/build tooling retain exceptions. |
| `runtime/circuit-breaker` | Explicit user cancellations do not count as repeated execution faults. Live text/reasoning checks honor `error`, `warn`, and `off`, in string or object form. | Repetition detection is heuristic: intentional repetition can trigger it. The bounded window supports periods up to 512 UTF-16 code units and excludes short quoted numeric/hex fixtures. A stop request is not proof of interruption or token savings. Rejected stop calls retry on later growth at most three times; an ambiguous timeout suppresses overlapping retries. V2 cannot cancel an already issued host call. |
| `task/instruction-fidelity` | Narrow English/Turkish research-only constraints are checked against observed mutations, installs and pushes. | Post-turn detection cannot undo a completed write. Other phrasings/languages are not claimed as universally understood. |
| `task/completion-gate` | Required zero-test/skipped-only/conflicting runs do not count as passing. Subagents reporting in-progress turns or intermediate updates without claiming completion are protected from false-positive completion gate blocking. | No automatic assertion that source inspection covered an entire repository. |

## Edit observations and safety

Existing V1/V2 before/after hooks capture hashes, sizes and declaration-name sets for recognized whole-file `content` writes. Files must resolve inside the project, be regular files and not exceed 2 MiB. A file with more than 1,024 distinct declaration names is outside this bounded observation. Pending before observations are capped at 32 per session and completed records at 512; session cleanup clears them. Raw source content is not retained in audit events.

An advisory is produced when an observed successful replacement removes at least two declaration names and reduces byte length below half. These are explicit heuristics for review, **not proof of unintended deletion**. Targeted edits, missing before hooks, failed writes and unsupported mutation shapes do not invent a previous file. Empty successful replacements still count as mutations and invalidate prior verification.

Code lexical views are limited to 2 MiB and 32 nested template expressions. Supported JS/TS paths retain private fields and executable template interpolations. Other syntax and general shell interpretation are not guaranteed. An intentionally quoted natural-language deletion target may conservatively require clearer authorization; quoted examples never grant permission.

## Configuration

Default production-dependency findings are advisory, including when the rule severity is `error`, because a build step may bundle the import. Opt in to strict production dependency checks with:

```json
{
  "rules": {
    "manifest/no-ghost-deps": {
      "severity": "error",
      "productionOnly": true
    }
  }
}
```

`blockEmptyHandlers` continues to control empty-handler blocking. Constant fallback and conditional-assertion findings stay advisory. Prose exceptions are literal phrases supplied through trusted project configuration, not authorization granted by comments in inspected code. No defaults enable a new external scanner or network service.

## Evaluation

`tests/discipline-coverage.test.mjs` exercises one violation and one legitimate-negative case for each of the fourteen rules: 28 labeled cases, plus a corpus-completeness check. Focused suites add format, cancellation, symlink, empty-write, authorization and lexical adversarial cases. This small synthetic corpus is a regression baseline, not a real-world accuracy estimate. It does not justify equal precision/recall across disciplines or languages.

Validation commands: `npm test`, `npm run typecheck`, `npm run typecheck:strict`, `npm run lint`, `node sandbox/smoke-test.mjs`, `node sandbox/comprehensive-test.mjs`. A fresh automated run and simulated host callbacks are distinct from loading a real pinned OpenCode host or visually exercising its TUI. Existing published acceptance reports remain historical.

Observed on 2026-10-20: **725 tests passed**, zero failed, cancelled or skipped; standard and strict TypeScript checks and lint passed. The isolated smoke scenario and all **18/18** comprehensive sandbox scenarios passed. The pre-change suite contained 619 tests. V1/V2 adapter tests exercise observed whole-file loss and the absence of before-hook evidence using simulated host callbacks. A live host/TUI acceptance run was not performed for this change.

