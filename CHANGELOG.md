# Changelog

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
