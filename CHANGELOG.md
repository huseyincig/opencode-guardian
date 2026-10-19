# Changelog

## 0.11.2 — 2026-10-20

- Sanitize all own `Error` properties recursively, including non-enumerable `cause`, aggregate errors and provider metadata, without modifying the original error.
- Remove executable serialization callbacks such as `toJSON` from sanitized values, and preserve reserved JSON keys without changing object prototypes.
- Read native V1 `session.deleted` events through `properties.info.id` and clear the associated task and capability state.
- Cancel stale V1 idle inspections on session deletion, plugin disposal and new human prompts, including attachment-only prompts.
- Prevent cancelled capability queries from repopulating deleted-session caches; clear previous task guidance on a new human turn.
- Honor V1 mutation-tool `deny`/`ask` rules and shared file-edit restrictions when deciding whether a child may remediate automatically.
- Add 19 debugging regressions and correct the capability test that treated enabled `apply_patch` as an override for an edit denial.

Validation on Node 24.22.0: 619 tests, strict TypeScript checks, lint, smoke test and 18 simulated scenarios passed. See the [Verification and Acceptance Report](docs/verification-report.md) for packaging checks and historical host-acceptance boundaries.
