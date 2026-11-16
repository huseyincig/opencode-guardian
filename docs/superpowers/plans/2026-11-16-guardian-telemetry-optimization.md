# Guardian Telemetry & I/O Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate excessive disk I/O and unbounded log growth in Guardian by introducing configurable telemetry levels (`violations`, `all`, `off`), directory verification caching, environment variable overrides for automated test runners, and configurable log size limits.

**Architecture:** 
1. Add typed `GuardianTelemetryConfig` to `GuardConfig` with validation in `src/engine.ts`.
2. Introduce a telemetry configuration registry in `src/telemetry.ts` that respects runtime config, directory context, and environment overrides (`OPENCODE_GUARDIAN_LOG_LEVEL`, `OPENCODE_GUARDIAN_TELEMETRY`, `OPENCODE_GUARDIAN_MAX_LOG_BYTES`).
3. Filter out high-frequency benign events (`preflight-allowed`, `post-inspected`) when `level === "violations"`, and bypass all file operations when `level === "off"` or `enabled === false`.
4. Cache state directory security verification per process to eliminate redundant `mkdirSync` and `lstatSync` syscalls per event.
5. Hook into `Guardian.server` and `Guardian.plugin` lifecycle to register effective telemetry config.

**Tech Stack:** TypeScript, Node.js (`node:fs`, `node:path`), OpenCode V2 Plugin Architecture, Node Test Runner (`node:test`).

**Spec:** Telemetry & I/O optimization specification as agreed in conversation.

## Global Constraints
- Node 18+ and OpenCode v2.3.0+ compatibility.
- Zero breaking changes for existing callers of `recordGuardianEvent` and `readGuardianStatus`.
- Maintain privacy-safety guarantees (no raw commands or unredacted paths leaked).
- Pass strict typecheck (`npm run typecheck:strict`) and lint (`npm run lint`).
- Pass all existing 786+ unit/integration tests and live V2 acceptance tests.

## Review Focus
- Event filtering in `violations` mode: benign events return `true` without touching disk; critical events (`preflight-blocked`, `post-warning`, `post-remediation`, `inspection-error`, `statistics-reset`) still write.
- Zero-I/O `off` mode: setting `OPENCODE_GUARDIAN_TELEMETRY=off` or `OPENCODE_GUARDIAN_LOG_LEVEL=off` performs zero filesystem operations.
- Directory cache invalidation: if directory is deleted during run, recovery handles recreation without crashing.
- Custom `maxBytes` boundary: file rotation accurately triggers at user-configured size threshold.
- Status and activity backwards compatibility: `readGuardianStatus()` and `readGuardianActivity()` behave consistently.

---

### Task 1: Type Definitions and Schema Validation

**Files:**
- Modify: `src/types.ts`
- Modify: `src/engine.ts`
- Test: `tests/telemetry-config-validation.test.mjs`

- [ ] Add `TelemetryLevel` (`"all" | "violations" | "off"`) and `GuardianTelemetryConfig` interface to `src/types.ts`.
- [ ] Add `telemetry?: GuardianTelemetryConfig` to `GuardConfig` in `src/types.ts`.
- [ ] Update `validateConfig` in `src/engine.ts` to validate `telemetry` fields (`enabled`, `level`, `maxBytes`).
- [ ] Update `resolveEffectiveConfig` in `src/engine.ts` to merge `telemetry` configuration across defaults, file config, and plugin options.
- [ ] Write unit test `tests/telemetry-config-validation.test.mjs` verifying valid and invalid telemetry configs.
- [ ] Run test suite to verify Task 1 passes.

---

### Task 2: Telemetry Resolver, Filtering, Directory Caching, and Bounded Rotation

**Files:**
- Modify: `src/telemetry.ts`
- Test: `tests/telemetry-optimization.test.mjs`

- [ ] Export `GuardianTelemetryConfig` and `TelemetryLevel` from `src/telemetry.ts`.
- [ ] Implement `configureGuardianTelemetry(directory?: string, config?: GuardianTelemetryConfig): void` in `src/telemetry.ts`.
- [ ] Implement `resolveTelemetrySettings(directory?: string)` supporting environment variables:
  - `OPENCODE_GUARDIAN_TELEMETRY=off|0|false`
  - `OPENCODE_GUARDIAN_LOG_LEVEL=violations|audit|all|off`
  - `OPENCODE_GUARDIAN_MAX_LOG_BYTES=<number>`
- [ ] Optimize `recordGuardianEvent`:
  - Early-exit if `!settings.enabled || settings.level === "off"` without any I/O.
  - Skip `preflight-allowed` and `post-inspected` when `settings.level === "violations"`.
  - Cache verified state directories in a set to avoid redundant `mkdirSync` / `lstatSync` on every single event.
  - Use `settings.maxBytes` for rotation check instead of hardcoded constant.
- [ ] Write unit tests in `tests/telemetry-optimization.test.mjs` testing:
  - Filtering in `violations` mode (no benign logs written, security findings written).
  - Suppression in `off` mode (zero files created).
  - Environment variable overrides.
  - Custom `maxBytes` log rotation.
- [ ] Run test suite to verify Task 2 passes.

---

### Task 3: Plugin Lifecycle Integration (V1 and V2)

**Files:**
- Modify: `src/index.ts`
- Test: `tests/plugin-telemetry-integration.test.mjs`

- [ ] In `src/index.ts` `server` (V1): call `configureGuardianTelemetry(directory, mergedConfig.telemetry)`.
- [ ] In `src/index.ts` `plugin` (V2): call `configureGuardianTelemetry(directory, mergedConfig.telemetry)`.
- [ ] Register cleanup in disposal / teardown hooks to unregister telemetry configuration.
- [ ] Write integration test in `tests/plugin-telemetry-integration.test.mjs` verifying that initializing Guardian with `telemetry: { level: "violations" }` suppresses `post-inspected` and `preflight-allowed` events during tool execution and session idle.
- [ ] Run test suite to verify Task 3 passes.

---

### Task 4: Full Verification and Acceptance Testing

**Files:**
- Run: `npm run lint`
- Run: `npm run typecheck:strict`
- Run: `npm test`
- Run: `node sandbox/smoke-test.mjs`
- Run: `node sandbox/comprehensive-test.mjs`
- Run: `node sandbox/v2-live-acceptance.mjs`

- [ ] Verify zero linter warnings / errors with `npm run lint`.
- [ ] Verify zero TypeScript errors with `npm run typecheck:strict`.
- [ ] Verify 100% test pass rate across entire suite with `npm test`.
- [ ] Run all sandboxes and live V2 acceptance tests.
- [ ] Rebuild production bundle with `npm run build`.
