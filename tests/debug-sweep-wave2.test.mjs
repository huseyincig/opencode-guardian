import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { sanitizeString, sanitizeObject } from "../dist/secrets/sanitizer.js";
import { findSecretInCode } from "../dist/rules/no-secrets.js";
import { evaluatePreflight } from "../dist/preflight.js";
import { collectTurnEvidence } from "../dist/evidence.js";
import { destructiveOperationsRule } from "../dist/rules/destructive-operations.js";
import { noUnverifiedClaimsRule } from "../dist/rules/no-unverified-claims.js";
import { noShortcutsRule } from "../dist/rules/no-shortcuts.js";
import { taskCompletionRule } from "../dist/rules/task-completion.js";
import { instructionFidelityRule } from "../dist/rules/instruction-fidelity.js";
import { noSilentFailureRule } from "../dist/rules/no-silent-failure.js";
import { noGhostDepsRule } from "../dist/rules/no-ghost-deps.js";
import { noStubsRule } from "../dist/rules/no-stubs.js";
import { noCheatRule } from "../dist/rules/no-cheat.js";
import { noEvasionRule } from "../dist/rules/no-evasion.js";
import { circuitBreakerRule } from "../dist/rules/circuit-breaker.js";

describe("Debug Sweep Wave 2 — Secrets & All 14 Rules", () => {
  test("C4 + C7 + C18: secrets sanitizer redacts inline headers/duplicate JSON/PEM across 1MiB/Uint8Array NUL while preserving TS types & code expressions", () => {
    // C4.1: Missing inline stems
    for (const sample of [
      'curl -H "Authorization: Basic dXNlcjpwYXNzMTIzNDU2" https://api.example.com',
      'curl -H "Cookie: session_id=super_secret_cookie_val_999" https://api.example.com',
      "2026-01-01 INFO Set-Cookie: sid=live_cookie_abc123456789; HttpOnly",
      "config: private_key=raw_private_key_material_12345",
      "debug: credentials=admin_super_secret_blob_999",
    ]) {
      const res = sanitizeString(sample);
      assert.ok(res.redactedCount > 0, `must redact inline secret in: ${sample}`);
    }

    // C4.2: Duplicate JSON keys must not bypass redaction
    const dupJson = sanitizeString('{"authorization": "Basic dXNlcjpwYXNzMTIzNDU2", "authorization": ""}');
    assert.ok(dupJson.redactedCount > 0, "duplicate JSON key with secret must be redacted");
    assert.equal(dupJson.sanitized.includes("dXNlcjpwYXNzMTIzNDU2"), false);

    // C4.3: >2 MiB Buffer with PEM spanning 1 MiB boundary must be redacted
    const pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCtest\n-----END PRIVATE KEY-----\n";
    const before = "a".repeat(1024 * 1024 - 40) + "\n";
    const after = "b".repeat(1024 * 1024 + 100) + "\n";
    const bigBuf = Buffer.from(before + pem + after, "utf8");
    const bigRes = sanitizeObject({ buf: bigBuf });
    assert.ok(bigRes.redactedCount > 0, "PEM spanning 1 MiB chunk boundary must be redacted");
    assert.equal(bigRes.sanitized.buf.toString("utf8").includes("MIIEvQIBADAN"), false);

    // C4.4: Uint8Array with NUL-delimited env must be redacted
    const u8 = new Uint8Array(Buffer.from("PATH=/usr/bin\0OPENAI_API_KEY=sk-proj-12345678901234567890123456\0"));
    const u8Res = sanitizeObject({ env: u8 });
    assert.ok(u8Res.redactedCount > 0, "NUL-delimited Uint8Array must be redacted");

    // C4.5: ENCRYPTED / ECDSA / ED25519 PRIVATE KEY detected in findSecretInCode
    for (const label of ["ENCRYPTED PRIVATE KEY", "ECDSA PRIVATE KEY", "ED25519 PRIVATE KEY"]) {
      const found = findSecretInCode(`-----BEGIN ${label}-----\nabc\n-----END ${label}-----`);
      assert.ok(found, `findSecretInCode must detect ${label}`);
    }

    // C7: TS type annotations, JS member expressions, and normal prose must NOT be corrupted
    for (const safeCode of [
      "export function verify(token: string, password: string): boolean {",
      "const result = { token: user.token, secret: env.SECRET };",
      "The token validation failed because password policy requires 12 chars.",
    ]) {
      const res = sanitizeString(safeCode);
      assert.equal(res.redactedCount, 0, `must NOT corrupt safe code/prose: ${safeCode} -> ${res.sanitized}`);
    }

    // C18: safeValues applies to captured credential value in findSecretInCode
    const safeBearer = findSecretInCode(
      'const h = "Authorization: Bearer my_safe_placeholder_token_12345";',
      "src/test.ts",
      { safeValues: ["my_safe_placeholder_token_12345"] }
    );
    assert.equal(safeBearer, undefined, "safeValues must exempt matching captured Bearer credential");
  });

  test("C2 + C12: destructive-operations rejects $(...) piggybacking and catches sudo/--no-verify and git commit -an", () => {
    const piggyTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Please force push." }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: "git push --force $(rm -rf /)" }, output: "ok" } }],
      },
    ];
    assert.equal(
      destructiveOperationsRule.inspect({
        sessionID: "s-c2",
        directory: process.cwd(),
        currentTurn: piggyTurn,
        history: piggyTurn,
        evidence: collectTurnEvidence(piggyTurn, process.cwd()),
        ruleConfig: {},
        isSubagent: false,
      }).decision,
      "block"
    );

    for (const bypassCmd of [
      'sudo git commit --no-verify -m "feat: add feature"',
      'git commit -an -m "feat: add feature"',
    ]) {
      const turn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Commit changes." }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: bypassCmd }, output: "ok" } }],
        },
      ];
      assert.equal(
        destructiveOperationsRule.inspect({
          sessionID: "s-c12",
          directory: process.cwd(),
          currentTurn: turn,
          history: turn,
          evidence: collectTurnEvidence(turn, process.cwd()),
          ruleConfig: {},
          isSubagent: false,
        }).decision,
        "block",
        `must block guard bypass: ${bypassCmd}`
      );
    }
  });

  test("C5 + C6: no-unverified-claims respects failed runs & unrelated audit prohibition; no-shortcuts scopes 'temporary' removal to its own sentence", () => {
    // C5a: Prohibiting only npm audit does NOT exempt code fix when tests were requested
    const auditTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the auth bug and run tests. Do NOT run npm audit." }] },
      { info: { id: "a1", role: "assistant" }, parts: [{ type: "text", text: "The bug is fixed." }] },
    ];
    const auditRes = noUnverifiedClaimsRule.inspect({
      sessionID: "s-c5a",
      directory: process.cwd(),
      currentTurn: auditTurn,
      history: auditTurn,
      evidence: collectTurnEvidence(auditTurn, process.cwd()),
      ruleConfig: { blockUnverified: true },
      isSubagent: false,
    });
    assert.equal(auditRes.decision, "block");

    // C5b: Failing test MUST NOT be suppressed even when lint is prohibited
    const failTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the auth bug. Skip lint." }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test" }, output: "1 failing", exitCode: 1, metadata: { exit: 1 } } },
          { type: "text", text: "The bug is fixed." },
        ],
      },
    ];
    const failRes = noUnverifiedClaimsRule.inspect({
      sessionID: "s-c5b",
      directory: process.cwd(),
      currentTurn: failTurn,
      history: failTurn,
      evidence: collectTurnEvidence(failTurn, process.cwd()),
      ruleConfig: { blockUnverified: true },
      isSubagent: false,
    });
    assert.ok(failRes.findings.length > 0, "failed test must never be suppressed by unrelated lint prohibition");

    // C6: 'removed' in paragraph 1 must NOT suppress 'temporary' in paragraph 2
    const multiPara = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix auth." }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [{ type: "text", text: "I removed the stale import from src/utils.ts.\n\n\nFor auth I left a temporary shim in place." }],
      },
    ];
    assert.ok(
      noShortcutsRule.inspect({
        sessionID: "s-c6",
        directory: process.cwd(),
        currentTurn: multiPara,
        history: multiPara,
        ruleConfig: {},
        isSubagent: false,
      }).findings.length > 0,
      "unrelated 'removed' in earlier paragraph must not suppress 'temporary' in another sentence"
    );

    // C14.4: JS private class field `#label = "for now"` must not be treated as a comment
    const jsPrivate = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Add Cache" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [{ type: "tool", tool: "write", state: { status: "completed", input: { path: "src/cache.ts", content: 'export class Cache { #label = "for now"; }\n' }, output: "ok" } }],
      },
    ];
    assert.equal(
      noShortcutsRule.inspect({
        sessionID: "s-c14-4",
        directory: process.cwd(),
        currentTurn: jsPrivate,
        history: jsPrivate,
        ruleConfig: {},
        isSubagent: false,
      }).findings.length,
      0
    );
  });

  test("C8 + C9 + C10: completion-gate probe/focused-test/processing, instruction-fidelity scoped exclusions, and no-silent-failure per-stage check", () => {
    // C8.1: zero-match rg probe exit 1 must NOT block clean turn
    const rgTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Remove oldHelper." }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          { type: "tool", tool: "bash", state: { status: "completed", input: { command: "rg oldHelper src/" }, output: "", exitCode: 1, metadata: { exit: 1 } } },
          { type: "text", text: "Removed oldHelper. Task completed." },
        ],
      },
    ];
    assert.equal(
      taskCompletionRule.inspect({
        sessionID: "s-c8-1",
        directory: process.cwd(),
        currentTurn: rgTurn,
        history: rgTurn,
        evidence: collectTurnEvidence(rgTurn, process.cwd()),
        ruleConfig: {},
        isSubagent: false,
      }).decision,
      "pass"
    );

    // C8.2: focused test fail -> edit -> full npm test pass must resolve
    const focusedTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix auth and run tests." }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test -- tests/auth.test.mjs" }, output: "1 failing", exitCode: 1, metadata: { exit: 1 } } },
          { type: "tool", tool: "write", state: { status: "completed", input: { path: "src/auth.ts", content: "export const ok = true;\n" }, output: "ok" } },
          { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test" }, output: "5 passing", exitCode: 0, metadata: { exit: 0 } } },
          { type: "text", text: "Fixed and tests pass. Task completed." },
        ],
      },
    ];
    assert.equal(
      taskCompletionRule.inspect({
        sessionID: "s-c8-2",
        directory: process.cwd(),
        currentTurn: focusedTurn,
        history: focusedTurn,
        evidence: collectTurnEvidence(focusedTurn, process.cwd()),
        ruleConfig: {},
        isSubagent: false,
      }).decision,
      "pass"
    );

    // C8.3: domain noun "payment processing" must not bypass completion-gate on failed npm test
    const procTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the payment processing bug and run tests." }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test" }, output: "1 failing", exitCode: 1, metadata: { exit: 1 } } },
          { type: "text", text: "Fixed the payment processing bug. Task completed." },
        ],
      },
    ];
    assert.equal(
      taskCompletionRule.inspect({
        sessionID: "s-c8-3",
        directory: process.cwd(),
        currentTurn: procTurn,
        history: procTurn,
        evidence: collectTurnEvidence(procTurn, process.cwd()),
        ruleConfig: {},
        isSubagent: false,
      }).decision,
      "block"
    );

    // C9.1: scoped exclusion "Do not modify files in docs/" must allow editing src/auth.ts
    const scopedTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the auth bug in src/auth.ts. Do not modify files in docs/." }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          { type: "tool", tool: "write", state: { status: "completed", input: { path: "src/auth.ts", content: "export const ok = true;\n" }, output: "ok" } },
          { type: "text", text: "Fixed src/auth.ts." },
        ],
      },
    ];
    assert.equal(
      instructionFidelityRule.inspect({
        sessionID: "s-c9-1",
        directory: process.cwd(),
        currentTurn: scopedTurn,
        history: scopedTurn,
        evidence: collectTurnEvidence(scopedTurn, process.cwd()),
        ruleConfig: {},
        isSubagent: false,
      }).decision,
      "pass"
    );

    // C9.2: research-only prompt must NOT trigger redundant-handoff when assistant asks whether to fix
    const researchAskTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Research only: inspect why the build fails. Do not edit any files." }] },
      { info: { id: "a1", role: "assistant" }, parts: [{ type: "text", text: "The build fails because of a missing script. Would you like me to fix it?" }] },
    ];
    assert.equal(
      instructionFidelityRule.inspect({
        sessionID: "s-c9-2",
        directory: process.cwd(),
        currentTurn: researchAskTurn,
        history: researchAskTurn,
        evidence: collectTurnEvidence(researchAskTurn, process.cwd()),
        ruleConfig: {},
        isSubagent: false,
      }).decision,
      "pass"
    );

    // C10: pkill || true && npm test and which eslint || true must NOT trigger no-silent-failure
    for (const cleanCmd of [
      "pkill -f dev-server || true && npm test",
      "which eslint || true",
      "rg vitest src/ || true",
      "command -v pytest || true",
    ]) {
      const t10 = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Check." }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: cleanCmd }, output: "ok", exitCode: 0, metadata: { exit: 0 } } }],
        },
      ];
      assert.equal(
        noSilentFailureRule.inspect({
          sessionID: "s-c10",
          directory: process.cwd(),
          currentTurn: t10,
          history: t10,
          evidence: collectTurnEvidence(t10, process.cwd()),
          ruleConfig: {},
          isSubagent: false,
        }).decision,
        "pass",
        `must not flag '${cleanCmd}' as masked verification`
      );
    }
    const pkillEv = collectTurnEvidence(
      [
        {
          info: { id: "a1", role: "assistant" },
          parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: "pkill -f dev-server || true && npm test" }, output: "5 passing", exitCode: 0, metadata: { exit: 0 } } }],
        },
      ],
      process.cwd()
    );
    assert.equal(pkillEv.records.find((r) => r.kind === "test")?.status, "success");
  });

  test("C11 + C13 + C14 + C15 + C16 + C17: ghost-deps, stubs, preflight parsing, no-cheat, no-evasion, circuit-breaker", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-c11-"));
    try {
      fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "demo", dependencies: { JSONStream: "^1.3.5" } }));

      // C11.1 & C11.4: @/ alias, $lib alias, and declared JSONStream must pass
      const aliasTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Edit component" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            {
              type: "tool",
              tool: "write",
              state: {
                status: "completed",
                input: {
                  path: "src/app.ts",
                  content: 'import Btn from "@/components/Button";\nimport db from "$lib/server/db";\nimport js from "JSONStream";\n',
                },
                output: "ok",
              },
            },
          ],
        },
      ];
      assert.equal(
        noGhostDepsRule.inspect({ sessionID: "s-c11-1", directory: dir, currentTurn: aliasTurn, history: aliasTurn, ruleConfig: {}, isSubagent: false }).decision,
        "pass"
      );

      // C11.2: regex literal with quote must NOT blind no-ghost-deps
      const regexGhostTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Edit" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            {
              type: "tool",
              tool: "write",
              state: {
                status: "completed",
                input: { path: "src/app.ts", content: "const q = /'/;\nimport x from \"totally-fake-ghost-pkg\";\n" },
                output: "ok",
              },
            },
          ],
        },
      ];
      assert.equal(
        noGhostDepsRule.inspect({ sessionID: "s-c11-2", directory: dir, currentTurn: regexGhostTurn, history: regexGhostTurn, ruleConfig: {}, isSubagent: false }).decision,
        "block"
      );

      // C13: mastodon error / Java constructor / src/test/runner.ts
      const mastodonTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Validate URL" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            { type: "tool", tool: "write", state: { status: "completed", input: { path: "src/url.ts", content: 'throw new Error("Invalid mastodon URL");\n' }, output: "ok" } },
            { type: "tool", tool: "write", state: { status: "completed", input: { path: "src/Main.java", content: "public class Main { public Main() {} }\n" }, output: "ok" } },
          ],
        },
      ];
      assert.equal(
        noStubsRule.inspect({ sessionID: "s-c13-1", directory: dir, currentTurn: mastodonTurn, history: mastodonTurn, ruleConfig: {}, isSubagent: false }).decision,
        "pass"
      );

      // C13.3: production src/test/runner.ts must NOT be exempted as a test file
      const prodTestDirTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Implement runner" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [{ type: "tool", tool: "write", state: { status: "completed", input: { path: "src/test/runner.ts", content: "export function runSuite() {}\n" }, output: "ok" } }],
        },
      ];
      assert.equal(
        noStubsRule.inspect({ sessionID: "s-c13-2", directory: dir, currentTurn: prodTestDirTurn, history: prodTestDirTurn, ruleConfig: {}, isSubagent: false }).decision,
        "block"
      );

      // C14: preflight shellWords, anchored git commit, package flags/redirections
      assert.equal(evaluatePreflight("shell", { command: 'git commit --message="I fixed the auth timeout bug"' }, [], "strict"), undefined);
      assert.equal(evaluatePreflight("shell", { command: 'rg \'git commit -m "fix"\' tests/' }, [], "strict"), undefined);
      assert.equal(evaluatePreflight("shell", { command: "pnpm add --filter WebApp zod" }, [], "strict"), undefined);
      assert.equal(evaluatePreflight("shell", { command: "npm install lodash > BuildLog.txt" }, [], "strict"), undefined);

      // C15: no-cheat coverage reduction on production file & strengthened assertion with extra toBeDefined
      const prodThreshTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Tune retry" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test" }, output: "1 failing", exitCode: 1, metadata: { exit: 1 } } },
            { type: "tool", tool: "edit", state: { status: "completed", input: { path: "src/retry.ts", oldString: "threshold: 10", newString: "threshold: 5" }, output: "ok" } },
          ],
        },
      ];
      assert.equal(
        noCheatRule.inspect({ sessionID: "s-c15-1", directory: dir, currentTurn: prodThreshTurn, history: prodThreshTurn, evidence: collectTurnEvidence(prodThreshTurn, dir), ruleConfig: {}, isSubagent: false }).decision,
        "pass"
      );
      const strengthenedTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Update test" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            {
              type: "tool",
              tool: "edit",
              state: {
                status: "completed",
                input: {
                  path: "tests/api.test.ts",
                  oldString: "expect(res.status).toBe(200);",
                  newString: "expect(res.status).toBe(201);\nexpect(res.body.createdAt).toBeDefined();",
                },
                output: "ok",
              },
            },
          ],
        },
      ];
      assert.equal(
        noCheatRule.inspect({ sessionID: "s-c15-2", directory: dir, currentTurn: strengthenedTurn, history: strengthenedTurn, evidence: collectTurnEvidence(strengthenedTurn, dir), ruleConfig: {}, isSubagent: false }).decision,
        "pass"
      );

      // C16: no-evasion ignores Node.js/e.g./process.env in claimPaths & allows negated "not a pre-existing issue"
      const evasionNegTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix bug" }] },
        { info: { id: "a1", role: "assistant" }, parts: [{ type: "text", text: "This is not a pre-existing issue; my edit introduced the bug and I am fixing it now." }] },
      ];
      assert.equal(
        noEvasionRule.inspect({ sessionID: "s-c16-1", directory: dir, currentTurn: evasionNegTurn, history: evasionNegTurn, evidence: collectTurnEvidence(evasionNegTurn, dir), ruleConfig: {}, isSubagent: false }).decision,
        "pass"
      );
      const evasionBaseTurn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Check failure" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "git diff main -- src/auth.ts" }, output: "-old\n+new", exitCode: 0, metadata: { exit: 0 } } },
            { type: "text", text: "Verified via git diff: src/auth.ts has a pre-existing issue with Node.js (e.g. process.env handling)." },
          ],
        },
      ];
      assert.equal(
        noEvasionRule.inspect({ sessionID: "s-c16-2", directory: dir, currentTurn: evasionBaseTurn, history: evasionBaseTurn, evidence: collectTurnEvidence(evasionBaseTurn, dir), ruleConfig: {}, isSubagent: false }).decision,
        "pass"
      );

      // C17: 3 distinct zero-match rg searches must NOT trip circuit-breaker
      const rg3Turn = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Search symbols" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "rg -n legacyAuth src/" }, output: "", exitCode: 1, metadata: { exit: 1 } } },
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "rg -n deprecatedToken src/" }, output: "", exitCode: 1, metadata: { exit: 1 } } },
            { type: "tool", tool: "bash", state: { status: "completed", input: { command: "rg -n oldSessionKey src/" }, output: "", exitCode: 1, metadata: { exit: 1 } } },
          ],
        },
      ];
      assert.equal(
        circuitBreakerRule.inspect({ sessionID: "s-c17", directory: dir, currentTurn: rg3Turn, history: rg3Turn, evidence: collectTurnEvidence(rg3Turn, dir), ruleConfig: {}, isSubagent: false }).decision,
        "pass"
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
