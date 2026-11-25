import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { collectTurnEvidence as collectTurnEvidence_3, collectTurnEvidence as collectTurnEvidence_4 } from "../dist/evidence.js";
import Guardian, { GuardEngine, GuardianPreflightError, REMEDIATION_MARKER, VerificationSnapshotStore, calculateProductFingerprint, collectTurnEvidence, enforcePreflight, evaluatePreflight, explicitlyAuthorizedStubOrPlaceholder, explicitlyAuthorizedTestEdit, guardianEventPath, isFileMutationTool, noCheatRule, noShortcutsRule, noTruncationRule, noUnverifiedClaimsRule, normalizeV2Messages, readGuardianActivity, recordGuardianEvent, sessionFingerprint, taskCompletionRule } from "../dist/index.js";
import { circuitBreakerRule } from "../dist/rules/circuit-breaker.js";
import { destructiveOperationsRule } from "../dist/rules/destructive-operations.js";
import { instructionFidelityRule } from "../dist/rules/instruction-fidelity.js";
import { noEvasionRule } from "../dist/rules/no-evasion.js";
import { taskCompletionRule as taskCompletionRule_3 } from "../dist/rules/task-completion.js";
import { hasPostMutationReview } from "../dist/task-contract.js";

describe("Verification Report & Count Semantics", () => {
  function run(output, exit = 0, command = 'node --test tests/a.test.mjs', extra = {}) {
    return { info: { id: 'run', role: 'assistant' }, parts: [{ type: 'tool', tool: 'bash',
      state: { status: 'completed', input: { command }, output, metadata: { exit, ...extra } } }] };
  }
  function context(messages, text = 'All tests passed.') {
    const currentTurn = [...messages, { info: { id: 'final', role: 'assistant' }, parts: [{ type: 'text', text }] }];
    return { sessionID: 'verification', directory: '/tmp', messages: currentTurn, currentTurn,
      ruleConfig: {}, evidence: collectTurnEvidence(currentTurn, '/tmp') };
  }
  const nodeSummary = (pass, fail = 0, skip = 0, cancel = 0, todo = 0) =>
    `ℹ tests ${pass + fail + skip + cancel + todo}\nℹ pass ${pass}\nℹ fail ${fail}\nℹ cancelled ${cancel}\nℹ skipped ${skip}\nℹ todo ${todo}\nℹ duration_ms 2`;

  test('evidence normalizes a complete Node test summary and preserves host failure', () => {
    const record = collectTurnEvidence([run(nodeSummary(6, 1, 1), 1)]).records[0];
    assert.deepEqual(record.testSummary, { format: 'node', total: 8, passed: 6, failed: 1, skipped: 1, cancelled: 0, todo: 0 });
    assert.equal(record.status, 'failure');
    assert.equal(record.outcomeReason, 'execution-failure');
  });

  test('evidence normalizes supported pytest, Jest and Vitest aggregate summaries', () => {
    for (const [command, output, format, total, passed, skipped] of [
      ['pytest tests/', '================ 4 passed, 2 skipped in 0.20s ================', 'pytest', 6, 4, 2],
      ['npx jest', 'Tests:       2 skipped, 3 passed, 5 total\nTime: 1 s', 'jest', 5, 3, 2],
      ['vitest run', ' Tests  3 passed | 2 skipped (5)\n Duration  4ms', 'vitest', 5, 3, 2],
    ]) {
      const record = collectTurnEvidence([run(output, 0, command)]).records.find(r => r.kind === 'test');
      assert.equal(record?.testSummary?.format, format);
      assert.equal(record.testSummary.total, total);
      assert.equal(record.testSummary.passed, passed);
      assert.equal(record.testSummary.skipped, skipped);
    }
  });

  test('zero tests and all-skipped runs never become successful verification', () => {
    for (const [output, reason] of [[nodeSummary(0), 'no-tests'], [nodeSummary(0, 0, 3), 'skipped-only']]) {
      const evidence = collectTurnEvidence([run(output)]);
      assert.equal(evidence.records[0].status, 'unknown');
      assert.equal(evidence.records[0].outcomeReason, reason);
      assert.equal(evidence.successfulVerifications.length, 0);
    }
  });

  test('pytest warning and deselection metadata do not hide all-skipped test counts', () => {
    const record = collectTurnEvidence([run('================ 2 skipped, 1 warning, 3 deselected in 0.02s ================', 0, 'pytest tests')]).records[0];
    assert.equal(record.testSummary?.skipped, 2);
    assert.equal(record.testSummary?.total, 2);
    assert.equal(record.status, 'unknown');
  });

  test('a passing shell exit cannot erase a complete failing test summary', () => {
    const record = collectTurnEvidence([run(nodeSummary(2, 1))]).records[0];
    assert.equal(record.status, 'unknown');
    assert.equal(record.exitCode, 0);
    assert.equal(record.outcomeReason, 'summary-conflict');
  });

  test('pytest collection failure, cancellation and timeouts have distinct reasons', () => {
    for (const [command, exit, reason] of [['pytest tests', 5, 'no-tests'], ['pytest tests', 2, 'execution-failure'], ['npm test', 124, 'timeout']]) {
      const record = collectTurnEvidence([run('', exit, command)]).records.find(r => r.kind === 'test');
      assert.equal(record.outcomeReason, reason);
      assert.equal(record.status, 'failure');
    }
  });

  test('pytest collection errors are failures rather than user cancellations', () => {
    const record = collectTurnEvidence([run('ERROR collecting tests/test_app.py\nModuleNotFoundError: missing dependency', 2, 'pytest tests')]).records[0];
    assert.equal(record.outcomeReason, 'execution-failure');
  });

  test('explicit host cancellation cannot count as a successful verification', () => {
    const evidence = collectTurnEvidence([run(nodeSummary(3), 0, 'npm test', { cancelled: true })]);
    assert.equal(evidence.records[0].outcomeReason, 'cancelled');
    assert.equal(evidence.records[0].status, 'unknown');
    assert.equal(evidence.successfulVerifications.length, 0);
  });

  test('unknown and malformed summaries do not invent counts or trust printed example lines', () => {
    for (const output of ['The docs say tests 0 and pass 0.', 'ℹ tests 2\nℹ pass 9\nℹ fail 0', '2 passed', 'Tests: 999999999999999999999 passed, 1 total']) {
      const record = collectTurnEvidence([run(output)]).records[0];
      assert.equal(record.testSummary, undefined);
      assert.equal(record.status, 'success');
    }
    assert.equal(collectTurnEvidence([run(nodeSummary(3), 0, 'cat results.txt')]).records[0].testSummary, undefined);
  });

  test('explicit total/pass claims are compared to observed counts', () => {
    const result = noUnverifiedClaimsRule.inspect(context([run(nodeSummary(3, 0, 2))], 'All 5 tests passed.'));
    assert.equal(result.decision, 'block');
    assert.ok(result.findings.some(f => f.pattern === 'test count contradicts observed summary'));
    assert.equal(noUnverifiedClaimsRule.inspect(context([run(nodeSummary(3))], 'All 3 tests passed.')).decision, 'pass');
  });

  test('historical test counts are not contradicted by the current result', () => {
    const result = noUnverifiedClaimsRule.inspect(context([run(nodeSummary(3))], 'Before this change, 2 tests passed. Now all 3 tests passed.'));
    assert.equal(result.decision, 'pass');
  });

  test('completion cannot accept an explicitly required test run that executed no tests', () => {
    const user = { info: { id: 'u', role: 'user' }, parts: [{ type: 'text', text: 'Run tests before finishing.' }] };
    const result = taskCompletionRule.inspect(context([user, run(nodeSummary(0))], 'Task completed. Tests passed.'));
    assert.equal(result.decision, 'block');
  });
});

describe("Edit Integrity & Content-Loss Observations", () => {
  function project(t) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-integrity-'));
    fs.mkdirSync(path.join(dir, 'src'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    return dir;
  }
  const before = ['alpha', 'beta', 'gamma', 'delta'].map(name => `export function ${name}() { return '${name}'; }`).join('\n');
  function inspect(dir, store, input, status = 'completed') {
    const messages = [{ info: { id: 'a', role: 'assistant' }, parts: [{ type: 'tool', tool: 'write_file', callID: 'w', state: { status, input } }] }];
    const evidence = collectTurnEvidence(messages, dir, store.snapshots('s'));
    return noTruncationRule.inspect({ sessionID: 's', directory: dir, messages, currentTurn: messages, ruleConfig: {}, evidence });
  }

  test('observed whole-file replacement reports lost definitions as advisory', t => {
    const dir = project(t), store = new VerificationSnapshotStore();
    const input = { path: 'src/a.ts', content: 'export function alpha() { return 1; }' };
    fs.writeFileSync(path.join(dir, input.path), before);
    store.observeBefore('s', 'w', 'write_file', input, dir);
    fs.writeFileSync(path.join(dir, input.path), input.content);
    store.observe('s', 'w', 'write_file', input, '', {}, dir);
    const result = inspect(dir, store, input);
    assert.equal(result.decision, 'pass');
    assert.ok(result.findings.some(f => f.pattern === 'observed whole-file content loss'));
    assert.equal(result.remediationPrompt, undefined);
    const observed = store.snapshots('s').get('w').editIntegrity;
    assert.equal(observed.status, 'observed');
    assert.equal(observed.removedDefinitions, 3);
    assert.notEqual(observed.beforeHash, observed.afterHash);
  });

  test('history without a before-hook cannot fabricate previous file content', t => {
    const dir = project(t), store = new VerificationSnapshotStore();
    const input = { path: 'src/a.ts', content: 'export const a = 1;' };
    fs.writeFileSync(path.join(dir, input.path), input.content);
    store.observe('s', 'w', 'write_file', input, '', {}, dir);
    assert.equal(inspect(dir, store, input).findings.length, 0);
    assert.equal(store.snapshots('s').get('w')?.editIntegrity, undefined);
  });

  test('an observed empty replacement remains mutation evidence and reports content loss', t => {
    const dir = project(t), store = new VerificationSnapshotStore();
    const input = { path: 'src/a.ts', content: '' };
    fs.writeFileSync(path.join(dir, input.path), before);
    store.observeBefore('s', 'w', 'write_file', input, dir);
    fs.writeFileSync(path.join(dir, input.path), '');
    store.observe('s', 'w', 'write_file', input, '', {}, dir);
    assert.ok(inspect(dir, store, input).findings.some(f => f.pattern === 'observed whole-file content loss'));
  });

  test('targeted edits, failed writes and unchanged replacements do not report content loss', t => {
    const dir = project(t);
    for (const [input, status] of [
      [{ path: 'src/a.ts', old_string: 'gamma', new_string: 'epsilon' }, 'completed'],
      [{ path: 'src/a.ts', content: '' }, 'error'],
      [{ path: 'src/a.ts', content: before }, 'completed'],
    ]) {
      const store = new VerificationSnapshotStore();
      fs.writeFileSync(path.join(dir, input.path), before);
      store.observeBefore('s', 'w', 'write_file', input, dir);
      store.observe('s', 'w', 'write_file', input, '', {}, dir, status);
      assert.equal(inspect(dir, store, input, status).findings.length, 0);
    }
  });

  test('before-hook refuses symlink escapes, external paths and oversized files', t => {
    const dir = project(t), outside = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-outside-'));
    t.after(() => fs.rmSync(outside, { recursive: true, force: true }));
    fs.writeFileSync(path.join(outside, 'a.ts'), before);
    fs.symlinkSync(outside, path.join(dir, 'escape'));
    fs.writeFileSync(path.join(dir, 'huge.ts'), 'x'.repeat(2 * 1024 * 1024 + 1));
    for (const target of ['escape/a.ts', path.join(outside, 'a.ts'), 'huge.ts']) {
      const store = new VerificationSnapshotStore(), input = { path: target, content: 'export const a = 1;' };
      store.observeBefore('s', 'w', 'write_file', input, dir);
      store.observe('s', 'w', 'write_file', input, '', {}, dir);
      assert.equal(store.snapshots('s').get('w')?.editIntegrity?.status, 'unavailable');
      assert.equal(inspect(dir, store, input).findings.length, 0);
    }
  });

  test('strict file preflight rejects executable truncation placeholders but permits quoted examples', () => {
    assert.equal(evaluatePreflight('write_file', { path: 'src/a.ts', content: '// ... existing code unchanged ...' }), 'truncation-placeholder-in-file-write');
    assert.equal(evaluatePreflight('edit', { path: 'src/a.py', new_string: '# ... rest of code ...' }), 'truncation-placeholder-in-file-write');
    assert.equal(evaluatePreflight('write_file', { path: 'src/a.ts', content: 'const example = "// ... existing code unchanged ...";' }), undefined);
    assert.equal(evaluatePreflight('write_file', { path: 'README.md', content: 'Example:\n```ts\n// ... existing code unchanged ...\n```' }), undefined);
  });

  test('v2 adapter delivers observed edit integrity to idle engine inspection', async t => {
    for (const capture of [true, false]) {
      const dir = project(t);
      fs.writeFileSync(path.join(dir, 'opencode-guardian.json'), JSON.stringify({ secrets: { enabled: false }, updateNotice: { enabled: false } }));
      const input = { path: 'src/a.ts', content: 'export function alpha() { return 1; }' };
      fs.writeFileSync(path.join(dir, input.path), before);
      let cleanup;
      {
        const callbacks = new Map();
        let release;
        const idle = new Promise(resolve => { release = resolve; });
        let inspected;
        const observed = new Promise(resolve => { inspected = resolve; });
        cleanup = await Guardian.setup({ location: { directory: dir },
          tool: { async hook(kind, handler) { callbacks.set(kind, handler); return { dispose() {} }; } },
          event: { subscribe({ signal }) { return (async function* () {
            await idle;
            yield { type: 'session.idle', data: { sessionID: 's' } };
            await new Promise(resolve => signal.aborted ? resolve() : signal.addEventListener('abort', resolve, { once: true }));
          })(); } },
          session: {
            async context() {
              inspected();
              return [
                { id: 'u', type: 'user', text: 'Fix alpha.' },
                { id: 'a', type: 'assistant', content: [{ type: 'tool', name: 'write_file', id: 'w', state: { status: 'completed', input } }] },
              ];
            },
            async synthetic() { assert.fail('advisory content loss must not start remediation'); },
          },
        });
        try {
          if (capture) await callbacks.get('execute.before')({ tool: 'write_file', sessionID: 's', id: 'w', input });
          fs.writeFileSync(path.join(dir, input.path), input.content);
          await callbacks.get('execute.after')({ tool: 'write_file', sessionID: 's', id: 'w', input, status: 'completed', result: { output: 'written', metadata: {} } });
          release();
          await observed;
          const deadline = Date.now() + 2000;
          while (capture && !readGuardianActivity(dir).some(e => e.rules?.includes('safety/no-truncation')) && Date.now() < deadline) {
            await new Promise(resolve => setTimeout(resolve, 5));
          }
          if (!capture) await new Promise(resolve => setImmediate(resolve));
        } finally { await cleanup(); }
      }
      assert.equal(readGuardianActivity(dir).some(e => e.rules?.includes('safety/no-truncation')), capture,
        'idle warning requires an actual before/after observation');
    }
  });
});

describe("Closed-Loop Remediation & State-Bound Evidence", () => {
  function isolated(t) {
    const dir = path.join(os.tmpdir(), `guardian-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    process.env.OPENCODE_GUARDIAN_STATE_DIR = dir;
    t.after(() => {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
      delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    });
    return dir;
  }

  test("Preflight intercepts hardcoded secrets in file mutation tools before disk write", () => {
    const fakeApiKey = "sk-" + "a".repeat(40);
    const fakeGithubPat = "ghp_" + "b".repeat(36);
    const fakeAwsKey = "AKIA" + "C".repeat(16);

    // Shell write tools
    assert.equal(isFileMutationTool("write_to_file"), true);
    assert.equal(isFileMutationTool("replace_file_content"), true);
    assert.equal(isFileMutationTool("edit_file"), true);
    assert.equal(isFileMutationTool("apply_patch"), true);
    assert.equal(isFileMutationTool("mcp__provider_fs__write_file"), true);
    assert.equal(isFileMutationTool("read_file"), false);

    // Hardcoded secret in write_to_file
    assert.equal(
      evaluatePreflight("write_to_file", {
        path: "src/config.ts",
        content: `export const API_KEY = "${fakeApiKey}";`,
      }),
      "hardcoded-secret-in-file-write"
    );

    // Hardcoded GitHub PAT in replace_file_content
    assert.equal(
      evaluatePreflight("replace_file_content", {
        filePath: "src/auth.ts",
        ReplacementContent: `const token = "${fakeGithubPat}";`,
      }),
      "hardcoded-secret-in-file-write"
    );

    // Hardcoded AWS key in apply_patch
    assert.equal(
      evaluatePreflight("apply_patch", {
        patch: `--- a/src/aws.ts\n+++ b/src/aws.ts\n@@ -1,2 +1,2 @@\n-const old = 1;\n+const awsKey = "${fakeAwsKey}";`,
      }),
      "hardcoded-secret-in-file-write"
    );

    // enforcePreflight throws GuardianPreflightError
    assert.throws(
      () => enforcePreflight("write_to_file", { path: "src/secret.ts", content: `const k = "${fakeApiKey}";` }),
      (err) => err instanceof GuardianPreflightError && err.reason === "hardcoded-secret-in-file-write"
    );

    // Benign code passes cleanly
    assert.equal(
      evaluatePreflight("write_to_file", {
        path: "src/config.ts",
        content: 'export const API_KEY = process.env.OPENAI_API_KEY ?? "";',
      }),
      undefined
    );

    // Template/example values pass cleanly
    assert.equal(
      evaluatePreflight("write_to_file", {
        path: ".env.example",
        content: "DATABASE_URL=postgres://user:password@localhost:5432/mydb",
      }),
      undefined
    );
  });

  test("State-bound test evidence invalidates verification when files change after tests", () => {
    const tmpDir = path.join(os.tmpdir(), `test-state-bound-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    const srcFile = path.join(tmpDir, "calculator.ts");
    fs.writeFileSync(srcFile, "export const add = (a, b) => a + b;");

    // Step 1: Agent mutates file
    const step1 = {
      info: { id: "a1", role: "assistant" },
      parts: [
        {
          type: "tool",
          tool: "write_to_file",
          state: {
            status: "completed",
            input: { path: "calculator.ts", content: "export const add = (a, b) => a + b;" },
          },
        },
      ],
    };

    // Step 2: Agent runs tests successfully
    const step2 = {
      info: { id: "a2", role: "assistant" },
      parts: [
        {
          type: "tool",
          tool: "bash",
          state: {
            status: "completed",
            input: { command: "npm test" },
            metadata: { exit: 0 },
          },
        },
      ],
    };

    // Case A: At step 2, test verification is fresh and matches current state
    const evidenceBeforePostEdit = collectTurnEvidence([step1, step2], tmpDir);
    const claimContextClean = {
      sessionID: "sess-1",
      directory: tmpDir,
      messages: [],
      ruleConfig: {},
      currentTurn: [step1, step2, {
        info: { id: "a3", role: "assistant" },
        parts: [{ type: "text", text: "All tests passing." }],
      }],
      evidence: evidenceBeforePostEdit,
    };
    const cleanResult = noUnverifiedClaimsRule.inspect(claimContextClean);
    assert.equal(cleanResult.decision, "pass");
    assert.equal(cleanResult.findings.length, 0);

    // Step 3: Agent mutates file AGAIN after the test
    fs.writeFileSync(srcFile, "export const add = (a, b) => a - b;"); // altered!
    const step3 = {
      info: { id: "a4", role: "assistant" },
      parts: [
        {
          type: "tool",
          tool: "write_to_file",
          state: {
            status: "completed",
            input: { path: "calculator.ts", content: "export const add = (a, b) => a - b;" },
          },
        },
      ],
    };

    // Case B: Claiming tests passed after a post-test mutation is flagged as stale
    const evidenceAfterPostEdit = collectTurnEvidence([step1, step2, step3], tmpDir);
    const claimContextStale = {
      sessionID: "sess-1",
      directory: tmpDir,
      messages: [],
      ruleConfig: { blockUnverified: true },
      currentTurn: [step1, step2, step3, {
        info: { id: "a5", role: "assistant" },
        parts: [{ type: "text", text: "All tests passing." }],
      }],
      evidence: evidenceAfterPostEdit,
    };
    const staleResult = noUnverifiedClaimsRule.inspect(claimContextStale);
    assert.equal(staleResult.decision, "block");
    assert.equal(staleResult.findings.length, 1);
    assert.equal(staleResult.findings[0].pattern, "tests passing");

    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  });

  test("Intent-aware exceptions: user-authorized test edits and stubs are permitted without blocks", () => {
    // 1. Authorized test edit
    assert.equal(explicitlyAuthorizedTestEdit("Lütfen testleri yeni şemaya göre güncelle"), true);
    assert.equal(explicitlyAuthorizedTestEdit("Update the failing tests in test_auth.py"), true);
    assert.equal(explicitlyAuthorizedTestEdit("Refactor tests and remove obsolete test_old"), true);
    assert.equal(explicitlyAuthorizedTestEdit("Fix the calculation bug in finance.ts"), false);

    const testSkipContextAuthorized = {
      sessionID: "sess-cheat",
      directory: "/tmp",
      messages: [
        {
          info: { id: "user-1", role: "user" },
          parts: [{ type: "text", text: "Update the tests in calculator.test.ts to skip unsupported mode" }],
        },
      ],
      ruleConfig: { blockStructuralTestChanges: true },
      currentTurn: [
        {
          info: { id: "user-1", role: "user" },
          parts: [{ type: "text", text: "Update the tests in calculator.test.ts to skip unsupported mode" }],
        },
        {
          info: { id: "asst-1", role: "assistant" },
          parts: [
            {
              type: "tool",
              tool: "write_to_file",
              state: {
                input: {
                  path: "calculator.test.ts",
                  content: "describe('calc', () => { it.skip('unsupported', () => {}); });",
                },
              },
            },
          ],
        },
      ],
    };

    const authorizedResult = noCheatRule.inspect(testSkipContextAuthorized);
    assert.equal(authorizedResult.decision, "pass");

    // Unauthorized test skip blocks
    const testSkipContextUnauthorized = {
      ...testSkipContextAuthorized,
      messages: [
        {
          info: { id: "user-2", role: "user" },
          parts: [{ type: "text", text: "Fix the math bug in calculator" }],
        },
      ],
      currentTurn: [
        {
          info: { id: "user-2", role: "user" },
          parts: [{ type: "text", text: "Fix the math bug in calculator" }],
        },
        testSkipContextAuthorized.currentTurn[1],
      ],
    };
    const unauthorizedResult = noCheatRule.inspect(testSkipContextUnauthorized);
    assert.equal(unauthorizedResult.decision, "block");

    // 2. Authorized stub/placeholder
    assert.equal(explicitlyAuthorizedStubOrPlaceholder("Add a placeholder function for now"), true);
    assert.equal(explicitlyAuthorizedStubOrPlaceholder("Add a TODO for tomorrow's migration"), true);
    assert.equal(explicitlyAuthorizedStubOrPlaceholder("Ödeme servisi için bir taslak oluştur"), true);
    assert.equal(explicitlyAuthorizedStubOrPlaceholder("Complete the user service implementation"), false);

    const stubContextAuthorized = {
      sessionID: "sess-stub",
      directory: "/tmp",
      messages: [
        {
          info: { id: "user-3", role: "user" },
          parts: [{ type: "text", text: "Add a stub implementation of the payment gateway" }],
        },
      ],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "user-3", role: "user" },
          parts: [{ type: "text", text: "Add a stub implementation of the payment gateway" }],
        },
        {
          info: { id: "asst-2", role: "assistant" },
          parts: [
            {
              type: "tool",
              tool: "write_to_file",
              state: {
                input: {
                  path: "src/payment.ts",
                  content: "// TODO: implement real stripe call\nexport function charge() { return true; }",
                },
              },
            },
          ],
        },
      ],
    };
    assert.equal(noShortcutsRule.inspect(stubContextAuthorized).decision, "pass");
  });

  test("Closed-loop remediation: verifies fixes and records remediation-verified / remediation-failed", async (t) => {
    const project = isolated(t);
    fs.mkdirSync(path.join(project, "src"), { recursive: true });
    const engine = new GuardEngine({
      enabled: true,
      remediationBudget: 1,
      rules: { "security/no-secrets": "error" },
    });

    const fakeKey = "sk-" + "c".repeat(40);
    fs.writeFileSync(path.join(project, "src/api.ts"), `export const KEY = "${fakeKey}";`);
    const initialTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Add the API client" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "write_to_file",
            state: { status: "completed", input: { path: "src/api.ts", content: `export const KEY = "${fakeKey}";` } },
          },
        ],
      },
    ];

    // Round 1: Violation detected, remediation requested
    const blockResult = await engine.inspect("session-remediation", project, initialTurn);
    assert.equal(blockResult.decision, "block");
    assert.ok(blockResult.combinedRemediationPrompt?.includes(REMEDIATION_MARKER));

    // Case A: Agent responds to remediation prompt with CLEAN code -> remediation verified!
    fs.writeFileSync(path.join(project, "src/api.ts"), 'export const KEY = process.env.API_KEY ?? "";');
    const remediationFixedTurn = [
      ...initialTurn,
      {
        info: { id: "rem-1", role: "user" },
        parts: [{ type: "text", text: blockResult.combinedRemediationPrompt, synthetic: true }],
      },
      {
        info: { id: "a2", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "write_to_file",
            state: { status: "completed", input: { path: "src/api.ts", content: 'export const KEY = process.env.API_KEY ?? "";' } },
          },
        ],
      },
    ];

    const verifiedResult = await engine.inspect("session-remediation", project, remediationFixedTurn);
    assert.equal(verifiedResult.decision, "pass");
    assert.equal(verifiedResult.remediationStatus, "verified");

    // Case B: In a new session, agent responds with STILL VIOLATING code -> remediation failed, no infinite loop!
    const engine2 = new GuardEngine({
      enabled: true,
      remediationBudget: 1,
      rules: { "security/no-secrets": "error" },
    });

    await engine2.inspect("session-failed", "/tmp", initialTurn); // block 1
    const anotherKey = "sk-" + "d".repeat(40);
    const remediationStillFailingTurn = [
      ...initialTurn,
      {
        info: { id: "rem-2", role: "user" },
        parts: [{ type: "text", text: blockResult.combinedRemediationPrompt, synthetic: true }],
      },
      {
        info: { id: "a3", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "write_to_file",
            state: { input: { path: "src/api.ts", content: `export const STILL_KEY = "${anotherKey}";` } },
          },
        ],
      },
    ];

    const failedResult = await engine2.inspect("session-failed", "/tmp", remediationStillFailingTurn);
    assert.equal(failedResult.decision, "pass"); // Stopped cleanly without infinite loop!
    assert.equal(failedResult.remediationStatus, "failed");
  });


  test("Remediation never claims verified without an observed, relevant correction", async (t) => {
    const project = isolated(t);
    fs.mkdirSync(path.join(project, "src"), { recursive: true });
    const token = "sk-" + "q".repeat(40);
    fs.writeFileSync(path.join(project, "src/config.ts"), 'const key = "' + token + '";');
    const initial = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Implement the client" }] },
      { info: { id: "a1", role: "assistant" }, parts: [{
        type: "tool", tool: "write_to_file",
        state: { status: "completed", input: { path: "src/config.ts", content: 'const key = "' + token + '";' } },
      }] },
    ];
    const engine = new GuardEngine({ enabled: true, remediationBudget: 1 });
    const blocked = await engine.inspect("no-change", project, initial);
    assert.equal(blocked.decision, "block");
    const followUp = [...initial,
      { info: { id: "r1", role: "user" }, parts: [{
        type: "text", text: blocked.combinedRemediationPrompt, synthetic: true,
      }] },
      { info: { id: "a2", role: "assistant" }, parts: [{ type: "text", text: "Fixed it." }] },
    ];
    const idle = await engine.inspect("no-change", project, followUp);
    assert.equal(idle.remediationStatus, "unverified");
    assert.equal(idle.decision, "pass");
    assert.deepEqual(idle.pendingRemediationRules, ["security/no-secrets"]);

    const restarted = new GuardEngine({ enabled: true, remediationBudget: 1 });
    const cold = await restarted.inspect("no-change", project, followUp);
    assert.equal(cold.remediationStatus, "unverified");
    assert.deepEqual(cold.pendingRemediationRules, []);

    const unrelatedEngine = new GuardEngine({ enabled: true, remediationBudget: 1 });
    const start = await unrelatedEngine.inspect("unrelated", project, initial);
    fs.writeFileSync(path.join(project, "src/other.ts"), "export const ok = true;");
    const unrelated = await unrelatedEngine.inspect("unrelated", project, [
      ...initial, { info: { id: "r2", role: "user" }, parts: [{
        type: "text", text: start.combinedRemediationPrompt, synthetic: true,
      }] },
      { info: { id: "a3", role: "assistant" }, parts: [{
        type: "tool", tool: "write_to_file",
        state: { status: "completed", input: {
          path: "src/other.ts", content: "export const ok = true;",
        } },
      }] },
    ]);
    assert.equal(unrelated.remediationStatus, "unverified");
  });

  test("Preflight understands generic MCP file mutations and rejects opaque write payloads", () => {
    const secret = "sk-" + "p".repeat(40);
    assert.equal(isFileMutationTool("mcp__provider_a__file_mutate"), true);
    assert.equal(isFileMutationTool("mcp__custom-provider__file_mutate"), true);
    assert.equal(evaluatePreflight("mcp__provider_a__file_mutate", {
      action: "write", path: "src/key.ts", content: "const key = '" + secret + "';",
    }), "hardcoded-secret-in-file-write");
    assert.equal(evaluatePreflight("mcp__provider_a__file_mutate", {
      action: "edit", path: "src/key.ts", edits: [{ replacement: "const key = '" + secret + "';" }],
    }), "hardcoded-secret-in-file-write");
    assert.equal(evaluatePreflight("mcp__provider_a__file_mutate", {
      action: "write", path: "src/key.ts",
    }), "uninspectable-file-input");
    assert.equal(evaluatePreflight("mcp__provider_a__file_mutate", null),
      "uninspectable-file-input");
    assert.equal(evaluatePreflight("mcp__provider_a__file_mutate", {
      action: "move", source: "src/key.ts", destination: "src/renamed.ts",
    }), undefined);
  });

  test("Generic test edits and unrelated mocks cannot waive security checks", () => {
    const human = (text) => ({ info: { id: "u1", role: "user" }, parts: [
      { type: "text", text },
    ] });
    const skip = { info: { id: "a1", role: "assistant" }, parts: [{
      type: "tool", tool: "edit_file", state: { input: {
        path: "tests/payments.test.ts", new_string: "test.skip('payments', () => {});",
      } },
    }] };
    const ctx = (text, event) => ({
      sessionID: "scope-test", directory: "/tmp", ruleConfig: {},
      messages: [human(text), event], currentTurn: [human(text), event],
    });
    assert.equal(noCheatRule.inspect(ctx("Fix the failing tests", skip)).decision, "block");
    assert.equal(noCheatRule.inspect(ctx("Do not skip tests; update failing tests", skip)).decision, "block");
    assert.equal(noCheatRule.inspect(ctx(
      "Explicitly skip unsupported payments test until the feature is available", skip,
    )).decision, "pass");
    const shortcut = { info: { id: "a2", role: "assistant" }, parts: [{
      type: "tool", tool: "write_to_file", state: { input: {
        path: "src/payment.ts", content: "// TODO: implement payment validation",
      } },
    }] };
    assert.equal(noShortcutsRule.inspect(ctx(
      "Create a mock for the HTTP tests and finish payment validation", shortcut,
    )).decision, "block");
    assert.equal(noShortcutsRule.inspect(ctx(
      "Do not add TODO to src/payment.ts; finish payment validation", shortcut,
    )).decision, "block");
  });

  test("A live test snapshot detects same-size edits with preserved timestamps", (t) => {
    const project = isolated(t);
    const source = path.join(project, "logic.ts");
    const fixed = new Date("2024-01-01T00:00:00Z");
    fs.writeFileSync(source, "export const value = 1;");
    fs.utimesSync(source, fixed, fixed);
    const initial = calculateProductFingerprint(project, ["logic.ts"]);
    const store = new VerificationSnapshotStore();
    store.observe("session", "mutation", "write_to_file", {
      path: "logic.ts", content: "export const value = 1;",
    }, "saved", {}, project);
    store.observe("session", "test-call", "bash", {
      command: "npm test",
    }, "tests passed", { exit: 0 }, project);
    const messages = [
      { info: { id: "u1", role: "user" }, parts: [{
        type: "text", text: "Implement logic and verify",
      }] },
      { info: { id: "a1", role: "assistant" }, parts: [{
        type: "tool", callID: "mutation", tool: "write_to_file",
        state: { status: "completed", input: {
          path: "logic.ts", content: "export const value = 1;",
        } },
      }] },
      { info: { id: "a2", role: "assistant" }, parts: [{
        type: "tool", callID: "test-call", tool: "bash",
        state: { status: "completed", input: {
          command: "npm test",
        }, metadata: { exit: 0 } },
      }] },
      { info: { id: "a3", role: "assistant" }, parts: [{
        type: "text", text: "All tests passing.",
      }] },
    ];
    const snapshot = store.snapshots("session");
    assert.equal(snapshot.has("test-call"), true);
    const before = collectTurnEvidence(messages, project, snapshot);
    assert.equal(noUnverifiedClaimsRule.inspect({
      sessionID: "session", directory: project, messages,
      currentTurn: messages, evidence: before, ruleConfig: { blockUnverified: true },
    }).decision, "pass");

    // A later user turn can verify files changed in an earlier turn.
    store.observe("session", "next-turn-test", "bash", {
      command: "npm test",
    }, "tests passed", { exit: 0 }, project);
    const nextTurn = [
      { info: { id: "u2", role: "user" }, parts: [{ type: "text", text: "Verify again" }] },
      { info: { id: "a4", role: "assistant" }, parts: [{
        type: "tool", callID: "next-turn-test", tool: "bash",
        state: { status: "completed", input: { command: "npm test" },
          metadata: { exit: 0 } },
      }] },
      { info: { id: "a5", role: "assistant" }, parts: [{
        type: "text", text: "All tests passing.",
      }] },
    ];
    const laterEvidence = collectTurnEvidence(nextTurn, project, snapshot);
    assert.deepEqual(laterEvidence.records.find((record) =>
      record.kind === "test").snapshotFiles, ["logic.ts"]);
    assert.equal(noUnverifiedClaimsRule.inspect({
      sessionID: "session", directory: project, messages: nextTurn,
      currentTurn: nextTurn, evidence: laterEvidence,
      ruleConfig: { blockUnverified: true },
    }).decision, "pass");

    fs.writeFileSync(source, "export const value = 2;");
    fs.utimesSync(source, fixed, fixed);
    const current = calculateProductFingerprint(project, ["logic.ts"]);
    assert.notEqual(current, initial, "the content hash must ignore forged mtime equivalence");
    const replay = collectTurnEvidence(messages, project, snapshot);
    assert.equal(replay.records.find((record) => record.kind === "test").stateFingerprint,
      snapshot.get("test-call").fingerprint, "historic snapshot must not be recalculated at idle");
    assert.equal(noUnverifiedClaimsRule.inspect({
      sessionID: "session", directory: project, messages,
      currentTurn: messages, evidence: replay, ruleConfig: { blockUnverified: true },
    }).decision, "block");
  });
  test("V2 host adapter registers and disposes live evidence hooks", async (t) => {
    const project = isolated(t);
    fs.writeFileSync(path.join(project, "opencode-guardian.json"),
      JSON.stringify({
        enabled: true,
        preflight: { enabled: false },
        secrets: { enabled: false },
      }));

    let afterHook;
    const disposed = [];
    const v2 = {
      location: { directory: project },
      session: { context: async () => [], synthetic: async () => {} },
      tool: { hook: async (name, callback) => {
        assert.equal(name, "execute.after");
        afterHook = callback;
        return { dispose: async () => { disposed.push(name); } };
      } },
      event: { subscribe: ({ signal }) => ({
        async *[Symbol.asyncIterator]() {
          if (!signal.aborted) await new Promise((resolve) =>
            signal.addEventListener("abort", resolve, { once: true }));
        },
      }) },
    };
    const cleanup = await Guardian.setup(v2);
    assert.equal(typeof afterHook, "function");
    await afterHook({
      tool: "write_to_file", sessionID: "s", id: "m2",
      input: { path: "file.ts", content: "export const value = true;" },
      status: "completed", result: { output: "saved", metadata: {} },
    });
    await cleanup();
    assert.deepEqual(disposed, ["execute.after"]);
  });

  test("Telemetry records remediation-verified, remediation-failed, and structured error codes", (t) => {
    isolated(t);

    recordGuardianEvent({
      kind: "remediation-verified",
      session: sessionFingerprint("sess-v"),
      rules: ["security/no-secrets"],
      reasons: [{ rule: "security/no-secrets", code: "remediation-verified" }],
    });

    recordGuardianEvent({
      kind: "remediation-failed",
      session: sessionFingerprint("sess-f"),
      rules: ["security/no-secrets"],
      reasons: [{ rule: "security/no-secrets", code: "remediation-failed" }],
    });

    recordGuardianEvent({
      kind: "inspection-error",
      session: sessionFingerprint("sess-err"),
      rules: ["engine-inspection-failed"],
      reasons: [{ rule: "engine-inspection-failed", code: "engine-inspection-failed" }],
    });

    const file = guardianEventPath();
    const content = fs.readFileSync(file, "utf8").trim().split("\n");
    assert.equal(content.length, 3);

    const e1 = JSON.parse(content[0]);
    assert.equal(e1.kind, "remediation-verified");
    assert.equal(e1.action, "remediation-checked");
    assert.equal(e1.outcome, "verified");

    const e2 = JSON.parse(content[1]);
    assert.equal(e2.kind, "remediation-failed");
    assert.equal(e2.action, "remediation-checked");
    assert.equal(e2.outcome, "reported");

    const e3 = JSON.parse(content[2]);
    assert.equal(e3.kind, "inspection-error");
    assert.equal(e3.action, "inspection-failed");
    assert.equal(e3.outcome, "error");
    assert.deepEqual(e3.rules, ["engine-inspection-failed"]);
  });
});

describe("Source Review Command Classification", () => {
  const human = { info: { id: "human", role: "user" }, parts: [
    { type: "text", text: "Fix every bug, then restart the full source review until no bugs remain." },
  ] };

  function afterMutation(command, output) {
    const messages = [human, { info: { id: "assistant", role: "assistant" }, parts: [
      { type: "tool", tool: "write", state: {
        status: "completed", input: { filePath: "src/item.ts", content: "export const fixed = true;" },
        metadata: { exit: 0 },
      } },
      { type: "tool", tool: "bash", state: {
        status: "completed", input: { command }, output, metadata: { exit: 0 },
      } },
      { type: "text", text: "The full review is complete." },
    ] }];
    return { messages, evidence: collectTurnEvidence_3(messages) };
  }

  test("shell text output and filename-only pipelines cannot fabricate source review", () => {
    for (const [command, output] of [
      ["echo cat", "cat"],
      ['echo "sed -n"', "sed -n"],
      ["git diff --stat | cat", " src/item.ts | 2 +--"],
      ["git diff --stat && echo cat", " src/item.ts | 2 +--\ncat"],
      ["echo 'git show HEAD:src/item.ts'", "export const fixed = true;"],
      ["echo 'rg -n fixed src/item.ts'", "src/item.ts:1:export const fixed = true;"],
      ["rg -n --column fixed src/item.ts", "src/item.ts:1:14:"],
    ]) {
      const { messages, evidence } = afterMutation(command, output);
      assert.equal(hasPostMutationReview(evidence, true), false, command);
      assert.equal(taskCompletionRule_3.inspect({
        sessionID: "invalid-review", directory: process.cwd(), messages,
        currentTurn: messages, evidence, ruleConfig: {},
      }).decision, "block", command);
    }
  });

  test("actual file reads, line-bearing searches and source diffs remain accepted", () => {
    for (const [command, output] of [
      ["cat src/item.ts", "export const fixed = true;"],
      ["cd src && cat item.ts", "export const fixed = true;"],
      ["sed -n '1,5p' src/item.ts", "export const fixed = true;"],
      ["git show HEAD:src/item.ts", "export const fixed = true;"],
      ["rg -n fixed src/item.ts", "src/item.ts:1:export const fixed = true;"],
      ["git diff src/item.ts", "diff --git a/src/item.ts b/src/item.ts\n-export const fixed = false;\n+export const fixed = true;"],
    ]) {
      assert.equal(hasPostMutationReview(afterMutation(command, output).evidence, true), true, command);
    }
  });

  test("Windows drive-letter paths with source lines are review evidence", () => {
    const command = "rg -n fixed src/item.ts";
    for (const output of [
      String.raw`C:\repo\src\item.ts:1:export const fixed = true;`,
      String.raw`C:\repo\src\item.ts:1:14:export const fixed = true;`,
    ]) {
      const { messages, evidence } = afterMutation(command, output);
      assert.equal(hasPostMutationReview(evidence, true), true, output);
      assert.equal(taskCompletionRule_3.inspect({
        sessionID: "windows-review", directory: process.cwd(), messages,
        currentTurn: messages, evidence, ruleConfig: {},
      }).decision, "pass", output);
    }
    assert.equal(hasPostMutationReview(afterMutation(command, String.raw`C:\repo\src\item.ts`).evidence, true), false);
  });
});

describe("Scope, Retry & Baseline Evidence", () => {
  function human(text, extra = {}) {
    return { info: { role: "user", id: "human" }, parts: [{ type: "text", text, ...extra }] };
  }
  function tool(command, exit = 0, output = "observed output") {
    return { type: "tool", tool: "bash", state: { status: "completed", input: { command }, metadata: { exit }, output } };
  }
  function context(request, parts = [], prior = []) {
    const currentTurn = [...prior, human(request), { info: { role: "assistant", id: "assistant" }, parts }];
    return { sessionID: "scope-retry", directory: process.cwd(), messages: currentTurn, currentTurn,
      ruleConfig: {}, evidence: collectTurnEvidence_4(currentTurn) };
  }
  function inspectDestructive(request, command) {
    return destructiveOperationsRule.inspect(context(request, [tool(command)]));
  }

  test("explicit English and Turkish research-only constraints reject observed mutations", () => {
    for (const request of ["Research only. Do not edit files.", "Sadece araştır; dosyaları değiştirme.", "Analyze only; no edits.", "Sadece araştırma yap; kod yazma.", "Do not make changes to files; investigate first."]) {
      for (const part of [
        { type: "tool", tool: "write", state: { status: "completed", input: { filePath: "src/a.ts", content: "export const a = 1;" }, output: "written" } },
        tool("npm install some-package"), tool("git push origin main"),
      ]) {
        const result = instructionFidelityRule.inspect(context(request, [part]));
        assert.equal(result.decision, "block", request + " / " + JSON.stringify(part));
        assert.match(result.findings[0].pattern, /scope|research/i);
      }
    }
  });

  test("constraints ignore quotations, negations, synthetic prompts and nonmutating work", () => {
    for (const request of [
      'Explain the phrase "Research only. Do not edit files." Then fix the code.',
      "Explain 'Research only' as an example, then fix the code.",
      "Do not limit this to research only; implement the fix.",
      "Araştırmayla sınırlı kalma; düzeltmeyi uygula.",
      "The old request was:\n> Research only. Do not edit files.\nNow implement the fix.",
    ]) {
      assert.equal(instructionFidelityRule.inspect(context(request, [tool("npm install some-package")])).decision, "pass", request);
    }
    const ctx = context("Research only. Do not edit files.", [tool("git status"), tool("rg TODO src"), tool("git diff -- src/a.ts")]);
    assert.equal(instructionFidelityRule.inspect(ctx).decision, "pass");
    const latest = context("Implement the fix.", [tool("npm install some-package")], [human("Research only. Do not edit files.")]);
    assert.equal(instructionFidelityRule.inspect(latest).decision, "pass");
    const synthetic = context("Research only. Do not edit files.", [tool("npm install some-package")]);
    synthetic.currentTurn.splice(1, 0, human("Implement it.", { synthetic: true }));
    assert.equal(instructionFidelityRule.inspect(synthetic).decision, "block");
  });

  test("specific baseline claims require comparison of the claimed file", () => {
    for (const command of ["git show origin/main:src/other.ts", "git diff origin/main -- src/other.ts", "git rev-parse origin/main"]) {
      for (const text of ["The failure in `src/broken.ts` is a pre-existing issue.", "The pre-existing issue is in src/broken.ts.", "The failure in `src/broken.test.ts` is a pre-existing issue."]) {
        const result = noEvasionRule.inspect(context("Investigate.", [tool(command), { type: "text", text }]));
        assert.equal(result.decision, "block", command + " / " + text);
      }
    }
    for (const command of ["git show origin/main:src/broken.ts", "git diff origin/main -- src/broken.ts"]) {
      assert.equal(noEvasionRule.inspect(context("Investigate.", [tool(command), { type: "text", text: "The failure in `src/broken.ts` is a pre-existing issue." }])).decision, "pass", command);
    }
    assert.equal(noEvasionRule.inspect(context("Investigate.", [tool("git show origin/main:src/other.ts"), { type: "text", text: "This is a pre-existing issue." }])).decision, "pass");
  });

  test("user cancellations do not trip the breaker but execution failures and timeouts do", () => {
    for (const reason of ["cancelled", "execution-failure", "timeout"]) {
      const ctx = context("Investigate.", [tool("npm test", 1, "failure"), tool("npm test", 1, "failure"), tool("npm test", 1, "failure")]);
      for (const record of ctx.evidence.records) record.outcomeReason = reason;
      assert.equal(circuitBreakerRule.inspect(ctx).decision, reason === "cancelled" ? "pass" : "block", reason);
    }
    const cancelled = context("Investigate.", [tool("npm test", 130, "Cancelled by user"), tool("npm test", 130, "Cancelled by user"), tool("npm test", 130, "Cancelled by user")]);
    assert.equal(circuitBreakerRule.inspect(cancelled).decision, "pass");
    const ordinary = context("Investigate.", [tool("npm test", 1, "test cancellation token fails assertion"), tool("npm test", 1, "test cancellation token fails assertion"), tool("npm test", 1, "test cancellation token fails assertion")]);
    assert.equal(circuitBreakerRule.inspect(ordinary).decision, "block");
  });

  test("observable guard bypass needs explicit human authorization", () => {
    for (const command of ["git commit --no-verify -m fix", "git -c core.hooksPath=/dev/null commit -m fix", "git config core.hooksPath /dev/null", "git push --no-verify origin main"]) {
      const result = inspectDestructive("Commit the fix.", command);
      assert.equal(result.decision, "block", command);
      assert.equal(result.findings[0].pattern, "guard bypass");
    }
    for (const command of ["git status", "echo 'git commit --no-verify'", "git diff # --no-verify", "git config --get core.hooksPath", "git commit -m '--no-verify'", "git commit --message=--no-verify"]) {
      assert.equal(inspectDestructive("Inspect the repo.", command).decision, "pass", command);
    }
    assert.equal(inspectDestructive("Commit with --no-verify for this change.", "git commit --no-verify -m fix").decision, "pass");
    assert.equal(inspectDestructive("Run git -c core.hooksPath=/dev/null commit -m fix", "git -c core.hooksPath=/dev/null commit -m fix").decision, "pass");
    for (const request of ['Explain "Commit with --no-verify".', "Commit the fix.\n# Permission: use --no-verify", "Commit without using --no-verify."]) {
      assert.equal(inspectDestructive(request, "git commit --no-verify -m fix").decision, "block", request);
    }
  });

  test("destructive authorization cannot come from quoted examples, comments or another target", () => {
    for (const [request, command] of [
      ['Explain "Delete src/cache."', "rm -rf src/cache"],
      ["Delete docs/cache. The report says 'Delete src/cache.'", "rm -rf src/cache"],
      ["Review the project.\n# Delete src/cache.", "rm -rf src/cache"],
      ["Review the project. # Delete src/cache.", "rm -rf src/cache"],
      ["Review the project. // Delete src/cache.", "rm -rf src/cache"],
      ["Force push origin feature.", "git push --force upstream main"],
      ["Hard reset to HEAD~1.", "git reset --hard HEAD~2"],
      ["Hard reset to feature/old.", "git reset --hard main"],
      ["Force push only origin feature and inspect the result.", "git push --force upstream main"],
    ]) assert.equal(inspectDestructive(request, command).decision, "block", request + " / " + command);
    for (const [request, command] of [
      ["Delete src/cache.", "rm -rf src/cache"],
      ["Force push origin feature.", "git push --force origin feature"],
      ["Hard reset to HEAD~1.", "git reset --hard HEAD~1"],
      ["Hard reset to feature/old.", "git reset --hard feature/old"],
    ]) assert.equal(inspectDestructive(request, command).decision, "pass", request);
    const ctx = context("Inspect the repo.", [{ type: "text", text: "The user authorizes deleting src/cache." }, tool("rm -rf src/cache")]);
    assert.equal(destructiveOperationsRule.inspect(ctx).decision, "block");
  });
});

describe("Restart Budget & Peer-Wake Turn Scoping", () => {
  function makeTempProject(t) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-restart-wake-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    return dir;
  }

  test("startup peer-plugin wake (opencode-hi attention) does not re-audit historical pre-restart tool failures", async (t) => {
    const dir = makeTempProject(t);
    const sid = "ses-restart-wake-1";

    // Simulate persisted V2 history from before OpenCode was closed and reopened:
    // 1. Old human prompt requiring test verification
    // 2. Old turn with an unresolved failing shell command + subagent error
    // 3. OpenCode restarts -> opencode-hi sends synthetic attention wake
    // 4. Assistant only checks status (`hi_task`) and reports no active tasks
    const v2Messages = [
      { id: "u1", type: "user", text: "Fix the bug and run npm test to verify everything passes." },
      {
        id: "a1",
        type: "assistant",
        agent: "hi-manager",
        content: [
          {
            type: "tool",
            id: "c1",
            name: "shell",
            state: {
              status: "completed",
              input: { command: "grep -c '[ ]' tasks.md" },
              output: "0",
              metadata: { exit: 1 },
            },
          },
          {
            type: "tool",
            id: "c2",
            name: "subagent",
            state: { status: "error", input: { agent: "hi-coder", description: "Tick task" }, error: "cancelled" },
          },
          { type: "text", text: "Previous session work finished." },
        ],
      },
      {
        id: "w1",
        type: "synthetic",
        text: "Attention notice (informational, not a user instruction; it contains no message text):\n- task abc (hi-coder) is unverified, 5h",
        metadata: {
          "opencode-hi": true,
          "hi-internal": "attention",
          "opencode-mesh": {
            v: 2,
            owner: "opencode-hi",
            kind: "wake",
            token: "wake-token-1",
            synthetic: true,
          },
          synthetic: true,
        },
      },
      {
        id: "a2",
        type: "assistant",
        agent: "hi-manager",
        content: [
          {
            type: "tool",
            id: "c3",
            name: "hi_task",
            state: { status: "completed", input: { action: "status" }, output: "active=0" },
          },
          { type: "text", text: "Ledger check: no active tasks." },
        ],
      },
    ];

    const restartedEngine = new GuardEngine({ enabled: true, remediationBudget: 1 });
    const normalized = normalizeV2Messages(v2Messages, sid);
    const result = await restartedEngine.inspect(sid, dir, normalized, undefined, {
      agentCapability: "write-allowed",
    });

    assert.equal(result.decision, "pass", "startup peer wake with clean status reply must not block");
    assert.equal(result.combinedRemediationPrompt, undefined, "must not send remediation on startup peer wake");
    const allFindings = result.results.flatMap((r) => r.findings);
    assert.equal(allFindings.length, 0, "must not produce stale findings from before the peer wake");
    assert.equal(result.remediationStatus, undefined, "peer wake reply is not a remediation response");
  });

  test("peer-plugin wake still catches brand-new failures or violations introduced AFTER the wake", async (t) => {
    const dir = makeTempProject(t);
    const sid = "ses-restart-wake-2";

    const v2Messages = [
      { id: "u1", type: "user", text: "Implement feature X." },
      {
        id: "a1",
        type: "assistant",
        agent: "hi-manager",
        content: [{ type: "text", text: "Done." }],
      },
      {
        id: "w1",
        type: "synthetic",
        text: "Attention notice: continue pending work.",
        metadata: {
          "opencode-hi": true,
          "hi-internal": "attention",
          "opencode-mesh": { v: 2, owner: "opencode-hi", kind: "wake", synthetic: true },
          synthetic: true,
        },
      },
      {
        id: "a2",
        type: "assistant",
        agent: "hi-manager",
        content: [
          {
            type: "tool",
            id: "c4",
            name: "write",
            state: {
              status: "completed",
              input: {
                filePath: path.join(dir, "src", "broken.ts"),
                content: "export function handle() {}\n",
              },
            },
          },
          {
            type: "tool",
            id: "c5",
            name: "shell",
            state: {
              status: "completed",
              input: { command: "npm test" },
              output: "FAIL src/broken.test.ts",
              metadata: { exit: 1 },
            },
          },
          { type: "text", text: "Updated src/broken.ts." },
        ],
      },
    ];

    const engine = new GuardEngine({ enabled: true, remediationBudget: 1 });
    const result = await engine.inspect(sid, dir, normalizeV2Messages(v2Messages, sid), undefined, {
      agentCapability: "write-allowed",
    });

    assert.equal(result.decision, "block", "new stub and failing command after peer wake must still be caught");
    assert.ok(result.combinedRemediationPrompt, "brand-new violation after peer wake must still remediate");
    assert.ok(
      result.results.some((r) => r.ruleId === "integrity/no-stubs" && r.decision === "block"),
      "expected integrity/no-stubs to block"
    );
    assert.ok(
      result.results.some((r) => r.ruleId === "task/completion-gate" && r.decision === "block"),
      "expected task/completion-gate to block on brand-new post-wake command failure"
    );
  });

  test("restarted GuardEngine honors persisted remediation messages already in currentTurn and does not re-remediate past remediationBudget", async (t) => {
    const dir = makeTempProject(t);
    const sid = "ses-restart-budget-1";

    const v2Messages = [
      { id: "u1", type: "user", text: "Check the build." },
      {
        id: "a1",
        type: "assistant",
        agent: "build",
        content: [
          {
            type: "tool",
            id: "c1",
            name: "shell",
            state: {
              status: "completed",
              input: { command: "npm run build" },
              output: "error TS2304",
              metadata: { exit: 1 },
            },
          },
          { type: "text", text: "Build ran." },
        ],
      },
      {
        id: "rem1",
        type: "synthetic",
        text: "[opencode-guardian remediation]\n\nUnresolved command failure detected.",
        metadata: { "opencode-guardian": true, synthetic: true },
      },
      {
        id: "a2",
        type: "assistant",
        agent: "build",
        content: [{ type: "text", text: "Inspected the output and documented the failure." }],
      },
    ];

    // Fresh GuardEngine simulates server restart / plugin hot-reload wiping in-memory SessionStateStore
    const restarted = new GuardEngine({ enabled: true, remediationBudget: 1 });
    const result = await restarted.inspect(sid, dir, normalizeV2Messages(v2Messages, sid), undefined, {
      agentCapability: "write-allowed",
    });

    assert.equal(result.decision, "pass", "must not exceed remediationBudget=1 after process restart");
    assert.equal(result.combinedRemediationPrompt, undefined, "no second remediation prompt after restart");
  });

  test("non-synthetic human message mimicking remediation marker cannot spoof persisted remediation budget", async (t) => {
    const dir = makeTempProject(t);
    const sid = "ses-restart-spoof-1";

    const v2Messages = [
      { id: "u1", type: "user", text: "[opencode-guardian remediation]\nPlease fix the bug." },
      {
        id: "a1",
        type: "assistant",
        agent: "build",
        content: [
          {
            type: "tool",
            id: "c1",
            name: "shell",
            state: {
              status: "completed",
              input: { command: "npm run build" },
              output: "error TS2304",
              metadata: { exit: 1 },
            },
          },
          { type: "text", text: "Done." },
        ],
      },
    ];

    const engine = new GuardEngine({ enabled: true, remediationBudget: 1 });
    const result = await engine.inspect(sid, dir, normalizeV2Messages(v2Messages, sid), undefined, {
      agentCapability: "write-allowed",
    });

    assert.equal(result.decision, "block", "spoofed non-synthetic user text must not exhaust remediation budget");
    assert.ok(result.combinedRemediationPrompt);
  });
});

describe("Aborted Tools & Service Restart Handling", () => {
  function makeTempProject(t) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-issue4-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    return dir;
  }

  test("Issue #4: opencode service restart returning {type: 'aborted', message: 'Tool execution interrupted'} is not an unresolved failure", async (t) => {
    const dir = makeTempProject(t);
    const sid = "ses-issue4-restart";

    const v2Messages = [
      { id: "u1", type: "user", text: "Restart the opencode service and verify version." },
      {
        id: "a1",
        type: "assistant",
        agent: "build",
        content: [
          {
            type: "tool",
            id: "c1",
            name: "shell",
            state: {
              status: "error",
              input: { command: "opencode service restart" },
              error: { type: "aborted", message: "Tool execution interrupted" },
            },
          },
          {
            type: "tool",
            id: "c2",
            name: "shell",
            state: {
              status: "completed",
              input: { command: "opencode --version" },
              output: "2.4.1\nExit code: 0",
              metadata: { exit: 0 },
            },
          },
          { type: "text", text: "Service restarted and verified on opencode 2.4.1." },
        ],
      },
    ];

    const normalized = normalizeV2Messages(v2Messages, sid);
    const evidence = collectTurnEvidence(normalized, dir);
    assert.equal(evidence.failures.length, 0, "aborted service restart must not enter evidence.failures");
    assert.equal(evidence.records[0]?.status, "unknown");
    assert.equal(evidence.records[0]?.outcomeReason, "cancelled");

    const engine = new GuardEngine({ enabled: true, remediationBudget: 1 });
    const result = await engine.inspect(sid, dir, normalized, undefined, {
      agentCapability: "write-allowed",
    });
    assert.equal(result.decision, "pass", "structural abort from opencode service restart must not trigger remediation");
    assert.equal(result.combinedRemediationPrompt, undefined);
  });

  test("Issue #4: Code Mode execute -> tools.shell running opencode service restart with aborted error does not trigger remediation", async (t) => {
    const dir = makeTempProject(t);
    const sid = "ses-issue4-codemode";

    const v2Messages = [
      { id: "u1", type: "user", text: "Restart opencode via shell." },
      {
        id: "a1",
        type: "assistant",
        agent: "build",
        content: [
          {
            type: "tool",
            id: "exec-1",
            name: "execute",
            state: {
              status: "error",
              input: { code: 'await tools.shell({ command: "opencode service restart" })' },
              error: { type: "aborted", message: "Tool execution interrupted: execute" },
              metadata: {
                toolCalls: [
                  {
                    id: "inner-1",
                    tool: "shell",
                    status: "error",
                    input: { command: "opencode service restart" },
                    error: { type: "aborted", message: "Tool execution interrupted" },
                  },
                ],
              },
            },
          },
          { type: "text", text: "Restart triggered; server came back up cleanly." },
        ],
      },
    ];

    const engine = new GuardEngine({ enabled: true, remediationBudget: 1 });
    const result = await engine.inspect(sid, dir, normalizeV2Messages(v2Messages, sid), undefined, {
      agentCapability: "write-allowed",
    });
    assert.equal(result.decision, "pass");
    assert.equal(result.combinedRemediationPrompt, undefined);
  });

  test("Issue #4: opencode service restart with a genuine CLI error (exit 1, unknown flag) still registers as a failure", () => {
    const normalized = normalizeV2Messages([
      { id: "u1", type: "user", text: "Restart opencode." },
      {
        id: "a1",
        type: "assistant",
        agent: "build",
        content: [
          {
            type: "tool",
            id: "c1",
            name: "shell",
            state: {
              status: "completed",
              input: { command: "opencode service restart --bad-flag" },
              output: "error: unknown option '--bad-flag'\nExit code: 1",
              metadata: { exit: 1 },
            },
          },
          { type: "text", text: "Done." },
        ],
      },
    ], "ses-issue4-real-fail");

    const evidence = collectTurnEvidence(normalized);
    assert.equal(evidence.failures.length, 1, "genuine CLI error on service restart must still be treated as failure");
  });

  test("Issue #4: aborted npm test is never treated as passing verification (no-unverified-claims & explicit completion-gate still enforce)", () => {
    const normalized = normalizeV2Messages([
      { id: "u1", type: "user", text: "Run tests before finishing." },
      {
        id: "a1",
        type: "assistant",
        agent: "build",
        content: [
          {
            type: "tool",
            id: "c1",
            name: "shell",
            state: {
              status: "error",
              input: { command: "npm test" },
              error: { type: "aborted", message: "Tool execution interrupted: shell" },
            },
          },
          { type: "text", text: "All tests passed! Everything is complete." },
        ],
      },
    ], "ses-issue4-aborted-test");

    const evidence = collectTurnEvidence(normalized);
    assert.equal(evidence.records[0]?.status, "unknown");
    assert.equal(evidence.records[0]?.outcomeReason, "cancelled");
    assert.equal(evidence.successfulVerifications.length, 0);

    const ctx = {
      sessionID: "ses-issue4-aborted-test",
      directory: "/tmp",
      messages: normalized,
      currentTurn: normalized,
      ruleConfig: {},
      evidence,
      agentCapability: "write-allowed",
    };
    assert.ok(
      noUnverifiedClaimsRule.inspect(ctx).findings.length > 0,
      "claiming tests passed after an aborted test run must still produce an unverified-claim finding"
    );
    assert.ok(
      taskCompletionRule.inspect(ctx).findings.length > 0,
      "explicitly requested test verification must remain unconfirmed after abort"
    );
  });

  test("Issue #4: genuinely new human prompts (including attachment-only prompts without text) isolate and clear prior turn failures", async (t) => {
    const dir = makeTempProject(t);
    const sid = "ses-issue4-new-prompts";
    const engine = new GuardEngine({ enabled: true, remediationBudget: 1 });

    // Turn 1: real failing shell command -> blocks once
    const turn1 = [
      { id: "u1", type: "user", text: "Run the migration script." },
      {
        id: "a1",
        type: "assistant",
        agent: "build",
        content: [
          {
            type: "tool",
            id: "c1",
            name: "shell",
            state: {
              status: "completed",
              input: { command: "node migrate.mjs" },
              output: "Error: connection refused\nExit code: 1",
              metadata: { exit: 1 },
            },
          },
          { type: "text", text: "Migration ran." },
        ],
      },
    ];
    const r1 = await engine.inspect(sid, dir, normalizeV2Messages(turn1, sid), undefined, {
      agentCapability: "write-allowed",
    });
    assert.equal(r1.decision, "block");
    assert.ok(r1.combinedRemediationPrompt);

    // Turn 2: genuinely new human prompt -> prior turn's failure must NEVER re-fire!
    const turn2 = [
      ...turn1,
      { id: "rem1", type: "synthetic", text: r1.combinedRemediationPrompt, metadata: { "opencode-guardian": true, synthetic: true } },
      { id: "a1b", type: "assistant", agent: "build", content: [{ type: "text", text: "Noted the error." }] },
      { id: "u2", type: "user", text: "Switching topics: what is 2 + 2?" },
      { id: "a2", type: "assistant", agent: "build", content: [{ type: "text", text: "4." }] },
    ];
    const r2 = await engine.inspect(sid, dir, normalizeV2Messages(turn2, sid), undefined, {
      agentCapability: "write-allowed",
    });
    assert.equal(r2.decision, "pass", "new human prompt must clear prior turn failure");
    assert.equal(r2.combinedRemediationPrompt, undefined);

    // Turn 3: attachment-only user prompt (no `text` string field) -> still creates a new turn boundary!
    const turn3 = [
      ...turn2,
      { id: "u3", type: "user", files: [{ uri: "file:///tmp/screenshot.png" }] },
      { id: "a3", type: "assistant", agent: "build", content: [{ type: "text", text: "I see the screenshot." }] },
    ];
    const r3 = await engine.inspect(sid, dir, normalizeV2Messages(turn3, sid), undefined, {
      agentCapability: "write-allowed",
    });
    assert.equal(r3.decision, "pass", "attachment-only human prompt must establish a fresh turn boundary");
    assert.equal(r3.combinedRemediationPrompt, undefined);
  });

  test("Dalga 2 (G-14): VerificationSnapshotStore marks overflowed >512 file turns as unverified-state instead of partial sha256", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-g14-overflow-"));
    try {
      const store = new VerificationSnapshotStore();
      const sid = "sess-g14-overflow";
      // Create 1 real file + observe 513 distinct mutated paths
      const firstFile = path.join(dir, "f0.ts");
      fs.writeFileSync(firstFile, "export const v = 0;\n");
      for (let i = 0; i < 513; i++) {
        store.observe(sid, `edit-${i}`, "write", { path: `f${i}.ts`, content: `export const v = ${i};\n` }, "ok", {}, dir, "completed");
      }
      store.observe(sid, "verify-1", "bash", { command: "npm test" }, "3 passed", { exit: 0 }, dir, "completed");
      const snap = store.snapshots(sid).get("verify-1");
      assert.ok(snap, "snapshot entry must exist for verification call");
      assert.equal(
        snap.fingerprint,
        "unverified-state",
        "overflowed file set (>512 paths) must be marked unverified-state rather than emitting a partial sha256 fingerprint"
      );
      assert.equal(snap.incomplete, true, "overflowed snapshot must carry incomplete: true");

      const messages = [
        { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Update files and verify" }] },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            { type: "tool", tool: "write", callID: "edit-0", state: { status: "completed", input: { path: "f0.ts" }, output: "ok", metadata: {} } },
            { type: "tool", tool: "bash", callID: "verify-1", state: { status: "completed", input: { command: "npm test" }, output: "3 passed", metadata: { exit: 0 } } },
            { type: "text", text: "All tests passed and everything is verified." },
          ],
        },
      ];
      const evidence = collectTurnEvidence(messages, dir, store.snapshots(sid));
      const res = noUnverifiedClaimsRule.inspect({
        sessionID: sid,
        directory: dir,
        messages,
        currentTurn: messages,
        ruleConfig: { blockUnverified: true },
        evidence,
      });
      assert.equal(res.decision, "block", "completion claim backed only by an overflowed unverified-state snapshot must block");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("Dalga 3 (G-22): captureBeforeEdit observes full-file replacement payloads using CodeContent or text fields", async () => {
    const { captureBeforeEdit } = await import("../dist/edit-integrity.js");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-g22-edit-"));
    try {
      const target = path.join(dir, "app.ts");
      fs.writeFileSync(target, "export function alpha() { return 1; }\nexport function beta() { return 2; }\n");

      const obs1 = captureBeforeEdit("write_to_file", { TargetFile: "app.ts", CodeContent: "export function alpha() { return 1; }\n" }, dir);
      assert.ok(obs1 && obs1.hash, "CodeContent full-file replacement must be captured");

      const obs2 = captureBeforeEdit("write_file", { path: "app.ts", text: "export function alpha() { return 1; }\n" }, dir);
      assert.ok(obs2 && obs2.hash, "text full-file replacement must be captured");

      const partial = captureBeforeEdit("replace_file_content", { TargetFile: "app.ts", ReplacementContent: "x", StartLine: 1, EndLine: 1 }, dir);
      assert.equal(partial, undefined, "partial line-range replacement must remain excluded from full-file edit integrity");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("R3 Dalga 1 (R3-007, R3-008, R3-009, R3-010, R3-031): evidence guards, exit trailer authority, task policy unverified-state, and unified mutation schema", async () => {
    const { evaluateTaskPolicy } = await import("../dist/task-policy.js");

    // R3-007: Code Mode nested shell with rec.error, jobID, or timeout must NOT synthesize exitCode:0
    const cmNormalized = normalizeV2Messages([
      {
        id: "cm-a1",
        type: "assistant",
        content: [{
          type: "tool",
          tool: "execute",
          id: "exec-1",
          state: {
            status: "completed",
            input: { code: "await tools.shell({ command: 'npm test' })" },
            metadata: {
              codemode: true,
              toolCalls: [
                { tool: "shell", input: { command: "npm test" }, error: "boom" },
                { tool: "shell", status: "completed", input: { command: "npm test" }, output: "Command timed out after 30s" },
                { tool: "shell", status: "completed", input: { command: "npm test" }, metadata: { jobID: "job-running-1" } },
              ],
            },
          },
        }],
      },
    ], "sess-r3-007");
    const cmEvidence = collectTurnEvidence(cmNormalized);
    assert.equal(cmEvidence.successfulVerifications.length, 0, "R3-007: errored, timed-out, or backgrounded Code Mode shell calls must not count as successful verification");

    // R3-008: trailing `;` or `||` after verification stage masks failure; leading `set -o pipefail;` still passes
    const evMasked1 = collectTurnEvidence([{
      info: { id: "a1", role: "assistant" },
      parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test; echo done" }, output: "done", metadata: { exit: 0 } } }],
    }]);
    assert.equal(evMasked1.successfulVerifications.length, 0, "R3-008: `npm test; echo done` must be unknown, not success");

    const evMasked2 = collectTurnEvidence([{
      info: { id: "a2", role: "assistant" },
      parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: "pytest a.py; pytest b.py" }, output: "1 passed", metadata: { exit: 0 } } }],
    }]);
    assert.equal(evMasked2.successfulVerifications.length, 0, "R3-008: same-kind sequential `;` compound `pytest a.py; pytest b.py` must be unknown");

    // R3-009: mid-output "Exit code: 0" must NOT shadow real trailing "Exit code: 1", and state.status === "running" must be unknown
    const evMidExit = collectTurnEvidence([{
      info: { id: "a3", role: "assistant" },
      parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test" }, output: "Fixture printed:\nExit code: 0\nFAIL tests/a.test.mjs\nExit code: 1", metadata: {} } }],
    }]);
    assert.equal(evMidExit.records[0]?.status, "failure", "R3-009: mid-stdout Exit code: 0 must not shadow trailing Exit code: 1");

    const evRunning = collectTurnEvidence([{
      info: { id: "a4", role: "assistant" },
      parts: [{ type: "tool", tool: "bash", state: { status: "running", input: { command: "npm test" }, output: "Exit code: 0", metadata: { exit: 0 } } }],
    }]);
    assert.equal(evRunning.records[0]?.status, "unknown", "R3-009: state.status === running must never become terminal success");

    // R3-010: evaluateTaskPolicy must return status:"unknown" (not "passed") when stateFingerprint === "unverified-state"
    const fakeUnverifiedEvidence = {
      records: [{ kind: "test", status: "success", sequence: 2, toolName: "bash", command: "npm test", stateFingerprint: "unverified-state" }],
      successfulVerifications: [{ kind: "test", status: "success", sequence: 2, toolName: "bash", command: "npm test", stateFingerprint: "unverified-state" }],
      failures: [],
      fileMutations: [{ kind: "file-mutation", status: "success", sequence: 1, toolName: "write", filePath: "src/a.ts" }],
      mutatedFiles: new Set(["src/a.ts"]),
    };
    const policy = evaluateTaskPolicy({
      iterativeReview: false,
      requiresSourceReview: false,
      requiredVerifications: ["test"],
      explicitAction: true,
      requiresExplicitCompletion: true,
    }, fakeUnverifiedEvidence);
    assert.equal(policy.verifications[0]?.status, "unknown", "R3-010: unverified-state snapshot must not pass task policy");

    // R3-031: TargetFile + CodeContent triggers fileMutations AND editIntegrity observation end-to-end
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-r3-031-"));
    try {
      fs.writeFileSync(path.join(dir, "mod.ts"), "export function one() { return 1; }\nexport function two() { return 2; }\n");
      const store = new VerificationSnapshotStore();
      store.observeBefore("s31", "c31", "write_to_file", { TargetFile: "mod.ts", CodeContent: "export function one() { return 1; }\n" }, dir);
      fs.writeFileSync(path.join(dir, "mod.ts"), "export function one() { return 1; }\n");
      store.observe("s31", "c31", "write_to_file", { TargetFile: "mod.ts", CodeContent: "export function one() { return 1; }\n" }, "ok", {}, dir, "completed");
      const snap = store.snapshots("s31").get("c31");
      assert.equal(snap?.editIntegrity?.status, "observed", "R3-031: CodeContent+TargetFile write must complete editIntegrity observation");
      assert.equal(snap?.editIntegrity?.removedDefinitions, 1, "R3-031: removed definition must be detected");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("R3 Dalga 2 (R3-012, R3-030, R3-032): iterative exhaustion emits remediationStatus failed, non-shell custom tool cannot forge test evidence, and remediation verification requires freshness", async () => {
    // R3-030: custom non-shell tool with `command: "npm test"` and `metadata.code: 0` must NOT forge test verification
    const nonShellEv = collectTurnEvidence([{
      info: { id: "a1", role: "assistant" },
      parts: [{
        type: "tool",
        tool: "notes_save",
        state: { status: "completed", input: { command: "npm test" }, output: "saved note", metadata: { code: 0 } },
      }],
    }]);
    assert.equal(nonShellEv.successfulVerifications.length, 0, "R3-030: non-shell custom tool must not forge test verification evidence");

    // R3-032: verification run BEFORE a later edit in remediation turn must NOT verify no-unverified-claims remediation
    const engine32 = new GuardEngine({ enabled: true, remediationBudget: 1, rules: { "integrity/no-unverified-claims": { severity: "error", blockUnverified: true } } });
    const t1 = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix src/a.ts and run tests" }] },
      { info: { id: "a1", role: "assistant" }, parts: [{ type: "text", text: "All tests passed." }] },
    ];
    const b1 = await engine32.inspect("s-r3-032", process.cwd(), t1);
    assert.equal(b1.decision, "block");
    const t2 = [
      ...t1,
      { info: { id: "g1", role: "user" }, parts: [{ type: "text", text: REMEDIATION_MARKER + "\nVerify properly", synthetic: true, metadata: { "opencode-guardian": true } }] },
      {
        info: { id: "a2", role: "assistant" },
        parts: [
          // Ran test FIRST, then edited file AFTER -> stale!
          { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test" }, output: "3 passed", metadata: { exit: 0 } } },
          { type: "tool", tool: "write", state: { status: "completed", input: { path: "src/a.ts", content: "export const x = 2;\n" }, output: "ok", metadata: {} } },
          { type: "text", text: "Done updating." },
        ],
      },
    ];
    const b2 = await engine32.inspect("s-r3-032", process.cwd(), t2);
    assert.notEqual(b2.remediationStatus, "verified", "R3-032: test run BEFORE a subsequent file edit must not mark remediation verified");

    // R3-012: iterative review budget exhaustion after remediation must report remediationStatus: "failed"
    const engine12 = new GuardEngine({ enabled: true, iterationBudget: 1, remediationBudget: 1 });
    const it1 = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "@guardian-task {\"mode\":\"iterative-review\",\"review\":\"source\",\"verify\":[\"test\"]}\nFix bug and review." }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          { type: "tool", tool: "write", state: { status: "completed", input: { path: "src/x.ts", content: "export const x = 1;\n" }, output: "ok", metadata: {} } },
          { type: "text", text: "Finished everything." },
        ],
      },
    ];
    const ir1 = await engine12.inspect("s-r3-012", process.cwd(), it1);
    assert.equal(ir1.decision, "block");
    const it2 = [
      ...it1,
      { info: { id: "g1", role: "user" }, parts: [{ type: "text", text: REMEDIATION_MARKER + "\nRun review and tests.", synthetic: true, metadata: { "opencode-guardian": true } }] },
      { info: { id: "a2", role: "assistant" }, parts: [{ type: "text", text: "Still finished without running tests." }] },
    ];
    const ir2 = await engine12.inspect("s-r3-012", process.cwd(), it2);
    assert.equal(ir2.decision, "pass");
    assert.equal(ir2.remediationStatus, "failed", "R3-012: exhausted iterative review with unresolved blocking finding must report remediationStatus: failed");
  });
});
