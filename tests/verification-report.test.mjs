import test from 'node:test';
import assert from 'node:assert/strict';
import { collectTurnEvidence, noUnverifiedClaimsRule, taskCompletionRule } from '../dist/index.js';

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
