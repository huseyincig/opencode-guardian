import test from 'node:test';
import assert from 'node:assert/strict';
import { collectTurnEvidence, noStubsRule, noCheatRule, circuitBreakerRule, destructiveOperationsRule } from '../dist/index.js';

function ctx(input, filePath = 'src/a.ts', user = 'Implement the requested fix.') {
  const part = typeof input === 'string' ? { type: 'tool', tool: 'edit', state: { status: 'completed', input: { filePath, new_string: input } } } : input;
  const currentTurn = [{ info: { id: 'u', role: 'user' }, parts: [{ type: 'text', text: user }] }, { info: { id: 'a', role: 'assistant' }, parts: [part] }];
  return { sessionID: 'review', directory: process.cwd(), messages: currentTurn, currentTurn, ruleConfig: {}, evidence: collectTurnEvidence(currentTurn) };
}
function shell(command, exit = 0, output = '') { return { type: 'tool', tool: 'bash', state: { status: 'completed', input: { command }, metadata: { exit }, output } }; }

test('JavaScript private fields do not hide later executable stubs', () => {
  assert.equal(noStubsRule.inspect(ctx('class A { #x = 1; run() { throw new Error("not implemented"); } }')).decision, 'block');
  assert.equal(noStubsRule.inspect(ctx('# raise NotImplementedError()', 'src/a.py')).decision, 'pass');
});

test('a TypeScript object return type is not an empty function body', () => {
  assert.equal(noStubsRule.inspect(ctx('export function make(): {} { return { ok: true }; }')).decision, 'pass');
});

test('template interpolation is executable while literal template examples stay inert', () => {
  assert.equal(noCheatRule.inspect(ctx('const result = `${test.skip("broken", () => {})}`;', 'tests/a.test.ts')).decision, 'block');
  assert.equal(noStubsRule.inspect(ctx('const result = `${(() => { throw new Error("not implemented"); })()}`;')).decision, 'block');
  assert.equal(noCheatRule.inspect(ctx('const example = `test.skip("broken", () => {})`;', 'tests/a.test.ts')).decision, 'pass');
});

test('pytest collection failures still trip repeated-error protection', () => {
  const current = ctx(shell('pytest tests', 2, 'ERROR collecting tests/test_app.py\nModuleNotFoundError: missing'));
  current.currentTurn[1].parts = [current.currentTurn[1].parts[0], current.currentTurn[1].parts[0], current.currentTurn[1].parts[0]];
  current.evidence = collectTurnEvidence(current.currentTurn);
  assert.equal(circuitBreakerRule.inspect(current).decision, 'block');
});

test('hook-bypass authorization stays scoped to repository and remote', () => {
  for (const [request, command] of [
    ['Run git -C safe commit --no-verify -m fix', 'git -C other commit --no-verify -m fix'],
    ['Push with --no-verify to origin feature.', 'git push --no-verify upstream main'],
    ['Run git -C safe push --no-verify origin feature', 'git -C safe push --no-verify upstream main'],
  ]) assert.equal(destructiveOperationsRule.inspect(ctx(shell(command), undefined, request)).decision, 'block', command);
  assert.equal(destructiveOperationsRule.inspect(ctx(shell('git -C safe commit --no-verify -m fix'), undefined, 'Run git -C safe commit --no-verify -m fix')).decision, 'pass');
});

test('force-push authorization does not permit an additional refspec', () => {
  assert.equal(destructiveOperationsRule.inspect(ctx(shell('git push --force origin feature evil'), undefined,
    'Force push origin feature.')).decision, 'block');
});

test('short and env-wrapped Git hook bypasses need authorization', () => {
  for (const command of ['git commit -n -m fix', 'env CI=1 git commit --no-verify -m fix', 'CI=1 git commit --no-verify -m fix']) {
    assert.equal(destructiveOperationsRule.inspect(ctx(shell(command))).decision, 'block', command);
  }
  assert.equal(destructiveOperationsRule.inspect(ctx(shell('echo "git commit -n"'))).decision, 'pass');
});
