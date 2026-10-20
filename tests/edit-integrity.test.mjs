import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Guardian, { VerificationSnapshotStore, collectTurnEvidence, noTruncationRule, evaluatePreflight, readGuardianActivity } from '../dist/index.js';

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

for (const version of ['v1', 'v2']) test(`${version} adapter delivers observed edit integrity to idle engine inspection`, async t => {
  for (const capture of [true, false]) {
    const dir = project(t);
    fs.writeFileSync(path.join(dir, 'opencode-guardian.json'), JSON.stringify({ secrets: { enabled: false }, updateNotice: { enabled: false } }));
    const input = { path: 'src/a.ts', content: 'export function alpha() { return 1; }' };
    fs.writeFileSync(path.join(dir, input.path), before);
    const messages = [{ info: { id: 'u', role: 'user' }, parts: [{ type: 'text', text: 'Fix alpha.' }] },
      { info: { id: 'a', role: 'assistant' }, parts: [{ type: 'tool', tool: 'write_file', callID: 'w', state: { status: 'completed', input } }] }];
    let cleanup;
    if (version === 'v1') {
      const hooks = await Guardian.server({ directory: dir, client: { session: {
        async get() { return { data: { id: 's' } }; },
        async messages() { return { data: messages }; },
        async promptAsync() { assert.fail('advisory content loss must not start remediation'); },
      } } });
      cleanup = hooks.dispose;
      try {
        if (capture) await hooks['tool.execute.before']({ tool: 'write_file', sessionID: 's', callID: 'w' }, { args: input });
        fs.writeFileSync(path.join(dir, input.path), input.content);
        await hooks['tool.execute.after']({ tool: 'write_file', sessionID: 's', callID: 'w', args: input }, { output: 'written', metadata: {} });
        await hooks.event({ event: { type: 'session.idle', properties: { sessionID: 's' } } });
      } finally { await cleanup(); }
    } else {
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
