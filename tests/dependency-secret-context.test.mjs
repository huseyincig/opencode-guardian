import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { noGhostDepsRule, clearDeclaredDepsCache } from '../dist/rules/no-ghost-deps.js';
import { noSecretsRule } from '../dist/rules/no-secrets.js';
import { sanitizeString } from '../dist/secrets/sanitizer.js';

function context(directory, filePath, content, ruleConfig = {}) {
  return {
    sessionID: 'dependency-secret-context', directory, messages: [], ruleConfig,
    currentTurn: [{ info: { id: 'edit', role: 'assistant' }, parts: [{
      type: 'tool', tool: 'write', state: { input: { filePath, content } },
    }] }],
  };
}

function project(t, extra = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-dependency-context-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    name: 'fixture-app', dependencies: { runtime: '1' },
    devDependencies: { tooling: '1', '@scope/dev-types': '1' }, ...extra,
  }));
  t.after(() => { clearDeclaredDepsCache(); fs.rmSync(root, { recursive: true, force: true }); });
  return root;
}

test('production imports of dev-only packages produce a nonblocking advisory by default', (t) => {
  const root = project(t);
  const result = noGhostDepsRule.inspect(context(root, 'src/service.ts', 'import value from "tooling/subpath";'));
  assert.equal(result.decision, 'pass');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].pattern, 'tooling');
  assert.match(result.findings[0].description, /devDependencies/);
});

test('strict production policy blocks runtime dev-only imports including require and dynamic import', (t) => {
  const root = project(t);
  for (const code of ['import x from "tooling";', 'const x = require("tooling");', 'const x = import("tooling");', 'export { x } from "tooling";']) {
    const result = noGhostDepsRule.inspect(context(root, 'src/service.ts', code, { productionOnly: true }));
    assert.equal(result.decision, 'block', code);
    assert.equal(result.findings[0].pattern, 'tooling');
  }
});

test('strict policy preserves valid type-only imports and exports from devDependencies', (t) => {
  const root = project(t);
  for (const code of [
    'import type { Shape } from "@scope/dev-types";',
    'import { type Shape, type Other as Alias } from "@scope/dev-types";',
    'export type { Shape } from "@scope/dev-types";',
    'export { type Shape } from "@scope/dev-types";',
  ]) {
    const result = noGhostDepsRule.inspect(context(root, 'src/service.ts', code, { productionOnly: true }));
    assert.equal(result.decision, 'pass', code);
    assert.equal(result.findings.length, 0, code);
  }
});

test('strict policy still rejects mixed type and runtime imports of dev-only packages', (t) => {
  const root = project(t);
  for (const code of [
    'import { type Shape, value } from "tooling";',
    'import { type Shape /* annotation */, value } from "tooling";',
    'import type from "tooling";',
  ]) {
    const result = noGhostDepsRule.inspect(context(root, 'src/service.ts', code, { productionOnly: true }));
    assert.equal(result.decision, 'block', code);
  }
});

test('strict policy preserves declarations, test dependencies and build tooling', (t) => {
  const root = project(t);
  for (const file of ['src/types.d.ts', 'src/types.d.mts', 'src/service.test.ts', 'src/service.spec.mts', 'tests/setup.ts', '__tests__/service.ts', 'scripts/build.mjs', 'vite.config.ts', 'eslint.config.js', 'test/setup.ts']) {
    const result = noGhostDepsRule.inspect(context(root, file, 'import value from "tooling";', { productionOnly: true }));
    assert.equal(result.decision, 'pass', file);
    assert.equal(result.findings.length, 0, file);
  }
});

test('strict policy accepts runtime, optional, peer and self dependencies', (t) => {
  const root = project(t, { peerDependencies: { peer: '1' }, optionalDependencies: { optional: '1' } });
  const code = ['runtime', 'peer', 'optional', 'fixture-app', 'node:fs'].map((name) => `import "${name}";`).join('\n');
  assert.equal(noGhostDepsRule.inspect(context(root, 'src/service.ts', code, { productionOnly: true })).decision, 'pass');
});

test('development exceptions do not permit undeclared dependencies or quoted fake imports', (t) => {
  const root = project(t);
  assert.equal(noGhostDepsRule.inspect(context(root, 'tests/service.ts', 'import value from "missing-library";', { productionOnly: true })).decision, 'block');
  const code = 'const example = `import value from "tooling";`; // import value from "missing-library";';
  assert.deepEqual(noGhostDepsRule.inspect(context(root, 'src/service.ts', code, { productionOnly: true })).findings, []);
});

test('production dependency cache follows manifest changes and nearest package boundaries', (t) => {
  const root = project(t);
  const input = context(root, 'src/service.ts', 'import value from "tooling";', { productionOnly: true });
  assert.equal(noGhostDepsRule.inspect(input).decision, 'block');
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ dependencies: { tooling: '1' } }));
  assert.equal(noGhostDepsRule.inspect(input).decision, 'pass');
  fs.mkdirSync(path.join(root, 'packages/nested'), { recursive: true });
  fs.writeFileSync(path.join(root, 'packages/nested/package.json'), JSON.stringify({ devDependencies: { tooling: '1' } }));
  assert.equal(noGhostDepsRule.inspect(context(root, 'packages/nested/src/service.ts', 'import "tooling";', { productionOnly: true })).decision, 'block');
});

// Values are deterministic synthetic fixtures, never provider-issued credentials.
const providers = [
  ['OpenAI', 'sk-proj-' + 'Ab9'.repeat(8)],
  ['GitHub personal', 'ghp_' + 'Ab9'.repeat(12)],
  ['GitHub OAuth', 'gho_' + 'Ab9'.repeat(12)],
  ['GitHub user', 'ghu_' + 'Ab9'.repeat(12)],
  ['GitHub server', 'ghs_' + 'Ab9'.repeat(12)],
  ['GitHub refresh', 'ghr_' + 'Ab9'.repeat(12)],
  ['GitHub fine grained', 'github_pat_' + 'Ab9_'.repeat(15)],
  ['Slack', 'xoxb-123456789012-123456789012-' + 'aB9'.repeat(8)],
  ['AWS', 'AKIA' + 'AB12'.repeat(4)],
  ['Google', 'AIza' + 'aB9_-'.repeat(7)],
  ['npm', 'npm_' + 'Ab9X'.repeat(8)],
  ['GitLab', 'glpat-' + 'Ab9_-'.repeat(5)],
  ['Stripe', 'sk_live_' + 'Ab9'.repeat(8)],
  ['JWT', 'eyJ' + 'aB9'.repeat(6) + '.eyJ' + 'aB9'.repeat(6) + '.' + 'aB9'.repeat(6)],
];

for (const [provider, value] of providers) {
  test(`${provider} credential formats are blocked on writes and redacted from plain output`, () => {
    const result = noSecretsRule.inspect(context('/tmp', 'src/config.ts', `const value = '${value}';`));
    assert.equal(result.decision, 'block');
    assert.equal(JSON.stringify(result).includes(value), false, 'findings must not expose credentials');
    const output = sanitizeString(`Observed ${value} while reading`, { includeRuntimeEnv: false });
    assert.equal(output.sanitized.includes(value), false);
    assert.match(output.sanitized, /\[REDACTED\]/);
    // A prior global-regexp match cannot suppress subsequent scans.
    assert.equal(noSecretsRule.inspect(context('/tmp', '.env.example', `VALUE=${value}`)).decision, 'block');
  });
}

test('entropy, public identifiers and explicit placeholders alone are not credentials', () => {
  for (const value of ['a4f8c73eb215d987ca8e401f729b560dc7e9246051ab2f936d4e5c801a9630be', 'sk_live_short', 'ghp_short', '<YOUR_API_KEY>', '${API_KEY}', 'process.env.API_KEY', 'pk_live_' + 'Ab9'.repeat(8)]) {
    assert.equal(noSecretsRule.inspect(context('/tmp', 'src/config.ts', `const value = '${value}';`)).decision, 'pass', value);
    assert.equal(sanitizeString(`Observed ${value}`, { includeRuntimeEnv: false }).sanitized, `Observed ${value}`, value);
  }
});
