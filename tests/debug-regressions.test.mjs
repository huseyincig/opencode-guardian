import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Guardian, {
  evaluateAgentMutationProfile,
  getCachedAgentCapability,
  cacheAgentCapability,
  sanitizeObject,
  sanitizeToolResult,
} from '../dist/index.js';

function directory(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-debug-fixture-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

const options = { notifications: { enabled: false }, updateNotice: { enabled: false } };

test('V1 native session.deleted clears cached capability and task guidance', async (t) => {
  const root = directory(t);
  const hooks = await Guardian.server({ directory: root, client: { session: {} } }, options);
  t.after(() => hooks.dispose());
  await hooks['chat.message']({ sessionID: 'deleted', messageID: 'human' }, {
    parts: [{ type: 'text', text: 'Implement the change, run all tests and review the source.' }],
  });
  cacheAgentCapability('deleted', { capability: 'write-allowed', evidence: { reasons: [] } });
  const before = { system: [] };
  await hooks['experimental.chat.system.transform']({ sessionID: 'deleted' }, before);
  assert.ok(before.system.length > 0, 'fixture must first establish task guidance');
  // @opencode-ai/sdk@1.18.34 EventSessionDeleted uses properties.info.
  await hooks.event({ event: { type: 'session.deleted', properties: { info: { id: 'deleted' } } } });
  assert.equal(getCachedAgentCapability('deleted'), undefined);
  const after = { system: [] };
  await hooks['experimental.chat.system.transform']({ sessionID: 'deleted' }, after);
  assert.deepEqual(after.system, []);
});

for (const cancellation of ['session.deleted', 'new human prompt', 'attachment-only prompt']) {
  test(`V1 ${cancellation} cancels an in-flight idle inspection`, async (t) => {
    const root = directory(t);
    const entered = Promise.withResolvers();
    const release = Promise.withResolvers();
    const prompts = [];
    const hooks = await Guardian.server({ directory: root, client: { session: {
      async get() { return { data: { id: 'session' } }; },
      async messages() { entered.resolve(); return release.promise; },
      async promptAsync(input) { prompts.push(input); return {}; },
    } } }, options);
    t.after(() => hooks.dispose());
    const handling = hooks.event({ event: { type: 'session.idle', properties: { sessionID: 'session' } } });
    await entered.promise;
    if (cancellation === 'session.deleted') {
      await hooks.event({ event: { type: cancellation, properties: { info: { id: 'session' } } } });
    } else {
      await hooks['chat.message']({ sessionID: 'session', messageID: 'new-human' }, {
        parts: cancellation === 'attachment-only prompt'
          ? [{ type: 'file', mime: 'image/png', url: 'data:image/png;base64,' }]
          : [{ type: 'text', text: 'Continue with the new task.' }],
      });
    }
    release.resolve({ data: [
      { info: { id: 'old-human', role: 'user' }, parts: [{ type: 'text', text: 'Complete this task.' }] },
      { info: { id: 'old-assistant', role: 'assistant' }, parts: [{ type: 'text', text: 'I am sorry.' }] },
    ] });
    await handling;
    assert.deepEqual(prompts, [], 'stale assistant output must not trigger a new model turn');
  });
}

for (const parts of [
  [{ type: 'text', text: 'Explain the architecture.' }],
  [{ type: 'file', mime: 'image/png', url: 'data:image/png;base64,' }],
]) {
  test(`V1 new ${parts[0].type} prompt clears guidance from the previous human task`, async (t) => {
    const root = directory(t);
    const hooks = await Guardian.server({ directory: root, client: { session: {} } }, options);
    t.after(() => hooks.dispose());
    await hooks['chat.message']({ sessionID: 'session', messageID: 'human-1' }, {
      parts: [{ type: 'text', text: 'Implement the change, run all tests and review the source.' }],
    });
    await hooks['chat.message']({ sessionID: 'session', messageID: 'human-2' }, { parts });
    const output = { system: [] };
    await hooks['experimental.chat.system.transform']({ sessionID: 'session' }, output);
    assert.deepEqual(output.system, []);
  });
}

test('V1 session deletion prevents a suspended capability query from reviving its cache', async (t) => {
  const root = directory(t);
  const entered = Promise.withResolvers();
  const release = Promise.withResolvers();
  const hooks = await Guardian.server({ directory: root, client: {
    app: { async agents() { entered.resolve(); return release.promise; } },
    session: {
      async get() { return { data: { id: 'child', parentID: 'parent' } }; },
      async messages() { return { data: [
        { info: { id: 'human', role: 'user' }, parts: [{ type: 'text', text: 'Complete the task.' }] },
        { info: { id: 'assistant', role: 'assistant', agent: 'worker' }, parts: [{ type: 'text', text: 'I am sorry.' }] },
      ] }; },
      async promptAsync() { assert.fail('deleted child must not receive remediation'); },
    },
  } }, options);
  t.after(() => hooks.dispose());
  const handling = hooks.event({ event: { type: 'session.idle', properties: { sessionID: 'child' } } });
  await entered.promise;
  await hooks.event({ event: { type: 'session.deleted', properties: { info: { id: 'child' } } } });
  release.resolve({ data: [{ name: 'worker', permission: { edit: 'allow' } }] });
  await handling;
  assert.equal(getCachedAgentCapability('child'), undefined);
});

for (const field of ['password', 'metadata', 'cause', 'errors']) {
  test(`nested Error.${field} cannot leak credentials through tool output`, () => {
    const credential = 'synthetic-error-credential-493827';
    const nested = field === 'password' ? credential
      : field === 'errors' ? [{ password: credential }] : { password: credential };
    const error = Object.assign(new Error('Request failed'), { [field]: nested });
    const result = sanitizeToolResult({ output: 'failed', error }, { includeRuntimeEnv: false });
    assert.equal(JSON.stringify(result).includes(credential), false);
    assert.equal(result.error instanceof Error, true, 'sanitization must preserve Error semantics');
  });
}

test('Error cause is redacted even when it is non-enumerable', () => {
  const credential = 'synthetic-cause-credential-284619';
  const error = new Error('Request failed', { cause: { password: credential } });
  const result = sanitizeObject({ error }, { includeRuntimeEnv: false }).sanitized;
  assert.equal(JSON.stringify(result.error.cause).includes(credential), false);
});

test('reserved JSON keys remain own properties after object sanitization', () => {
  const input = JSON.parse('{"__proto__":{"password":"synthetic-password-1234"},"output":"ok"}');
  const result = sanitizeObject(input, { includeRuntimeEnv: false }).sanitized;
  assert.equal(Object.hasOwn(result, '__proto__'), true);
  assert.equal(Object.getPrototypeOf(result), Object.prototype);
  assert.deepEqual(JSON.parse(JSON.stringify(result)), JSON.parse('{"__proto__":{"password":"[REDACTED]"},"output":"ok"}'));
});

for (const wrap of [value => value, value => Object.assign(new Error('Request failed'), value)]) {
  test('tool serialization cannot execute an untrusted toJSON callback', () => {
    const credential = 'synthetic-serializer-credential-483921';
    const result = sanitizeToolResult({ output: 'failed', detail: wrap({
      toJSON() { return { password: credential }; },
    }) }, { includeRuntimeEnv: false });
    assert.equal(JSON.stringify(result).includes(credential), false);
  });
}

test('V1 broad allow does not override a file mutation channel deny', () => {
  const profile = evaluateAgentMutationProfile({
    tools: { write_file: true },
    permission: { '*': 'allow', edit: 'deny', bash: 'deny' },
  });
  assert.notEqual(profile.capability, 'write-allowed');
});

for (const permission of ['deny', 'ask', { '*': 'deny' }]) {
  test(`V1 mutating tool permission ${JSON.stringify(permission)} cannot grant autonomous writes`, () => {
    const profile = evaluateAgentMutationProfile({
      tools: { write_file: true },
      permission: { edit: 'deny', bash: 'deny', write_file: permission },
    });
    assert.notEqual(profile.capability, 'write-allowed');
    if (permission === 'ask') assert.equal(profile.capability, 'write-requires-approval');
  });
}
