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

const options = { notifications: { enabled: false }, updateNotice: { enabled: false }, secrets: { enabled: false } };

test('V2 native session.deleted clears cached capability and task guidance', async (t) => {
  const root = directory(t);
  let promptHook;
  let contextHook;
  let emitEvent;
  const host = {
    location: { directory: root },
    options,
    event: {
      subscribe({ signal }) {
        return (async function* () {
          while (!signal.aborted) {
            const next = await new Promise((resolve) => { emitEvent = resolve; });
            if (next === null) break;
            yield next;
          }
        })();
      },
    },
    session: {
      async context() { return []; },
      async synthetic() {},
      async hook(name, handler) {
        if (name === 'prompt') promptHook = handler;
        if (name === 'context') contextHook = handler;
        return { dispose() {} };
      },
    },
  };
  const cleanup = await Guardian.setup(host);
  t.after(() => cleanup());
  await promptHook({
    sessionID: 'deleted',
    prompt: { text: 'Implement the change, run all tests and review the source.' },
  });
  cacheAgentCapability('deleted', { capability: 'write-allowed', evidence: { reasons: [] } });
  const before = { system: [] };
  await contextHook({ sessionID: 'deleted', system: before.system });
  assert.ok(before.system.length > 0, 'fixture must first establish task guidance');
  emitEvent({ type: 'session.deleted', data: { sessionID: 'deleted' } });
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(getCachedAgentCapability('deleted'), undefined);
  const after = { system: [] };
  await contextHook({ sessionID: 'deleted', system: after.system });
  assert.deepEqual(after.system, []);
  emitEvent(null);
});

for (const cancellation of ['session.deleted', 'new human prompt', 'attachment-only prompt']) {
  test(`V2 ${cancellation} cancels an in-flight idle inspection`, async (t) => {
    const root = directory(t);
    const entered = Promise.withResolvers();
    const release = Promise.withResolvers();
    const prompts = [];
    let promptHook;
    let emitEvent;
    const host = {
      location: { directory: root },
      options,
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              const next = await new Promise((resolve) => { emitEvent = resolve; });
              if (next === null) break;
              yield next;
            }
          })();
        },
      },
      session: {
        async get() { return { id: 'session', parentID: undefined }; },
        async context() { entered.resolve(); return release.promise; },
        async synthetic(input) { prompts.push(input); },
        async hook(name, handler) {
          if (name === 'prompt') promptHook = handler;
          return { dispose() {} };
        },
      },
    };
    const cleanup = await Guardian.setup(host);
    t.after(() => cleanup());
    emitEvent({ type: 'session.idle', data: { sessionID: 'session' } });
    await entered.promise;
    if (cancellation === 'session.deleted') {
      emitEvent({ type: 'session.deleted', data: { sessionID: 'session' } });
      await new Promise((r) => setTimeout(r, 20));
    } else {
      await promptHook({
        sessionID: 'session',
        prompt: cancellation === 'attachment-only prompt'
          ? { text: '' }
          : { text: 'Continue with the new task.' },
      });
    }
    release.resolve([
      { id: 'old-human', type: 'user', text: 'Complete this task.' },
      { id: 'old-assistant', type: 'assistant', content: [{ type: 'text', text: 'I am sorry.' }] },
    ]);
    await new Promise((r) => setTimeout(r, 40));
    assert.deepEqual(prompts, [], 'stale assistant output must not trigger a new model turn');
    emitEvent(null);
  });
}

for (const prompt of [
  { label: 'text', text: 'Explain the architecture.' },
  { label: 'empty', text: '' },
]) {
  test(`V2 new ${prompt.label} prompt clears guidance from the previous human task`, async (t) => {
    const root = directory(t);
    let promptHook;
    let contextHook;
    const host = {
      location: { directory: root },
      options,
      event: { subscribe: () => (async function* () {})() },
      session: {
        async context() { return []; },
        async synthetic() {},
        async hook(name, handler) {
          if (name === 'prompt') promptHook = handler;
          if (name === 'context') contextHook = handler;
          return { dispose() {} };
        },
      },
    };
    const cleanup = await Guardian.setup(host);
    t.after(() => cleanup());
    await promptHook({
      sessionID: 'session',
      prompt: { text: 'Implement the change, run all tests and review the source.' },
    });
    await promptHook({ sessionID: 'session', prompt: { text: prompt.text } });
    const output = { system: [] };
    await contextHook({ sessionID: 'session', system: output.system });
    assert.deepEqual(output.system, []);
  });
}

test('V2 session deletion prevents a suspended capability query from reviving its cache', async (t) => {
  const root = directory(t);
  const entered = Promise.withResolvers();
  const release = Promise.withResolvers();
  let emitEvent;
  const host = {
    location: { directory: root },
    options,
    agent: { async list() { entered.resolve(); return release.promise; } },
    event: {
      subscribe({ signal }) {
        return (async function* () {
          while (!signal.aborted) {
            const next = await new Promise((resolve) => { emitEvent = resolve; });
            if (next === null) break;
            yield next;
          }
        })();
      },
    },
    session: {
      async get() { return { id: 'child', parentID: 'parent' }; },
      async context() {
        return [
          { id: 'human', type: 'user', text: 'Complete the task.' },
          { id: 'assistant', type: 'assistant', agent: 'worker', content: [{ type: 'text', text: 'I am sorry.' }] },
        ];
      },
      async synthetic() { assert.fail('deleted child must not receive remediation'); },
    },
  };
  const cleanup = await Guardian.setup(host);
  t.after(() => cleanup());
  emitEvent({ type: 'session.idle', data: { sessionID: 'child' } });
  await entered.promise;
  emitEvent({ type: 'session.deleted', data: { sessionID: 'child' } });
  await new Promise((r) => setTimeout(r, 20));
  release.resolve([{ name: 'worker', permission: [{ permission: 'edit', pattern: '*', action: 'allow' }] }]);
  await new Promise((r) => setTimeout(r, 40));
  assert.equal(getCachedAgentCapability('child'), undefined);
  emitEvent(null);
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
