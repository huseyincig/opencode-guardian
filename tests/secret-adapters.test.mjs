import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Guardian from '../dist/index.js';

function createTempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-secret-test-'));
  fs.writeFileSync(
    path.join(dir, 'opencode-guardian.json'),
    JSON.stringify({ enabled: true, preflight: { enabled: false } })
  );
  t.after(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return dir;
}

test('V2 ADAPTER: setup registers tool and session hooks, redacting output and LLM context', async (t) => {
  const dir = createTempDir(t);
  const canary = 'canary_v2_secret_token_abcdef123';

  const toolHooks = new Map();
  const sessionHooks = new Map();

  const mockContext = {
    location: { directory: dir },
    options: { customSecretValues: [canary] },
    tool: {
      hook: async (name, handler) => {
        toolHooks.set(name, handler);
        return { dispose: () => toolHooks.delete(name) };
      },
    },
    session: {
      context: async () => [],
      synthetic: async () => {},
      hook: async (name, handler) => {
        sessionHooks.set(name, handler);
        return { dispose: () => sessionHooks.delete(name) };
      },
    },
    event: {
      subscribe: ({ signal }) => ({
        async *[Symbol.asyncIterator]() {
          if (!signal.aborted) {
            await new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
          }
        },
      }),
    },
  };

  const cleanup = await Guardian.setup(mockContext);
  assert.ok(typeof cleanup === 'function', 'Setup must return cleanup function');

  // Verify registered hooks
  assert.ok(toolHooks.has('execute.after'), 'Must register execute.after hook');
  assert.ok(sessionHooks.has('context'), 'Must register session context hook');

  // 1. Test execute.after hook
  const executeAfterHandler = toolHooks.get('execute.after');
  const toolEvent = {
    status: 'completed',
    tool: 'bash',
    id: 'call-01',
    sessionID: 'ses-v2-01',
    messageID: 'msg-01',
    result: {
      output: `DATABASE_PASSWORD=${canary}\nDB_PORT=5432`,
      title: `Result ${canary}`,
      content: `Sibling content ${canary}`,
      metadata: { exitCode: 0 },
    },
  };

  await executeAfterHandler(toolEvent);
  assert.equal(JSON.stringify(toolEvent.result).includes(canary), false, 'V2 result siblings must be redacted');
  assert.equal(toolEvent.result.output.includes(canary), false, 'V2 tool result must be redacted');
  assert.match(toolEvent.result.output, /DATABASE_PASSWORD=\[REDACTED\]/);
  assert.match(toolEvent.result.output, /DB_PORT=5432/);

  // Installed @opencode/plugin 2.0.22 declares Tool.Error with message,
  // optional defect/error data and metadata. Every model-visible field must
  // cross the same POST redaction boundary.
  const toolError = new Error(`Tool failed with token=${canary}`);
  toolError.stack = `Error: token=${canary}\n    at synthetic-test`;
  toolError.error = { password: canary };
  toolError.metadata = { apiKey: canary, region: 'eu' };
  const errorEvent = {
    status: 'error',
    tool: 'bash',
    id: 'call-error-01',
    sessionID: 'ses-v2-01',
    messageID: 'msg-error-01',
    input: {},
    error: toolError,
  };

  await executeAfterHandler(errorEvent);
  assert.equal(errorEvent.error.message.includes(canary), false, 'V2 Tool.Error.message must be redacted');
  assert.equal(errorEvent.error.stack.includes(canary), false, 'V2 Tool.Error.stack must be redacted');
  assert.equal(JSON.stringify(errorEvent.error.error).includes(canary), false, 'V2 Tool.Error defect must be redacted');
  assert.equal(JSON.stringify(errorEvent.error.metadata).includes(canary), false, 'V2 Tool.Error metadata must be redacted');
  assert.equal(errorEvent.error.metadata.region, 'eu');

  // 2. Test session context hook (the outgoing LLM request)
  const contextHandler = sessionHooks.get('context');
  const sessionEvent = {
    sessionID: 'ses-v2-01',
    system: [
      {
        type: 'text',
        text: `System runtime token: ${canary}`,
        metadata: { secretEcho: canary, safe: 'kept' },
      },
    ],
    messages: [
      {
        info: { role: 'assistant' },
        parts: [
          {
            type: 'tool',
            state: {
              output: `PADDLE_API_KEY=${canary}`,
            },
          },
        ],
      },
    ],
  };

  await contextHandler(sessionEvent);
  const partOutput = sessionEvent.messages[0].parts[0].state.output;
  assert.equal(partOutput.includes(canary), false, 'V2 model context must not contain raw secret');
  assert.match(partOutput, /PADDLE_API_KEY=\[REDACTED\]/);
  assert.equal(
    JSON.stringify(sessionEvent.system).includes(canary),
    false,
    'MODEL_CONTEXT.includes(S) must be false for V2 system context'
  );
  assert.match(sessionEvent.system[0].text, /System runtime token: \[REDACTED\]/);
  assert.equal(sessionEvent.system[0].metadata.safe, 'kept');

  // 3. Test disposal cleanup
  await cleanup();
});
