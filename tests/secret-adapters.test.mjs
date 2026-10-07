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

test('V1 ADAPTER: tool.execute.after redacts secrets from output and metadata', async (t) => {
  const dir = createTempDir(t);
  const canary = 'canary_v1_tool_output_secret_998877';
  const hooks = await Guardian.server({
    client: { session: {} },
    directory: dir,
  });

  const input = {
    tool: 'bash',
    sessionID: 'ses-v1-01',
    callID: 'call-01',
    args: { command: 'docker exec app env' },
  };

  const output = {
    title: 'bash: docker exec app env',
    output: [
      'PATH=/usr/bin:/bin',
      `PADDLE_API_KEY=${canary}`,
      'SERVICE=billing',
    ].join('\n'),
    metadata: {
      exitCode: 0,
      envDump: `TOKEN=${canary}`,
    },
  };

  await hooks['tool.execute.after'](input, output);

  assert.equal(output.output.includes(canary), false, 'V1 output must not contain raw secret');
  assert.equal(output.metadata.envDump.includes(canary), false, 'V1 metadata must not contain raw secret');
  assert.match(output.output, /PADDLE_API_KEY=\[REDACTED\]/);
  assert.match(output.metadata.envDump, /TOKEN=\[REDACTED\]/);
  assert.match(output.output, /PATH=\/usr\/bin:\/bin/);

  await hooks.dispose();
});

test('V1 ADAPTER: experimental.chat.messages.transform sanitizes messages before LLM context', async (t) => {
  const dir = createTempDir(t);
  const canary = 'canary_v1_msg_context_secret_112233';
  const hooks = await Guardian.server({
    client: { session: {} },
    directory: dir,
  });

  const transformOutput = {
    messages: [
      {
        info: { role: 'assistant', id: 'msg-01' },
        parts: [
          {
            type: 'text',
            text: `Here is the token: ${canary}`,
          },
          {
            type: 'tool',
            state: {
              input: { command: 'printenv' },
              output: `SECRET_KEY=${canary}\nSAFE_VAR=1`,
            },
          },
        ],
      },
    ],
  };

  assert.equal(typeof hooks['experimental.chat.messages.transform'], 'function');
  await hooks['experimental.chat.messages.transform']({}, transformOutput);

  const textPart = transformOutput.messages[0].parts[0];
  const toolPart = transformOutput.messages[0].parts[1];

  assert.equal(textPart.text.includes(canary), false, 'Message text must not contain secret');
  assert.equal(toolPart.state.output.includes(canary), false, 'Tool state output must not contain secret');
  assert.match(textPart.text, /Here is the token: \[REDACTED\]/);
  assert.match(toolPart.state.output, /SECRET_KEY=\[REDACTED\]/);

  await hooks.dispose();
});

test('V1 ADAPTER: experimental.chat.system.transform sanitizes system context before LLM use', async (t) => {
  const dir = createTempDir(t);
  const canary = 'canary_v1_system_context_secret_445566';
  const hooks = await Guardian.server({
    client: { session: {} },
    directory: dir,
  });

  const output = {
    system: [
      'You are a coding assistant.',
      `Injected runtime token: ${canary}`,
    ],
  };

  await hooks['experimental.chat.system.transform'](
    { sessionID: 'ses-v1-system-secret' },
    output
  );

  assert.equal(
    JSON.stringify(output.system).includes(canary),
    false,
    'MODEL_CONTEXT.includes(S) must be false for V1 system context'
  );
  assert.match(output.system[1], /Injected runtime token: \[REDACTED\]/);

  await hooks.dispose();
});

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
    },
  };

  await executeAfterHandler(toolEvent);
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
