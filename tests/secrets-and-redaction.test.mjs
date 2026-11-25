import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, { RuntimeSecretRegistry, assessCommandPreflight, evaluatePreflight, isDestructiveCommand, isSimpleFileRemoval, noSecretsRule as noSecretsRule_3, sanitizeMessages, sanitizeString, sanitizeToolResult } from "../dist/index.js";
import { clearDeclaredDepsCache, noGhostDepsRule } from "../dist/rules/no-ghost-deps.js";
import { noSecretsRule } from "../dist/rules/no-secrets.js";
import { sanitizeString as sanitizeString_2 } from "../dist/secrets/sanitizer.js";

describe("Multi-Layer Secret Output Redaction", () => {
  const SYNTHETIC_CANARY_SECRET = 'canary_secret_ABC123_DEF456_789XYZ';

  test('string output envelopes redact title and content siblings without altering safe fields', () => {
    const secret = 'guardianSyntheticSiblingSecret7654321';
    const input = {
      output: 'finished', title: secret,
      content: [{ type: 'text', text: secret }],
      raw: { detail: secret }, metadata: { exitCode: 0, region: 'eu-central-1' },
    };
    const sanitized = sanitizeToolResult(input, { includeRuntimeEnv: false, customSecretValues: [secret] });
    assert.equal(JSON.stringify(sanitized).includes(secret), false);
    assert.equal(sanitized.output, 'finished');
    assert.equal(sanitized.title, '[REDACTED]');
    assert.deepEqual(sanitized.content, [{ type: 'text', text: '[REDACTED]' }]);
    assert.deepEqual(sanitized.raw, { detail: '[REDACTED]' });
    assert.deepEqual(sanitized.metadata, input.metadata);
    assert.equal(input.title, secret, 'sanitization must not mutate the source result');
  });

  test('REPRODUCTION & VERIFICATION: Tool output leak in docker exec ... env', () => {
    const rawToolOutput = [
      'PATH=/usr/local/bin:/usr/bin:/bin',
      'NODE_ENV=production',
      'PORT=3000',
      `FAKE_PADDLE_API_KEY=${SYNTHETIC_CANARY_SECRET}`,
      'SAFE_CONFIG=normal-value',
    ].join('\n');

    // Baseline proof of vulnerability:
    const unshieldedModelContext = rawToolOutput;
    assert.equal(
      unshieldedModelContext.includes(SYNTHETIC_CANARY_SECRET),
      true,
      'Baseline vulnerability confirmed: unshielded tool output reaches model context containing raw secret'
    );

    // Post-execution redaction layer applied
    const sanitizedOutput = sanitizeToolResult(rawToolOutput);

    assert.equal(
      sanitizedOutput.includes(SYNTHETIC_CANARY_SECRET),
      false,
      'CRITICAL: Model-visible output MUST NOT contain the canary secret'
    );

    assert.match(
      sanitizedOutput,
      /FAKE_PADDLE_API_KEY=\[REDACTED\]/,
      'Output must retain variable name and have value cleanly redacted'
    );

    assert.match(
      sanitizedOutput,
      /PATH=\/usr\/local\/bin:\/usr\/bin:\/bin/,
      'Safe environment variables must be preserved verbatim'
    );
    assert.match(sanitizedOutput, /PORT=3000/, 'Port must be preserved');
    assert.match(sanitizedOutput, /SAFE_CONFIG=normal-value/, 'Safe config must be preserved');
  });

  test('Shell stdout environment dump redacts secret value and preserves safe vars', () => {
    const canary = 'secret_canary_test_api_key_8829103';
    const stdout = [
      'PATH=/usr/local/bin:/usr/bin:/bin',
      `TEST_API_KEY=${canary}`,
      'SAFE_VALUE=hello',
      'PORT=8080',
    ].join('\n');

    const result = sanitizeToolResult(stdout);
    assert.equal(result.includes(canary), false, 'Literal secret must not be in model output');
    assert.match(result, /TEST_API_KEY=\[REDACTED\]/);
    assert.match(result, /SAFE_VALUE=hello/);
    assert.match(result, /PATH=\/usr\/local\/bin/);
    assert.match(result, /PORT=8080/);
  });

  test('stderr output containing secret is redacted', () => {
    const canary = 'canary_stderr_secret_value_991823';
    const toolResult = {
      stdout: 'Compilation succeeded with warnings',
      stderr: `Warning: auth failed with token=${canary} at line 42`,
    };

    const sanitized = sanitizeToolResult(toolResult);
    assert.equal(sanitized.stderr.includes(canary), false);
    assert.match(sanitized.stderr, /token=\[REDACTED\]/);
    assert.match(sanitized.stderr, /at line 42/);
    assert.equal(sanitized.stdout, 'Compilation succeeded with warnings');
  });

  test('Nested JSON objects preserve structure while redacting values', () => {
    const canaryToken = 'canary_token_nested_json_112233';
    const canaryPass = 'canary_password_nested_json_445566';

    const rawJson = {
      service: 'auth-service',
      status: 'ok',
      token: canaryToken,
      nested: {
        user: 'admin',
        password: canaryPass,
        retryCount: 3,
      },
    };

    const sanitized = sanitizeToolResult(rawJson);
    assert.equal(JSON.stringify(sanitized).includes(canaryToken), false);
    assert.equal(JSON.stringify(sanitized).includes(canaryPass), false);
    assert.equal(sanitized.token, '[REDACTED]');
    assert.equal(sanitized.nested.password, '[REDACTED]');
    assert.equal(sanitized.nested.user, 'admin');
    assert.equal(sanitized.nested.retryCount, 3);
    assert.equal(sanitized.service, 'auth-service');
  });

  test('Arrays redact secrets in elements while preserving normal entries', () => {
    const canary = 'canary_array_secret_token_778899';
    const rawArray = [
      'normal-entry-1',
      `TOKEN=${canary}`,
      'normal-entry-2',
      { apiKey: canary, role: 'viewer' },
    ];

    const sanitized = sanitizeToolResult(rawArray);
    assert.equal(JSON.stringify(sanitized).includes(canary), false);
    assert.equal(sanitized[0], 'normal-entry-1');
    assert.equal(sanitized[1], 'TOKEN=[REDACTED]');
    assert.equal(sanitized[2], 'normal-entry-2');
    assert.equal(sanitized[3].apiKey, '[REDACTED]');
    assert.equal(sanitized[3].role, 'viewer');
  });

  test('Exact runtime secret appearing in arbitrary prose is redacted', () => {
    const runtimeCanary = 'canary_runtime_secret_standalone_xyz999';

    const registry = new RuntimeSecretRegistry();
    registry.scanEnv({
      MY_CUSTOM_SECRET: runtimeCanary,
      SAFE_PORT: '8080',
    });

    const prose = `Connection rejected. Authentication failed for ${runtimeCanary} from 192.168.1.1`;
    const sanitized = sanitizeString(prose, {
      customSecretValues: registry.getSecrets(),
    });

    assert.equal(sanitized.sanitized.includes(runtimeCanary), false);
    assert.equal(
      sanitized.sanitized,
      'Connection rejected. Authentication failed for [REDACTED] from 192.168.1.1'
    );
  });

  test('Password hash values (bcrypt, argon2, scrypt) are redacted', () => {
    const bcryptHash = '$2b$12$e8uqPz7UqEeV2y18j9i/7e0O7yU8B9B7N6M5L4K3J2H1G0F9E8D7C';
    const argonHash = '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlfreahfm赶上';

    const envDump = [
      `NC_ADMIN_PASSWORD_HASH=${bcryptHash}`,
      `NC_DEMO_PASSWORD_HASH=${argonHash}`,
      'NC_ENV=production',
    ].join('\n');

    const sanitized = sanitizeToolResult(envDump);
    assert.equal(sanitized.includes(bcryptHash), false);
    assert.equal(sanitized.includes(argonHash), false);
    assert.match(sanitized, /NC_ADMIN_PASSWORD_HASH=\[REDACTED\]/);
    assert.match(sanitized, /NC_DEMO_PASSWORD_HASH=\[REDACTED\]/);
    assert.match(sanitized, /NC_ENV=production/);
  });

  test('Safe environment variables and ordinary strings are NOT redacted', () => {
    const safeText = [
      'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      'HOME=/root',
      'PORT=3000',
      'NODE_ENV=production',
      'USER=appservice',
      'SHELL=/bin/bash',
      'LANG=en_US.UTF-8',
      'HOSTNAME=vps-prod-node-01',
      'URL=https://api.example.invalid/v1/health',
      'COMMIT_SHA=7c161913f581533c18caeeeb91cb04645d72acae',
      'PRIMARY_KEY=id',
    ].join('\n');

    const sanitized = sanitizeToolResult(safeText);
    assert.equal(sanitized, safeText, 'Safe variables must remain completely untouched');
  });

  test('Synthetic .env file content read is redacted before reaching model', () => {
    const paddleCanary = 'canary_paddle_api_key_live_998877';
    const secretKeyCanary = 'canary_app_secret_key_abcdef123456';

    const dotEnvContent = [
      '# Application settings',
      'PORT=4000',
      `PADDLE_API_KEY=${paddleCanary}`,
      `APP_SECRET=${secretKeyCanary}`,
      'PUBLIC_URL=https://example.com',
    ].join('\n');

    const sanitized = sanitizeToolResult(dotEnvContent);
    assert.equal(sanitized.includes(paddleCanary), false);
    assert.equal(sanitized.includes(secretKeyCanary), false);
    assert.match(sanitized, /PADDLE_API_KEY=\[REDACTED\]/);
    assert.match(sanitized, /APP_SECRET=\[REDACTED\]/);
    assert.match(sanitized, /PORT=4000/);
    assert.match(sanitized, /PUBLIC_URL=https:\/\/example\.com/);
  });

  test('Log output containing tokens is redacted', () => {
    const tokenCanary = 'ghp_11223344556677889900aabbccddeeff1122';
    const logLine = `[2026-10-07T01:00:00Z] INFO [github-sync] Using credentials with token: ${tokenCanary} to fetch releases`;

    const sanitized = sanitizeToolResult(logLine);
    assert.equal(sanitized.includes(tokenCanary), false);
    assert.match(sanitized, /Using credentials with token: \[REDACTED\] to fetch releases/);
  });

  test('MCP text content result containing secret is sanitized', () => {
    const canary = 'canary_mcp_text_secret_443322';
    const mcpResult = {
      content: [
        {
          type: 'text',
          text: `Config dump:\nSECRET_KEY=${canary}\nHOST=127.0.0.1`,
        },
      ],
    };

    const sanitized = sanitizeToolResult(mcpResult);
    assert.equal(JSON.stringify(sanitized).includes(canary), false);
    assert.match(sanitized.content[0].text, /SECRET_KEY=\[REDACTED\]/);
    assert.match(sanitized.content[0].text, /HOST=127\.0\.0\.1/);
  });

  test('MCP structured result with nested secret properties is sanitized', () => {
    const canary = 'canary_mcp_structured_token_887766';
    const mcpResult = {
      content: [
        {
          type: 'resource',
          metadata: {
            clientSecret: canary,
            region: 'eu-central-1',
          },
        },
      ],
    };

    const sanitized = sanitizeToolResult(mcpResult);
    assert.equal(JSON.stringify(sanitized).includes(canary), false);
    assert.equal(sanitized.content[0].metadata.clientSecret, '[REDACTED]');
    assert.equal(sanitized.content[0].metadata.region, 'eu-central-1');
  });

  test('Tool error message containing secret is redacted', () => {
    const canary = 'canary_error_pass_secret_332211';
    const errorObj = new Error(`Connection failed: password ${canary} was rejected`);

    const sanitized = sanitizeToolResult(errorObj);
    assert.equal(sanitized.message.includes(canary), false);
    assert.match(sanitized.message, /password \[REDACTED\] was rejected/);
  });

  test('Multiple secrets in a single output are all redacted', () => {
    const secret1 = 'canary_multi_sec1_111111';
    const secret2 = 'canary_multi_sec2_222222';
    const secret3 = 'canary_multi_sec3_333333';

    const multiOutput = [
      `API_KEY=${secret1}`,
      `JWT_SECRET=${secret2}`,
      `DATABASE_PASSWORD=${secret3}`,
      'APP_NAME=my-app',
    ].join('\n');

    const sanitized = sanitizeToolResult(multiOutput);
    assert.equal(sanitized.includes(secret1), false);
    assert.equal(sanitized.includes(secret2), false);
    assert.equal(sanitized.includes(secret3), false);
    assert.match(sanitized, /API_KEY=\[REDACTED\]/);
    assert.match(sanitized, /JWT_SECRET=\[REDACTED\]/);
    assert.match(sanitized, /DATABASE_PASSWORD=\[REDACTED\]/);
  });

  test('Repeated secret appearing 5 times is completely eliminated in all 5 places', () => {
    const canary = 'canary_repeated_secret_99887766';
    const repeatedText = [
      `export TOKEN=${canary}`,
      `echo "debug token: ${canary}"`,
      `curl -H "Authorization: Bearer ${canary}" https://api.example.com`,
      `retrying with token ${canary}`,
      `failed token=${canary}`,
    ].join('\n');

    const sanitized = sanitizeString(repeatedText, {
      customSecretValues: [canary],
    });

    assert.equal(sanitized.sanitized.includes(canary), false, '0 copies must remain');
    const count = (sanitized.sanitized.match(/\[REDACTED\]/g) || []).length;
    assert.ok(count >= 5, `Expected at least 5 redactions, got ${count}`);
  });

  test('Multiline PEM private key is cleanly redacted to [REDACTED:PRIVATE_KEY]', () => {
    const pemKey = [
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEowIBAAKCAQEA0Y7Z5r3W8kXyZ1v2u3t4s5r6q7p8o9n0m1l2k3j4h5g6f7e8',
      'd9c8b7a6Z5Y4X3W2V1U0T9S8R7Q6P5O4N3M2L1K0J9I8H7G6F5E4D3C2B1A0z9y8',
      'x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3h2g1f0e9d8c7b6a5Z4Y3X2W1V0U9T8S7R6',
      '-----END RSA PRIVATE KEY-----',
    ].join('\n');

    const text = `Certificate loaded:\n${pemKey}\nServer running on port 443`;
    const sanitized = sanitizeToolResult(text);

    assert.equal(sanitized.includes('MIIEowIBAAKCAQEA0Y7Z5r3W8kXyZ1v2u3t4s5r6q7p8o9n0m1l2k3j4h5g6f7e8'), false);
    assert.match(sanitized, /\[REDACTED:PRIVATE_KEY\]/);
    assert.match(sanitized, /Server running on port 443/);
  });

  test('Database connection strings have only password component redacted', () => {
    const secretPass = 'super_secret_db_password_12345';
    const connStr = `postgres://app_user:${secretPass}@db.internal.example.invalid:5432/production_db?sslmode=require`;

    const sanitized = sanitizeToolResult(connStr);
    assert.equal(sanitized.includes(secretPass), false);
    assert.equal(
      sanitized,
      'postgres://app_user:[REDACTED]@db.internal.example.invalid:5432/production_db?sslmode=require'
    );
  });

  test('Telemetry and diagnostic logger never receive raw secret values', () => {
    const canary = 'canary_telemetry_secret_998811';
    const loggedMessages = [];

    const text = `API_KEY=${canary}`;
    sanitizeString(text, {
      logger: (msg) => loggedMessages.push(msg),
    });

    for (const log of loggedMessages) {
      assert.equal(log.includes(canary), false, 'Logger must never receive secret');
    }
  });

  test('Fail-safe suppression ensures raw sensitive output is never leaked if an error occurs', () => {
    const circular = {};
    circular.self = circular;

    const result = sanitizeToolResult(circular);
    assert.ok(result !== undefined);
  });

  test('Sanitizer processes large output (10,000 lines) quickly without ReDoS', () => {
    const lines = [];
    for (let i = 0; i < 10000; i++) {
      if (i === 5000) {
        lines.push('SECRET_KEY=canary_perf_secret_1234567890');
      } else {
        lines.push(`LOG_LINE_${i}=normal_operational_data_line_value_${i}`);
      }
    }
    const largeOutput = lines.join('\n');

    const start = performance.now();
    const sanitized = sanitizeToolResult(largeOutput);
    const duration = performance.now() - start;

    assert.equal(sanitized.includes('canary_perf_secret_1234567890'), false);
    assert.match(sanitized, /SECRET_KEY=\[REDACTED\]/);
    assert.ok(duration < 500, `Sanitization of 10,000 lines took ${duration}ms (must be < 500ms)`);
  });

  test('FINAL context gate redacts secrets from every tool-state field, including metadata', () => {
    const canary = 'canary_final_context_metadata_778812';
    const modelContext = sanitizeMessages([
      {
        info: { id: 'a-final-meta', role: 'assistant' },
        parts: [{
          type: 'tool',
          tool: 'file_read',
          state: {
            status: 'completed',
            output: 'safe output',
            metadata: { token: canary, region: 'eu' },
            raw: { nested: { password: canary } },
          },
        }],
      },
    ], { includeRuntimeEnv: false });

    const serialized = JSON.stringify(modelContext);
    assert.equal(
      serialized.includes(canary),
      false,
      'MODEL_CONTEXT.includes(S) must be false even when POST missed tool metadata/raw fields'
    );
    assert.equal(modelContext[0].parts[0].state.metadata.token, '[REDACTED]');
    assert.equal(modelContext[0].parts[0].state.metadata.region, 'eu');
  });

  test('FINAL context gate fails closed when message sanitization itself throws', () => {
    const canary = 'canary_final_context_failure_993311';
    let firstRead = true;
    const maliciousMessage = {
      info: { id: 'a-final-fail', role: 'assistant' },
    };
    Object.defineProperty(maliciousMessage, 'parts', {
      enumerable: true,
      configurable: true,
      get() {
        if (firstRead) {
          firstRead = false;
          throw new Error('synthetic sanitizer fault');
        }
        return [{ type: 'text', text: canary }];
      },
    });

    const modelContext = sanitizeMessages([maliciousMessage], {
      includeRuntimeEnv: false,
      customSecretValues: [canary],
    });

    assert.equal(
      JSON.stringify(modelContext).includes(canary),
      false,
      'MODEL_CONTEXT.includes(S) must remain false on sanitizer failure'
    );
  });

  test('Preflight accurately flags broad env dump commands', () => {
    assert.equal(assessCommandPreflight('docker exec -it my-container env').isHighRiskEnvDump, true);
    assert.equal(assessCommandPreflight('printenv').isHighRiskEnvDump, true);
    assert.equal(assessCommandPreflight('env').isHighRiskEnvDump, true);
    assert.equal(assessCommandPreflight('docker inspect my-container').isHighRiskEnvDump, true);
    assert.equal(assessCommandPreflight('systemctl show my-service Environment').isHighRiskEnvDump, true);

    assert.equal(assessCommandPreflight('git status').isHighRiskEnvDump, false);
    assert.equal(assessCommandPreflight('npm test').isHighRiskEnvDump, false);
    assert.equal(assessCommandPreflight('cat src/index.ts').isHighRiskEnvDump, false);
  });
});

describe("V2 Secret Adapter Boundaries", () => {
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
});

describe("Dependency & Secret Context Handling", () => {
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
      const output = sanitizeString_2(`Observed ${value} while reading`, { includeRuntimeEnv: false });
      assert.equal(output.sanitized.includes(value), false);
      assert.match(output.sanitized, /\[REDACTED\]/);
      // A prior global-regexp match cannot suppress subsequent scans.
      assert.equal(noSecretsRule.inspect(context('/tmp', '.env.example', `VALUE=${value}`)).decision, 'block');
    });
  }

  test('entropy, public identifiers and explicit placeholders alone are not credentials', () => {
    for (const value of ['a4f8c73eb215d987ca8e401f729b560dc7e9246051ab2f936d4e5c801a9630be', 'sk_live_short', 'ghp_short', '<YOUR_API_KEY>', '${API_KEY}', 'process.env.API_KEY', 'pk_live_' + 'Ab9'.repeat(8)]) {
      assert.equal(noSecretsRule.inspect(context('/tmp', 'src/config.ts', `const value = '${value}';`)).decision, 'pass', value);
      assert.equal(sanitizeString_2(`Observed ${value}`, { includeRuntimeEnv: false }).sanitized, `Observed ${value}`, value);
    }
  });
});

describe("Dynamic Shell & Example-File Credential Rules", () => {
  const tick = String.fromCharCode(96);
  const target = "/tmp/guardian-disposable-fixture";

  test("Preflight detects literal command-name substitutions", () => {
    const inputs = [
      tick + "echo rm" + tick + " -rf " + target,
      tick + "printf %s rm" + tick + " -f " + target,
      "sudo " + tick + "echo rm" + tick + " -rf " + target,
      "bash -c '" + tick + "echo rm" + tick + " -rf " + target + "'",
    ];
    for (const command of inputs) {
      assert.equal(evaluatePreflight("bash", { command }), "destructive-command", command);
      assert.equal(isDestructiveCommand(command) || isSimpleFileRemoval(command), true, command);
    }
  });

  test("dynamic commands not safely resolved are denied in strict preflight", () => {
    for (const command of [
      tick + "echo unknown_binary" + tick + " arg",
      "$(echo unknown_binary) arg",
      "${DYNAMIC_BINARY} arg",
      "bash -c '" + tick + "echo unknown_binary" + tick + " arg'",
      '"$(echo unknown_binary)" arg',
      '"${DYNAMIC_BINARY}" arg',
    ]) {
      assert.equal(evaluatePreflight("bash", { command }),
        "uninspectable-shell-input", command);
    }
  });

  test("passive quoted documentation and echo substitutions are not false positives", () => {
    for (const command of [
      "echo " + tick + "echo rm" + tick + " -rf " + target,
      "echo '" + tick + "rm -rf " + target + tick + "'",
      "printf '%s' '" + tick + "echo rm" + tick + "'",
      "grep '" + tick + "echo rm" + tick + "' README.md",
      "echo '$(echo rm) -rf " + target + "'",
      "git status",
    ]) {
      assert.equal(evaluatePreflight("bash", { command }), undefined, command);
    }
  });

  function secretScan(filePath, content) {
    return noSecretsRule_3.inspect({
      sessionID: "sample", directory: "/tmp", messages: [], ruleConfig: {},
      currentTurn: [{ info: { id: "a", role: "assistant" },
        parts: [{ type: "tool", state: { input: { filePath, content } } }] }],
    });
  }

  test("local documented sample passwords pass only in example files", () => {
    for (const filePath of [".env.example", ".env.sample", "config.template"]) {
      assert.equal(secretScan(filePath,
        "DATABASE_URL=postgres://user:pass@localhost:5432/db").decision,
        "pass", filePath);
      assert.equal(secretScan(filePath,
        "DATABASE_URL=postgres://user:your_password_here@127.0.0.1:5432/db").decision,
        "pass", filePath);
    }
    assert.equal(secretScan("src/config.ts",
      "DATABASE_URL=postgres://user:pass@localhost:5432/db").decision, "block");
  });

  test("sample filename never exempts real-looking tokens or remote credentials", () => {
    const fakeGithubToken = "ghp_" + "3".repeat(36);
    for (const filePath of [".env.example", "config.template", "config.sample"]) {
      assert.equal(secretScan(filePath, "GITHUB_TOKEN=" + fakeGithubToken).decision,
        "block", filePath);
      assert.equal(secretScan(filePath,
        "DATABASE_URL=postgres://user:pass@production.internal:5432/db").decision,
        "block", filePath);
      assert.equal(secretScan(filePath,
        "DATABASE_URL=postgres://user:ActualCredential123@localhost:5432/db").decision,
        "block", filePath);
      assert.equal(secretScan(filePath,
        "DATABASE_URL=postgres://user:pass@localhost:5432/db\nTOKEN=" + fakeGithubToken).decision,
        "block", filePath);
    }
  });

  test("a permitted template credential cannot conceal a later real credential", () => {
    const example = "DATABASE_URL=postgres://user:pass@localhost:5432/db";
    const actual = "DATABASE_URL=postgres://admin:ActualCredential123@production.internal:5432/db";
    assert.equal(secretScan(".env.example", example + "\n" + actual).decision, "block");
    const dynamic = "DATABASE_URL=postgres://user:${DB_PASSWORD}@localhost:5432/db";
    assert.equal(secretScan(".env.example", dynamic + "\n" + actual).decision, "block");
    assert.equal(secretScan(".env.example", example + "\n" + dynamic).decision, "pass");
  });

  test("Dalga 3 (G-06): numeric credentials on sensitive non-counter keys are redacted while counters stay intact", async () => {
    const { sanitizeObject } = await import("../dist/secrets/index.js");
    const { sanitized } = sanitizeObject({
      password: 849201,
      api_key: 99887766,
      passcode: 123456,
      pass: 12,
      secretCount: 3,
      tokenLength: 32,
    }, { includeRuntimeEnv: false });
    assert.equal(sanitized.password, "[REDACTED]", "numeric password must be redacted");
    assert.equal(sanitized.api_key, "[REDACTED]", "numeric api_key must be redacted");
    assert.equal(sanitized.passcode, "[REDACTED]", "numeric passcode must be redacted");
    assert.equal(sanitized.pass, 12, "non-sensitive pass counter must remain numeric");
    assert.equal(sanitized.secretCount, 3, "counter suffix key must remain numeric");
    assert.equal(sanitized.tokenLength, 32, "length suffix key must remain numeric");
  });

  test("Dalga 3 (G-07): inline quoted multi-word credentials are fully redacted", async () => {
    const { sanitizeString } = await import("../dist/secrets/index.js");
    const res1 = sanitizeString('login password="my super secret passphrase" done', { includeRuntimeEnv: false });
    assert.ok(!res1.sanitized.includes("super") && !res1.sanitized.includes("passphrase"), `full quoted double-quote secret must be redacted: ${res1.sanitized}`);
    assert.ok(res1.sanitized.includes("[REDACTED]"));

    const res2 = sanitizeString("auth token='alpha beta gamma' ok", { includeRuntimeEnv: false });
    assert.ok(!res2.sanitized.includes("beta") && !res2.sanitized.includes("gamma"), `full quoted single-quote secret must be redacted: ${res2.sanitized}`);
  });

  test("Dalga 3 (G-08): inherited toJSON serializer cannot reintroduce unsanitized secrets after sanitizeObject", async () => {
    const { sanitizeObject } = await import("../dist/secrets/index.js");
    const privateStore = new WeakMap();
    class SecretCarrier {
      constructor(publicText, hiddenSecret) {
        this.text = publicText;
        privateStore.set(this, hiddenSecret);
      }
      toJSON() {
        return { text: this.text, leaked: privateStore.get(this) ?? "from-prototype-toJSON-secret" };
      }
    }
    const carrier = new SecretCarrier("hello", "raw-private-secret-999");
    const { sanitized } = sanitizeObject(carrier, { includeRuntimeEnv: false });
    assert.equal(sanitized instanceof SecretCarrier, true, "class prototype must remain preserved");
    const serialized = JSON.stringify(sanitized);
    assert.ok(
      !serialized.includes("from-prototype-toJSON-secret") && !serialized.includes("raw-private-secret-999"),
      `inherited toJSON must not reintroduce unsanitized data: ${serialized}`
    );
  });

  test("Dalga 3 (G-21): RuntimeSecretRegistry.refreshEnv adds late-loaded env secrets and evicts rotated ones", async () => {
    const { RuntimeSecretRegistry } = await import("../dist/secrets/index.js");
    const reg = new RuntimeSecretRegistry();
    reg.clear();
    reg.refreshEnv({ MY_API_TOKEN: "initial-secret-token-111" });
    assert.ok(reg.getSecrets().includes("initial-secret-token-111"));
    reg.refreshEnv({ MY_API_TOKEN: "rotated-secret-token-222" });
    assert.ok(reg.getSecrets().includes("rotated-secret-token-222"), "rotated secret must be present");
    assert.ok(!reg.getSecrets().includes("initial-secret-token-111"), "stale rotated-out secret must be evicted");
  });

  test("R3 Dalga 1 (R3-016): custom Error subclass prototype toJSON and getters are neutralized by sanitizeObject", async () => {
    const { sanitizeObject } = await import("../dist/secrets/index.js");
    class CustomSdkError extends Error {
      constructor(msg) {
        super(msg);
        this.name = "CustomSdkError";
      }
      toJSON() {
        return { message: this.message, leakedSecret: "raw-error-proto-secret-777" };
      }
      get apiKey() {
        return "raw-getter-secret-888";
      }
    }
    const err = new CustomSdkError("request failed");
    const { sanitized } = sanitizeObject(err, { includeRuntimeEnv: false });
    assert.equal(sanitized instanceof CustomSdkError, true, "Error subclass prototype preserved");
    const json = JSON.stringify(sanitized);
    assert.ok(!json.includes("raw-error-proto-secret-777"), `Error prototype toJSON must not leak: ${json}`);
    assert.equal(sanitized.apiKey, "[REDACTED]", "Error prototype sensitive getter must be neutralized");
  });

  test("R3 Dalga 1 (R3-034): YAML block scalar body lines and >512-char quoted inline secrets are fully redacted", async () => {
    const { sanitizeString } = await import("../dist/secrets/index.js");
    const yaml = [
      "service: api",
      "client_secret: |-",
      "  line-one-secret-payload",
      "  line-two-secret-payload",
      "public_flag: true",
    ].join("\n");
    const resYaml = sanitizeString(yaml, { includeRuntimeEnv: false });
    assert.ok(!resYaml.sanitized.includes("line-one-secret-payload"), `YAML block line 1 must be redacted: ${resYaml.sanitized}`);
    assert.ok(!resYaml.sanitized.includes("line-two-secret-payload"), `YAML block line 2 must be redacted: ${resYaml.sanitized}`);
    assert.ok(resYaml.sanitized.includes("public_flag: true"), "non-indented following YAML key must remain intact");

    const longVal = "A".repeat(700);
    const resLong = sanitizeString(`auth token="${longVal}" done`, { includeRuntimeEnv: false });
    assert.ok(!resLong.sanitized.includes("AAAAAAAAAA"), `>512-char quoted secret must be redacted: ${resLong.sanitized}`);
    assert.ok(resLong.sanitized.includes("[REDACTED]"));
  });

  test("R3 Dalga 2 (R3-017): text-bearing Node Buffer containing secrets is redacted while binary Uint8Array media stays intact", async () => {
    const { sanitizeObject } = await import("../dist/secrets/index.js");
    const rawBuf = Buffer.from("Authorization: Bearer sk-proj-1234567890abcdefghijklmnop", "utf8");
    const media = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]);
    const { sanitized, redactedCount } = sanitizeObject({ stdout: rawBuf, media }, { includeRuntimeEnv: false });
    assert.ok(Buffer.isBuffer(sanitized.stdout), "redacted Buffer should remain a Buffer");
    assert.ok(!sanitized.stdout.toString("utf8").includes("sk-proj-1234567890"), "R3-017: Buffer secret must be redacted");
    assert.ok(redactedCount >= 1);
    assert.equal(sanitized.media instanceof Uint8Array, true);
    assert.deepEqual([...sanitized.media], [0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]);
  });

  test("R4 Wave 1 (R4-013, R4-014, R4-015, R4-020): RegExp/large Buffer redaction, non-envelope opencode-mesh UUID redaction, YAML sequence & >4096 inline secret redaction, and custom secret write preflight", async () => {
    const { sanitizeObject, sanitizeString } = await import("../dist/secrets/index.js");
    const { evaluateFileMutationPreflight } = await import("../dist/preflight.js");

    // R4-013: RegExp containing a secret and >256 KiB UTF-8 text Buffer must be redacted
    const secretKey = "sk-proj-" + "z".repeat(40);
    const reObj = sanitizeObject({ pattern: new RegExp(secretKey, "i") }, { includeRuntimeEnv: false });
    assert.ok(!reObj.sanitized.pattern.source.includes(secretKey), "R4-013: RegExp source secret must be redacted");
    const bigBuf = Buffer.from("log ".repeat(75_000) + `API_KEY=${secretKey}\n`, "utf8");
    assert.ok(bigBuf.byteLength > 256 * 1024);
    const bigRes = sanitizeObject({ stdout: bigBuf }, { includeRuntimeEnv: false });
    assert.ok(!bigRes.sanitized.stdout.toString("utf8").includes(secretKey), "R4-013: >256 KiB UTF-8 text Buffer must be redacted");

    // R4-014: arbitrary JSON tool output with { "opencode-mesh": { "token": "<uuid>" } } (not a V2 mesh envelope) must be redacted
    const fakeMeshJson = JSON.stringify({ "opencode-mesh": { token: "550e8400-e29b-41d4-a716-446655440000" } });
    const fakeMeshRes = sanitizeString(fakeMeshJson, { includeRuntimeEnv: false });
    assert.ok(!fakeMeshRes.sanitized.includes("550e8400-e29b-41d4-a716-446655440000"), "R4-014: non-envelope opencode-mesh UUID token must be redacted");

    // R4-015: YAML sequence block scalar with digit-before-chomp (|2-), YAML sequence inline, and >4096 char quoted secret
    const yamlSeq = [
      "items:",
      "  - api_secret: |2-",
      "      hidden-yaml-seq-secret-1",
      "      hidden-yaml-seq-secret-2",
      "  - token: inline-seq-secret-999",
      "  - public_name: hello",
    ].join("\n");
    const yamlSeqRes = sanitizeString(yamlSeq, { includeRuntimeEnv: false });
    assert.ok(!yamlSeqRes.sanitized.includes("hidden-yaml-seq-secret-1"), `R4-015: YAML sequence block scalar line 1 must be redacted: ${yamlSeqRes.sanitized}`);
    assert.ok(!yamlSeqRes.sanitized.includes("hidden-yaml-seq-secret-2"), `R4-015: YAML sequence block scalar line 2 must be redacted: ${yamlSeqRes.sanitized}`);
    assert.ok(!yamlSeqRes.sanitized.includes("inline-seq-secret-999"), `R4-015: YAML sequence inline secret must be redacted: ${yamlSeqRes.sanitized}`);
    assert.ok(yamlSeqRes.sanitized.includes("public_name: hello"));

    const hugeSecret = "S".repeat(5000) + "_TAIL_LEAK";
    const hugeRes = sanitizeString(`auth token="${hugeSecret}" end`, { includeRuntimeEnv: false });
    assert.ok(!hugeRes.sanitized.includes("_TAIL_LEAK"), `R4-015: >4096-char quoted secret tail must not leak: ${hugeRes.sanitized}`);

    // R4-020: file mutation preflight must catch configured customSecretValues
    const customSecret = "corp_internal_secret_987654321";
    assert.equal(
      evaluateFileMutationPreflight(
        "write",
        { path: "src/config.ts", content: `export const cfg = "${customSecret}";\n` },
        "strict",
        { customSecretValues: [customSecret], includeRuntimeEnv: false }
      ),
      "hardcoded-secret-in-file-write",
      "R4-020: configured customSecretValues must block in file write preflight"
    );
  });

  test("Re-audit closure: CRLF YAML block scalar, NUL-delimited Buffer, text Uint8Array, customSensitiveKeys RegExp/JSON/env, noSecretsRule write keys, and sanitizeMessages fake mesh", async () => {
    const { sanitizeObject, sanitizeString, sanitizeMessages } = await import("../dist/secrets/index.js");
    const { noSecretsRule, findAllSecretsInCode } = await import("../dist/rules/no-secrets.js");

    // CRLF YAML block scalar with trailing spaces
    const crlfYaml = "api_secret: |2-  \r\n  crlf-secret-line-1\r\n  crlf-secret-line-2\r\npublic: ok\r\n";
    const crlfRes = sanitizeString(crlfYaml, { includeRuntimeEnv: false });
    assert.ok(!crlfRes.sanitized.includes("crlf-secret-line-1"), `CRLF YAML secret line 1 leaked: ${crlfRes.sanitized}`);
    assert.ok(!crlfRes.sanitized.includes("crlf-secret-line-2"), `CRLF YAML secret line 2 leaked: ${crlfRes.sanitized}`);
    assert.ok(crlfRes.sanitized.includes("public: ok"));

    // NUL-delimited UTF-8 Buffer (/proc/self/environ style) and UTF-8 text Uint8Array must be redacted; binary PNG must stay untouched
    const secretVal = "sk-proj-" + "q".repeat(36);
    const environBuf = Buffer.from(`PATH=/usr/bin\0OPENAI_API_KEY=${secretVal}\0HOME=/root\0`, "utf8");
    const textU8 = new TextEncoder().encode(`token=${secretVal}\n`);
    const pngU8 = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00]);
    const binRes = sanitizeObject({ environBuf, textU8, pngU8 }, { includeRuntimeEnv: false });
    assert.ok(!binRes.sanitized.environBuf.toString("utf8").includes(secretVal), "NUL-delimited Buffer secret must be redacted");
    assert.ok(!new TextDecoder().decode(binRes.sanitized.textU8).includes(secretVal), "text Uint8Array secret must be redacted");
    assert.deepEqual([...binRes.sanitized.pngU8], [...pngU8], "binary PNG Uint8Array must stay byte-identical");

    // sanitizeMessages must redact forged non-envelope metadata["opencode-mesh"].token
    const forgedMsgs = [
      {
        role: "tool",
        content: "ok",
        metadata: { "opencode-mesh": { token: "550e8400-e29b-41d4-a716-446655440000" } },
      },
    ];
    const sanMsgs = sanitizeMessages(forgedMsgs, { includeRuntimeEnv: false });
    assert.ok(!JSON.stringify(sanMsgs).includes("550e8400-e29b-41d4-a716-446655440000"), "forged non-envelope opencode-mesh token in sanitizeMessages must be redacted");

    // customSensitiveKeys: RegExp + JSON quoted + unquoted env + second match after template
    const jsonCustomFindings = findAllSecretsInCode(
      '{"acme_vault": "${PLACEHOLDER}", "acme_vault_prod": "super-secret-value-999"}\n',
      "config.json",
      undefined,
      { customSensitiveKeys: [/^acme_vault/i] }
    );
    assert.equal(jsonCustomFindings.length, 1, "customSensitiveKeys must loop past template value and catch JSON quoted secret");
    const envCustomFindings = findAllSecretsInCode(
      "ACME_VAULT=unquoted-secret-value-777\n",
      ".env",
      undefined,
      { customSensitiveKeys: [/^acme_vault/i] }
    );
    assert.equal(envCustomFindings.length, 1, "customSensitiveKeys must catch unquoted .env secret via RegExp key");

    // Pass-2 re-audit: embedded JSON redaction, linear-time hyphen runs, TS type/safeKeyNames/300+ lines
    const embeddedJsonRes = sanitizeString('HTTP 200 OK: {"password": "my_real_secret_value"}', { includeRuntimeEnv: false });
    assert.ok(!embeddedJsonRes.sanitized.includes("my_real_secret_value"), "embedded JSON quoted secret must be redacted");
    const t0 = Date.now();
    sanitizeString("-".repeat(20_000), { includeRuntimeEnv: false });
    assert.ok(Date.now() - t0 < 250, "long hyphen run must run in linear time without ReDoS");

    assert.equal(
      findAllSecretsInCode("export interface AppConfig { MY_CUSTOM_KEY: string; }\nconst v = env.MY_CUSTOM_KEY;\n", "src/config.ts", undefined, { customSensitiveKeys: ["MY_CUSTOM_KEY"] }).length,
      0,
      "TypeScript type annotations and property lookups must not false-positive under customSensitiveKeys"
    );
    assert.equal(
      findAllSecretsInCode('INTERNAL_PUBLIC = "https://example.com/public"', "src/config.ts", undefined, { customSensitiveKeys: [/^INTERNAL_/i], safeKeyNames: ["INTERNAL_PUBLIC"] }).length,
      0,
      "safeKeyNames must exclude matching keys from customSensitiveKeys"
    );
    const bigFile = Array.from({ length: 300 }, (_, i) => `const k${i} = "normal_${i}";`).join("\n") + '\nconst MY_CUSTOM_KEY = "real_secret_value_12345";\n';
    assert.equal(
      findAllSecretsInCode(bigFile, "src/big.ts", undefined, { customSensitiveKeys: ["MY_CUSTOM_KEY"] }).length,
      1,
      "customSensitiveKeys must scan past 256 assignments in normal files"
    );

    // R5-018: object keys containing credentials/secrets must be redacted (including JSON fast-path)
    const keyLeakJson = JSON.stringify({ "https://admin:super_secret_pw@db.internal": 1, token: "tok-1234567890" });
    const keyLeakSan = sanitizeString(keyLeakJson, { includeRuntimeEnv: false });
    assert.ok(!keyLeakSan.sanitized.includes("super_secret_pw"), `R5-018: credential in JSON object key must be redacted: ${keyLeakSan.sanitized}`);
    const objKeyLeak = sanitizeObject({ "sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "val1", "sk-proj-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": "val2" }, { includeRuntimeEnv: false });
    assert.ok(!JSON.stringify(objKeyLeak.sanitized).includes("sk-proj-"), "R5-018: secret object keys must be redacted");
    assert.equal(Object.keys(objKeyLeak.sanitized).length, 2, "R5-018: colliding redacted keys must preserve both values");

    // Pass-2 re-audit: normal HTTP URLs with ports + @ in query/fragment must NOT be corrupted;
    // reverse-order key collision and Error custom keys must be handled safely
    for (const safeUrl of [
      "http://localhost:3000?email=alice@example.com",
      "https://api.example.com:8443?pkg=@opencode/plugin",
      "https://example.com:8080#user@host",
      "http://[::1]:3000?email=alice@example.com",
    ]) {
      assert.equal(sanitizeString(safeUrl, { includeRuntimeEnv: false }).sanitized, safeUrl, `normal URL must not be corrupted: ${safeUrl}`);
    }
    const revCollision = sanitizeObject({ "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "from-secret", "[REDACTED]": "from-literal" }, { includeRuntimeEnv: false });
    assert.equal(Object.keys(revCollision.sanitized).length, 2, "reverse-order redacted/literal key collision must preserve both entries");
    const errWithSecretKey = new Error("failed");
    errWithSecretKey["https://admin:s3cr3tPass@api.example.com/v1"] = "500";
    const sanErr = sanitizeObject(errWithSecretKey, { includeRuntimeEnv: false });
    assert.ok(!Object.getOwnPropertyNames(sanErr.sanitized).some((k) => k.includes("s3cr3tPass")), "Error own property keys must be redacted");

    // 512 KiB seam straddling customSensitiveKeys assignment must not be missed
    const seamCode = "a".repeat(512 * 1024 - 18) + '\nmyCustomKey = "secret_value_999"\n';
    assert.equal(
      findAllSecretsInCode(seamCode, "app.ts", undefined, { customSensitiveKeys: ["myCustomKey"] }).length,
      1,
      "customSensitiveKeys assignment straddling 512 KiB offset must be detected"
    );

    // R5-022: customSensitiveKeys appended at tail of >512 KiB file must still be detected
    const hugeCustomFile = "const pad = 1;\n".repeat(40_000) + '\nconst MY_TAIL_KEY = "tail_secret_value_99999";\n';
    assert.ok(hugeCustomFile.length > 512 * 1024);
    assert.equal(
      findAllSecretsInCode(hugeCustomFile, "src/huge.ts", undefined, { customSensitiveKeys: ["MY_TAIL_KEY"] }).length,
      1,
      "R5-022: customSensitiveKeys at tail of >512 KiB file must still be detected"
    );

    // noSecretsRule must inspect all 5 extra write keys (new_str, file_text, CodeContent, ReplacementContent, text)
    for (const [key, fileKey] of [
      ["new_str", "path"],
      ["file_text", "path"],
      ["CodeContent", "TargetFile"],
      ["ReplacementContent", "TargetFile"],
      ["text", "path"],
    ]) {
      const res = noSecretsRule.inspect({
        sessionID: `s-key-${key}`,
        directory: process.cwd(),
        currentTurn: [{
          info: { id: "a1", role: "assistant" },
          parts: [{
            type: "tool",
            tool: "write_to_file",
            state: { status: "completed", input: { [fileKey]: "src/auth.ts", [key]: `export const K = "${secretVal}";` } },
          }],
        }],
        history: [],
        ruleConfig: {},
      });
      assert.equal(res.decision, "block", `noSecretsRule must scan write key '${key}'`);
    }
  });
});
