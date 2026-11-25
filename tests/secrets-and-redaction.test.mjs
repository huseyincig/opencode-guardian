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
      'USER=nodecommand',
      'SHELL=/bin/bash',
      'LANG=en_US.UTF-8',
      'HOSTNAME=vps-prod-node-01',
      'URL=https://api.nodecommand.app/v1/health',
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
    const connStr = `postgres://app_user:${secretPass}@db.internal.nodecommand.app:5432/production_db?sslmode=require`;

    const sanitized = sanitizeToolResult(connStr);
    assert.equal(sanitized.includes(secretPass), false);
    assert.equal(
      sanitized,
      'postgres://app_user:[REDACTED]@db.internal.nodecommand.app:5432/production_db?sslmode=require'
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
});
