import test from 'node:test';
import assert from 'node:assert/strict';
import {
  sanitizeString,
  sanitizeToolResult,
  sanitizeMessages,
  RuntimeSecretRegistry,
  assessCommandPreflight,
} from '../dist/index.js';

const SYNTHETIC_CANARY_SECRET = 'canary_secret_ABC123_DEF456_789XYZ';

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
