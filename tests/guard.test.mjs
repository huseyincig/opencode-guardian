import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { GuardEngine, REMEDIATION_MARKER, BUILTIN_RULES, loadConfig, GuardianConfigError } from "../dist/engine.js";
import { noEvasionRule } from "../dist/rules/no-evasion.js";
import { noShortcutsRule } from "../dist/rules/no-shortcuts.js";
import { noStubsRule } from "../dist/rules/no-stubs.js";
import { noTruncationRule } from "../dist/rules/no-truncation.js";
import { noCheatRule } from "../dist/rules/no-cheat.js";
import { noSecretsRule } from "../dist/rules/no-secrets.js";
import { noGhostDepsRule, clearDeclaredDepsCache } from "../dist/rules/no-ghost-deps.js";
import { circuitBreakerRule } from "../dist/rules/circuit-breaker.js";
import { noApologyRule } from "../dist/rules/no-apology.js";
import { noUnverifiedClaimsRule } from "../dist/rules/no-unverified-claims.js";
import { noSilentFailureRule } from "../dist/rules/no-silent-failure.js";
import { destructiveOperationsRule } from "../dist/rules/destructive-operations.js";
import { collectTurnEvidence, normalizeErrorFingerprint } from "../dist/evidence.js";
import { extractTaskContract, taskGuidance } from "../dist/task-contract.js";
import { taskCompletionRule } from "../dist/rules/task-completion.js";
import { instructionFidelityRule } from "../dist/rules/instruction-fidelity.js";
import OpencodeGuardian, { normalizeV2Messages } from "../dist/index.js";

// --- 1. discipline/no-evasion ---
test("discipline/no-evasion rule detects dismissal phrases", () => {
  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "text",
            text: "I finished the feature. The test failure is unrelated to this change.",
          },
        ],
      },
    ],
  };

  const result = noEvasionRule.inspect(context);
  assert.equal(result.decision, "block");
  assert.equal(result.findings[0].pattern, "unrelated to this change");
  assert.equal(result.ruleId, "discipline/no-evasion");
});

// --- 2. quality/no-shortcuts ---
test("quality/no-shortcuts rule detects hedging and shortcuts", () => {
  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [{ type: "text", text: "This basic implementation is good enough for now." }],
      },
    ],
  };

  const result = noShortcutsRule.inspect(context);
  assert.equal(result.decision, "block");
  assert.equal(result.ruleId, "quality/no-shortcuts");
  assert.ok(result.findings.length >= 2);
});

// --- 3. integrity/no-stubs ---
test("integrity/no-stubs rule detects throw NotImplementedError", () => {
  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                content: "function calculate() {\n  throw new NotImplementedError('todo');\n}",
              },
            },
          },
        ],
      },
    ],
  };

  const result = noStubsRule.inspect(context);
  assert.equal(result.decision, "block");
  assert.equal(result.ruleId, "integrity/no-stubs");
  assert.equal(result.findings[0].pattern, "throw NotImplementedError");
  assert.ok(result.remediationPrompt.includes("Incomplete or stubbed implementation"));
});

test("integrity/no-stubs rule passes complete implementation", () => {
  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                content: "function add(a, b) {\n  return a + b;\n}",
              },
            },
          },
        ],
      },
    ],
  };

  const result = noStubsRule.inspect(context);
  assert.equal(result.decision, "pass");
});

// --- 4. safety/no-truncation ---
test("safety/no-truncation rule detects lazy code placeholders", () => {
  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                content: "class App {\n  // ... existing code unchanged ...\n  newMethod() {}\n}",
              },
            },
          },
        ],
      },
    ],
  };

  const result = noTruncationRule.inspect(context);
  assert.equal(result.decision, "block");
  assert.equal(result.ruleId, "safety/no-truncation");
  assert.ok(result.remediationPrompt.includes("Lazy code truncation placeholder detected"));
});

test("safety/no-truncation rule passes untruncated code", () => {
  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                content: "class App {\n  oldMethod() {}\n  newMethod() {}\n}",
              },
            },
          },
        ],
      },
    ],
  };

  const result = noTruncationRule.inspect(context);
  assert.equal(result.decision, "pass");
});

// --- 5. testing/no-cheat ---
test("testing/no-cheat rule detects it.skip in test files", () => {
  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: { blockStructuralTestChanges: true },
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                filePath: "src/calculator.test.ts",
                content: "describe('calc', () => {\n  it.skip('handles division', () => {});\n});",
              },
            },
          },
        ],
      },
    ],
  };

  const result = noCheatRule.inspect(context);
  assert.equal(result.decision, "block");
  assert.equal(result.ruleId, "testing/no-cheat");
  assert.equal(result.findings[0].pattern, "test.skip() / it.skip() (JS/TS)");
  assert.ok(result.remediationPrompt.includes("Test integrity violation detected"));
});

test("testing/no-cheat rule detects commented-out expect/assert in test files", () => {
  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: { blockStructuralTestChanges: true },
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                filePath: "tests/auth.spec.js",
                content: "test('login', () => {\n  // expect(user).toBeDefined();\n});",
              },
            },
          },
        ],
      },
    ],
  };

  const result = noCheatRule.inspect(context);
  assert.equal(result.decision, "block");
  assert.equal(result.findings[0].pattern, "commented-out assertion (expect / assert)");
});

// --- 6. security/no-secrets ---
test("security/no-secrets rule detects hardcoded OpenAI and GitHub tokens", () => {
  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                filePath: "src/client.ts",
                content: "const token = 'ghp_" + "111122223333444455556666777788889999';\nconst aiKey = 'sk-" + "proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD';",
              },
            },
          },
        ],
      },
    ],
  };

  const result = noSecretsRule.inspect(context);
  assert.equal(result.decision, "block");
  assert.equal(result.ruleId, "security/no-secrets");
  assert.equal(result.findings.length, 2);
  assert.ok(result.remediationPrompt.includes("Hardcoded secret or credential detected"));
});

test("security/no-secrets scans real-looking credentials in template and example files", () => {
  const fakeToken = "ghp_" + "1".repeat(36);
  for (const filePath of [".env.example", "settings.template", "auth.sample", "src/config.env.example"]) {
    const context = {
      sessionID: "sample-credentials", directory: "/tmp", messages: [], ruleConfig: {},
      currentTurn: [{ info: { id: "msg-1", role: "assistant" }, parts: [{
        type: "tool", state: { input: { filePath, content: "GITHUB_TOKEN=" + fakeToken } },
      }] }],
    };
    const result = noSecretsRule.inspect(context);
    assert.equal(result.decision, "block", filePath);
    assert.equal(result.findings.length, 1, filePath);
  }
});

test("security/no-secrets permits explicit placeholder values in example files", () => {
  const context = {
    sessionID: "sample-placeholders", directory: "/tmp", messages: [], ruleConfig: {},
    currentTurn: [{ info: { id: "msg-1", role: "assistant" }, parts: [{
      type: "tool", state: { input: {
        filePath: ".env.example",
        content: "GITHUB_TOKEN=<YOUR_TOKEN>\nDATABASE_URL=postgres://user:${DB_PASSWORD}@localhost:5432/app",
      } },
    }] }],
  };
  assert.equal(noSecretsRule.inspect(context).decision, "pass");
});

// --- 7. manifest/no-ghost-deps ---
test("manifest/no-ghost-deps rule detects unlisted imports", () => {
  const context = {
    sessionID: "test-sess",
    directory: process.cwd(),
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                filePath: "src/feature.ts",
                content: "import lodash from 'lodash';\nimport fs from 'node:fs';\nimport { GuardEngine } from './engine.js';",
              },
            },
          },
        ],
      },
    ],
  };

  const result = noGhostDepsRule.inspect(context);
  assert.equal(result.decision, "block");
  assert.equal(result.ruleId, "manifest/no-ghost-deps");
  assert.equal(result.findings[0].pattern, "lodash");
  assert.ok(result.remediationPrompt.includes("Ghost/undeclared dependency detected"));
});

// --- 8. runtime/circuit-breaker ---
test("runtime/circuit-breaker rule detects 3 identical tool errors", () => {
  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          { type: "tool", state: { status: "error", error: "FATAL: Connection refused on port 5432" } },
          { type: "tool", state: { status: "error", error: "FATAL: Connection refused on port 5432" } },
          { type: "tool", state: { status: "error", error: "FATAL: Connection refused on port 5432" } },
        ],
      },
    ],
  };

  const result = circuitBreakerRule.inspect(context);
  assert.equal(result.decision, "block");
  assert.equal(result.ruleId, "runtime/circuit-breaker");
  assert.equal(result.findings[0].pattern, "Repeated error loop");
  assert.ok(result.remediationPrompt.includes("Circuit breaker tripped"));
});

// --- GuardEngine Full Integration ---
test("GuardEngine lifecycle and synthetic prompt loop guard", async () => {
  const engine = new GuardEngine({
    enabled: true,
  });

  const sessionID = "sess-123";
  const messages = [
    {
      info: { id: "u-1", role: "user" },
      parts: [{ type: "text", text: "Fix the bug" }],
    },
    {
      info: { id: "a-1", role: "assistant" },
      parts: [
        {
          type: "text",
          text: "I did not fix this because it is already broken on main.",
        },
      ],
    },
  ];

  // First inspection -> must BLOCK
  const result1 = await engine.inspect(sessionID, "/tmp", messages);
  assert.equal(result1.decision, "block");

  // Synthetic remediation prompt sent by detector
  const messagesAfterRemediation = [
    ...messages,
    {
      info: { id: "u-2", role: "user" },
      parts: [{ type: "text", text: result1.combinedRemediationPrompt, synthetic: true }],
    },
    {
      info: { id: "a-2", role: "assistant" },
      parts: [
        {
          type: "text",
          text: "Here is the evidence for already broken on main: commit abc1234.",
        },
      ],
    },
  ];

  // Second inspection -> must PASS to prevent infinite loop!
  const result2 = await engine.inspect(sessionID, "/tmp", messagesAfterRemediation);
  assert.equal(result2.decision, "pass");
});

test("quality/no-shortcuts localized exception boundary checking", () => {
  // Case A: TemporaryDirectory alone should pass
  const contextA = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [{ type: "text", text: "I created a TemporaryDirectory to store test fixtures." }],
      },
    ],
  };
  assert.equal(noShortcutsRule.inspect(contextA).decision, "pass");

  // Case B: TemporaryDirectory mentioned BUT text also contains a shortcut phrase -> must BLOCK
  const contextB = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "text",
            text: "Using TemporaryDirectory for tests, this temporary fix is good enough for now.",
          },
        ],
      },
    ],
  };
  const resB = noShortcutsRule.inspect(contextB);
  assert.equal(resB.decision, "block");
  assert.ok(resB.findings.some((f) => f.pattern === "good enough"));
});

test("testing/no-cheat does not false-positive on regular comments in non-test files", () => {
  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                filePath: "src/auth/service.ts",
                content: "// assert that session is still valid\nif (!session) return false;",
              },
            },
          },
        ],
      },
    ],
  };
  const res = noCheatRule.inspect(context);
  assert.equal(res.decision, "pass");
});

test("testing/no-cheat resolves target file from patch header +++ b/...", () => {
  const patchContent =
    "--- a/tests/unit.test.ts\n" +
    "+++ b/tests/unit.test.ts\n" +
    "@@ -10,3 +10,4 @@\n" +
    "+  it.skip('broken test', () => {});\n";

  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                patch: patchContent,
              },
            },
          },
        ],
      },
    ],
  };
  const res = noCheatRule.inspect(context);
  assert.equal(res.decision, "block");
  assert.equal(res.ruleId, "testing/no-cheat");
});

test("security/no-secrets ignores template variables and env references", () => {
  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                filePath: "src/db.ts",
                content: "const uri = `postgres://user:${process.env.DB_PASSWORD}@localhost:5432/app`;",
              },
            },
          },
        ],
      },
    ],
  };
  const res = noSecretsRule.inspect(context);
  assert.equal(res.decision, "pass");
});

test("runtime/circuit-breaker correctly serializes object errors", () => {
  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          { type: "tool", state: { status: "error", error: { message: "SQLSTATE[HY000]: General error: 2006 MySQL server has gone away" } } },
          { type: "tool", state: { status: "error", error: { message: "SQLSTATE[HY000]: General error: 2006 MySQL server has gone away" } } },
          { type: "tool", state: { status: "error", error: { message: "SQLSTATE[HY000]: General error: 2006 MySQL server has gone away" } } },
        ],
      },
    ],
  };
  const res = circuitBreakerRule.inspect(context);
  assert.equal(res.decision, "block");
  assert.equal(res.ruleId, "runtime/circuit-breaker");
});

test("runtime/circuit-breaker detects 3 identical non-zero exit commands (bash completed state)", () => {
  const bashPart = () => ({
    type: "tool",
    state: {
      status: "completed",
      output: "cat: /missing.txt: No such file or directory\n\n[exit code: 1]",
      metadata: { exit: 1, output: "cat: /missing.txt: No such file or directory\n\n[exit code: 1]" },
    },
  });

  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      { info: { id: "msg-1", role: "assistant" }, parts: [bashPart(), bashPart(), bashPart()] },
    ],
  };

  const res = circuitBreakerRule.inspect(context);
  assert.equal(res.decision, "block");
  assert.equal(res.ruleId, "runtime/circuit-breaker");
  assert.ok(res.remediationPrompt.includes("Circuit breaker tripped"));
});

test("runtime/circuit-breaker ignores successful commands with exit 0", () => {
  const okPart = () => ({
    type: "tool",
    state: {
      status: "completed",
      output: "all good\n\n[exit code: 0]",
      metadata: { exit: 0, output: "all good\n\n[exit code: 0]" },
    },
  });

  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      { info: { id: "msg-1", role: "assistant" }, parts: [okPart(), okPart(), okPart()] },
    ],
  };

  assert.equal(circuitBreakerRule.inspect(context).decision, "pass");
});

test("GuardEngine severity warn does not block", async () => {
  const engine = new GuardEngine({
    enabled: true,
    rules: {
      "quality/no-shortcuts": "warn",
    },
  });

  const sessionID = "sess-warn";
  const messages = [
    {
      info: { id: "u-1", role: "user" },
      parts: [{ type: "text", text: "Do work" }],
    },
    {
      info: { id: "a-1", role: "assistant" },
      parts: [{ type: "text", text: "This is good enough for now." }],
    },
  ];

  const result = await engine.inspect(sessionID, "/tmp", messages);
  assert.equal(result.decision, "pass");
});

test("GuardEngine passes isSubagent flag to inspection context", async () => {
  let capturedIsSubagent = null;

  const engine = new GuardEngine();
  engine.registerRule({
    id: "test/subagent-checker",
    description: "Checks if isSubagent is properly propagated",
    inspect: (context) => {
      capturedIsSubagent = context.isSubagent;
      return { ruleId: "test/subagent-checker", decision: "pass", findings: [] };
    },
  });

  const messages = [
    {
      info: { id: "u-1", role: "user", agent: "research" },
      parts: [{ type: "text", text: "Research the bug" }],
    },
    {
      info: { id: "a-1", role: "assistant" },
      parts: [{ type: "text", text: "I looked into the codebase." }],
    },
  ];

  await engine.inspect("sess-sub", "/tmp", messages);
  assert.equal(capturedIsSubagent, true);
});

// --- 9. discipline/no-apology ---
test("discipline/no-apology detects English apology phrases", () => {
  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [{ type: "text", text: "I sincerely apologize for the mistake. I am so sorry for the confusion." }],
      },
    ],
  };

  const result = noApologyRule.inspect(context);
  assert.equal(result.decision, "block");
  assert.equal(result.ruleId, "discipline/no-apology");
  assert.ok(result.findings.some((f) => f.pattern === "English"));
  assert.ok(result.remediationPrompt.includes("Excessive apology / sycophancy language detected"));
});

test("discipline/no-apology detects Turkish apology phrases", () => {
  const context = {
    sessionID: "test-sess",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [{ type: "text", text: "Çok özür dilerim, kusura bakmayın hata benden kaynaklandı." }],
      },
    ],
  };

  const result = noApologyRule.inspect(context);
  assert.equal(result.decision, "block");
  assert.equal(result.ruleId, "discipline/no-apology");
  assert.ok(result.findings.some((f) => f.pattern === "Turkish"));
});

test("discipline/no-apology detects German, French, Spanish, and Russian apologies", () => {
  for (const [lang, phrase] of [
    ["German", "Es tut mir leid, das war mein Fehler."],
    ["French", "Je suis désolé pour cette confusion."],
    ["Spanish", "Lo siento mucho, me equivoqué."],
    ["Russian", "Извините за ошибku, сейчас всё исправлю."],
  ]) {
    const context = {
      sessionID: `test-${lang}`,
      directory: "/tmp",
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "msg-1", role: "assistant" },
          parts: [{ type: "text", text: phrase }],
        },
      ],
    };
    const result = noApologyRule.inspect(context);
    assert.equal(result.decision, "block", `Expected block for ${lang}: "${phrase}"`);
    assert.equal(result.ruleId, "discipline/no-apology");
    assert.equal(result.findings[0].pattern, lang);
  }
});

test("discipline/no-apology passes clean direct technical response and non-apology usages", () => {
  for (const cleanText of [
    "Root cause identified in config.ts:42. Patch applied and verified with test suite.",
    "The user requested an apology letter generator template.",
    "Bu fonksiyon nesneyi özelleştirir ve kaydeder.",
  ]) {
    const context = {
      sessionID: "test-clean",
      directory: "/tmp",
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "msg-1", role: "assistant" },
          parts: [{ type: "text", text: cleanText }],
        },
      ],
    };

    const result = noApologyRule.inspect(context);
    assert.equal(result.decision, "pass", `Expected pass for: "${cleanText}"`);
    assert.equal(result.findings.length, 0);
  }
});

test("prose rules ignore citations, backticks, blockquotes, and quoted patterns", () => {
  // 1. no-apology ignores quotes & backticks
  const apologyContext = {
    sessionID: "test-quotes-1",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "text",
            text: 'Ben bilerek *"Çok özür dilerim"* yazdım ve `I am so sorry` kalıbını test ettim.\n> "Excessive apology detected: I apologize"\nÖzür dileme konusunu inceledik.',
          },
        ],
      },
    ],
  };
  assert.equal(noApologyRule.inspect(apologyContext).decision, "pass");

  // 2. no-shortcuts ignores code markers inside inline backticks in prose
  const shortcutsContext = {
    sessionID: "test-quotes-2",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "text",
            text: "Bu kural `hardcoded`, `placeholder` ve `TODO` kelimelerini inceler ve engeller.",
          },
        ],
      },
    ],
  };
  assert.equal(noShortcutsRule.inspect(shortcutsContext).decision, "pass");

  // 3. no-evasion ignores quoted evasion phrases in prose
  const evasionContext = {
    sessionID: "test-quotes-3",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "msg-1", role: "assistant" },
        parts: [
          {
            type: "text",
            text: 'The detector caught: "unrelated to this change" and "already broken on main".',
          },
        ],
      },
    ],
  };
  assert.equal(noEvasionRule.inspect(evasionContext).decision, "pass");
});

test("manifest/no-ghost-deps resolves deps from the target file's own package", () => {
  clearDeclaredDepsCache();

  // Package A declares @babel/core (the exact cross-package FP seen in production).
  const pkgA = fs.mkdtempSync(path.join(os.tmpdir(), "guardpkg-a-"));
  fs.writeFileSync(
    path.join(pkgA, "package.json"),
    JSON.stringify({ name: "pkg-a", devDependencies: { "@babel/core": "^7.0.0" } })
  );
  const fileA = path.join(pkgA, "scripts", "emit.mjs");
  fs.mkdirSync(path.dirname(fileA), { recursive: true });

  // Session root is a DIFFERENT package that declares nothing.
  const pkgB = fs.mkdtempSync(path.join(os.tmpdir(), "guardpkg-b-"));
  fs.writeFileSync(path.join(pkgB, "package.json"), JSON.stringify({ name: "pkg-b", dependencies: {} }));
  const fileB = path.join(pkgB, "src", "x.ts");
  fs.mkdirSync(path.dirname(fileB), { recursive: true });

  const mkCtx = (targetFile, content) => ({
    sessionID: "ghost-ctx",
    directory: pkgB,
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "m1", role: "assistant" },
        parts: [{ type: "tool", state: { input: { filePath: targetFile, content } } }],
      },
    ],
  });

  // Owned by pkgA -> @babel/core IS declared there -> must PASS (no cross-package FP)
  assert.equal(
    noGhostDepsRule.inspect(mkCtx(fileA, 'import babel from "@babel/core";')).decision,
    "pass"
  );

  // Owned by pkgB -> lodash is NOT declared anywhere -> must BLOCK
  const blocked = noGhostDepsRule.inspect(
    mkCtx(fileB, 'import lodash from "lodash";')
  );
  assert.equal(blocked.decision, "block");
  assert.equal(blocked.findings[0].pattern, "lodash");

  fs.rmSync(pkgA, { recursive: true, force: true });
  fs.rmSync(pkgB, { recursive: true, force: true });
});

test("manifest/no-ghost-deps resolves RELATIVE target paths against the session directory", () => {
  clearDeclaredDepsCache();

  const pkg = fs.mkdtempSync(path.join(os.tmpdir(), "guardpkg-rel-"));
  fs.writeFileSync(
    path.join(pkg, "package.json"),
    JSON.stringify({ name: "pkg-rel", dependencies: { chalk: "^5.0.0" } })
  );

  // Relative path must resolve against the session dir, NOT process.cwd().
  const res = noGhostDepsRule.inspect({
    sessionID: "ghost-rel",
    directory: pkg,
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "m1", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                filePath: "src/logger.ts",
                content: 'import chalk from "chalk";\nexport const ok = true;',
              },
            },
          },
        ],
      },
    ],
  });

  assert.equal(res.decision, "pass");
  fs.rmSync(pkg, { recursive: true, force: true });
});

test("plugin exports OpencodeGuardian with id 'opencode-guardian' and backward-compatible OpencodeGuard alias", async () => {
  const pluginMod = await import("../dist/index.js");
  assert.equal(pluginMod.OpencodeGuardian.id, "opencode-guardian");
  assert.equal(typeof pluginMod.OpencodeGuardian.server, "function");
  assert.equal(typeof pluginMod.OpencodeGuardian.setup, "function");
  assert.equal(pluginMod.default, pluginMod.OpencodeGuardian);
  assert.equal(pluginMod.OpencodeGuard, pluginMod.OpencodeGuardian);
});

test("root index.js and server.js re-export plugin cleanly", async () => {
  const rootIndex = await import("../index.js");
  const rootServer = await import("../server.js");
  assert.equal(rootIndex.OpencodeGuardian.id, "opencode-guardian");
  assert.equal(rootIndex.default.id, "opencode-guardian");
  assert.equal(rootServer.OpencodeGuardian.id, "opencode-guardian");
  assert.equal(rootServer.default.id, "opencode-guardian");
});

test("loadConfig supports opencode-guardian.json and falls back to opencode-guard.json", async () => {
  const { loadConfig } = await import("../dist/engine.js");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-cfg-"));

  // 1. When opencode-guardian.json exists
  fs.writeFileSync(
    path.join(tmpDir, "opencode-guardian.json"),
    JSON.stringify({ enabled: true, rules: { "testing/no-cheat": "off" } })
  );
  let cfg = loadConfig(tmpDir);
  assert.equal(cfg.rules["testing/no-cheat"], "off");

  // 2. When only opencode-guard.json exists (backward compat)
  fs.unlinkSync(path.join(tmpDir, "opencode-guardian.json"));
  fs.writeFileSync(
    path.join(tmpDir, "opencode-guard.json"),
    JSON.stringify({ enabled: true, rules: { "testing/no-cheat": "warn" } })
  );
  cfg = loadConfig(tmpDir);
  assert.equal(cfg.rules["testing/no-cheat"], "warn");

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("GuardEngine honors object severity off", async () => {
  const engine = new GuardEngine({
    enabled: true,
    rules: {
      "discipline/no-evasion": { severity: "off" },
      "discipline/no-apology": "off",
      "quality/no-shortcuts": "off",
      "integrity/no-stubs": "off",
      "safety/no-truncation": "off",
      "testing/no-cheat": "off",
      "security/no-secrets": "off",
      "manifest/no-ghost-deps": "off",
      "runtime/circuit-breaker": "off",
    },
  });

  const result = await engine.inspect("severity-off", "/tmp", [
    { info: { id: "u-off", role: "user" }, parts: [{ type: "text", text: "check" }] },
    { info: { id: "a-off", role: "assistant" }, parts: [{ type: "text", text: "This is unrelated to this change." }] },
  ]);

  assert.equal(result.decision, "pass");
});

test("quality/no-shortcuts ignores empty configured exceptions without hanging", () => {
  const context = {
    sessionID: "empty-exception",
    directory: "/tmp",
    messages: [],
    ruleConfig: { exceptions: [""] },
    currentTurn: [
      {
        info: { id: "a-empty", role: "assistant" },
        parts: [{ type: "text", text: "This temporary fix is good enough for now." }],
      },
    ],
  };
  assert.equal(noShortcutsRule.inspect(context).decision, "block");
});

test("security/no-secrets does not bypass real-looking secrets containing test/sample words", () => {
  const cases = [
    "const key = 'sk-aaaaaaaaaaaaaaaaatestbbbbbbbbbbbbbbbbbbbbbbbb';",
    "const db = 'postgres://admin:SuperSecretPassword@db.example.com/testdb';",
  ];

  for (const content of cases) {
    const context = {
      sessionID: "secret-substring",
      directory: "/tmp",
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-secret-substring", role: "assistant" },
          parts: [{ type: "tool", state: { input: { path: "src/config.ts", content } } }],
        },
      ],
    };
    assert.equal(noSecretsRule.inspect(context).decision, "block");
  }
});

test("manifest/no-ghost-deps stops at the nearest package boundary", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-monorepo-"));
  const child = path.join(root, "packages", "child");
  fs.mkdirSync(path.join(child, "src"), { recursive: true });
  fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ dependencies: { lodash: "1.0.0" } }));
  fs.writeFileSync(path.join(child, "package.json"), JSON.stringify({ name: "child", dependencies: {} }));
  clearDeclaredDepsCache();

  const context = {
    sessionID: "monorepo",
    directory: child,
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "a-monorepo", role: "assistant" },
        parts: [{ type: "tool", state: { input: { path: path.join(child, "src", "x.js"), content: 'import lodash from "lodash";' } } }],
      },
    ],
  };

  assert.equal(noGhostDepsRule.inspect(context).decision, "block");
});

test("manifest/no-ghost-deps detects dynamic imports but ignores comments and string examples", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-imports-"));
  fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ dependencies: {} }));

  clearDeclaredDepsCache();
  const dynamicContext = {
    sessionID: "dynamic-import",
    directory: root,
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "a-dynamic", role: "assistant" },
        parts: [{ type: "tool", state: { input: { path: path.join(root, "src.js"), content: 'const mod = await import("lodash");' } } }],
      },
    ],
  };
  assert.equal(noGhostDepsRule.inspect(dynamicContext).decision, "block");

  clearDeclaredDepsCache();
  const docsContext = {
    ...dynamicContext,
    sessionID: "docs-import",
    currentTurn: [
      {
        info: { id: "a-docs", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                path: path.join(root, "docs.js"),
                content: '// docs: import lodash from "lodash";\nconst example = \'require("axios")\';',
              },
            },
          },
        ],
      },
    ],
  };
  assert.equal(noGhostDepsRule.inspect(docsContext).decision, "pass");
});

test("testing/no-cheat recognizes Windows and root-level Python test paths", () => {
  for (const filePath of ["C:\\repo\\tests\\foo.py", "/repo/test_auth.py"]) {
    const context = {
      sessionID: "test-paths",
      directory: "/tmp",
      messages: [],
      ruleConfig: { blockStructuralTestChanges: true },
      currentTurn: [
        {
          info: { id: `a-${filePath}`, role: "assistant" },
          parts: [{ type: "tool", state: { input: { path: filePath, content: '@pytest.mark.skip(reason="broken")' } } }],
        },
      ],
    };
    assert.equal(noCheatRule.inspect(context).decision, "block");
  }
});

test("file-mutation rules inspect shell heredoc writes", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-shell-"));
  fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ dependencies: {} }));
  clearDeclaredDepsCache();

  const command =
    "cat > src/unsafe.js <<'EOF'\n" +
    'import lodash from "lodash";\n' +
    'const key = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";\n' +
    'function f(){ throw new NotImplementedError("todo") }\n' +
    '// TODO: temporary fix\n' +
    '// ... existing code unchanged ...\n' +
    'it.skip("x",()=>{});\n' +
    "EOF";

  const currentTurn = [
    {
      info: { id: "a-shell", role: "assistant" },
      parts: [{ type: "tool", state: { input: { command } } }],
    },
  ];
  const base = {
    sessionID: "shell-write",
    directory: root,
    messages: [],
    ruleConfig: {
      blockStructuralTestChanges: true,
      blockPythonGhostDeps: true,
    },
    currentTurn,
  };

  for (const rule of [noShortcutsRule, noStubsRule, noTruncationRule, noCheatRule, noSecretsRule, noGhostDepsRule]) {
    assert.equal(rule.inspect(base).decision, "block", rule.id);
  }
});

test("GuardEngine does not blindly skip the next unrelated idle after a block", async () => {
  const engine = new GuardEngine();
  const first = await engine.inspect("no-blind-skip", "/tmp", [
    { info: { id: "u-1-skip", role: "user" }, parts: [{ type: "text", text: "do it" }] },
    { info: { id: "a-1-skip", role: "assistant" }, parts: [{ type: "text", text: "This is unrelated to this change." }] },
  ]);
  assert.equal(first.decision, "block");

  const second = await engine.inspect("no-blind-skip", "/tmp", [
    { info: { id: "u-2-skip", role: "user" }, parts: [{ type: "text", text: "next" }] },
    {
      info: { id: "a-2-skip", role: "assistant" },
      parts: [
        {
          type: "tool",
          state: {
            input: {
              path: "src/key.ts",
              content: 'const key = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";',
            },
          },
        },
      ],
    },
  ]);
  assert.equal(second.decision, "block");
  assert.ok(second.results.some((result) => result.ruleId === "security/no-secrets" && result.decision === "block"));
});

test("GuardEngine retries the same message after a transient rule exception", async () => {
  const engine = new GuardEngine({
    enabled: true,
    rules: {
      "discipline/no-evasion": "off",
      "discipline/no-apology": "off",
      "quality/no-shortcuts": "off",
      "integrity/no-stubs": "off",
      "safety/no-truncation": "off",
      "testing/no-cheat": "off",
      "security/no-secrets": "off",
      "manifest/no-ghost-deps": "off",
      "runtime/circuit-breaker": "off",
    },
  });
  let calls = 0;
  engine.registerRule({
    id: "custom/throws-once",
    description: "test",
    inspect() {
      calls += 1;
      if (calls === 1) throw new Error("transient");
      return {
        ruleId: "custom/throws-once",
        decision: "block",
        findings: [{ ruleId: "custom/throws-once", pattern: "x", messageSnippet: "x", description: "x" }],
        remediationPrompt: "fix",
      };
    },
  });

  const messages = [
    { info: { id: "u-retry", role: "user" }, parts: [{ type: "text", text: "run" }] },
    { info: { id: "a-retry", role: "assistant" }, parts: [{ type: "text", text: "done" }] },
  ];

  await assert.rejects(() => engine.inspect("retry-session", "/tmp", messages), /transient/);
  const second = await engine.inspect("retry-session", "/tmp", messages);
  assert.equal(calls, 2);
  assert.equal(second.decision, "block");
});

test("runtime/circuit-breaker keys repetition by tool invocation, not only error text", () => {
  const part = (command, error) => ({
    type: "tool",
    tool: "bash",
    state: { status: "error", input: { command }, error },
  });

  const base = {
    sessionID: "breaker-signature",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
  };

  const differentCommands = {
    ...base,
    currentTurn: [
      {
        info: { id: "a-different", role: "assistant" },
        parts: [
          part("cat a", "No such file or directory"),
          part("cat b", "No such file or directory"),
          part("cat c", "No such file or directory"),
        ],
      },
    ],
  };
  assert.equal(circuitBreakerRule.inspect(differentCommands).decision, "pass");

  const sameCommand = {
    ...base,
    currentTurn: [
      {
        info: { id: "a-same", role: "assistant" },
        parts: [
          part("curl example", "attempt 1: connection refused"),
          part("curl example", "attempt 2: connection refused"),
          part("curl example", "attempt 3: connection refused"),
        ],
      },
    ],
  };
  assert.equal(circuitBreakerRule.inspect(sameCommand).decision, "block");
});

test("OpenCode v2 setup consumes the async event stream and sends synthetic remediation", async () => {
  const { OpencodeGuardian } = await import("../dist/index.js");
  let subscribeOptions;
  let contextCalls = 0;
  let remediation = "";

  const remediated = new Promise((resolve) => {
    const context = {
      location: { directory: process.cwd() },
      event: {
        subscribe(options) {
          subscribeOptions = options;
          return {
            async *[Symbol.asyncIterator]() {
              yield { type: "session.idle", data: { sessionID: "v2-session" } };
            },
          };
        },
      },
      session: {
        async context({ sessionID }) {
          contextCalls += 1;
          assert.equal(sessionID, "v2-session");
          return [
            { id: "v2-user", type: "user", time: { created: 1 }, text: "fix it" },
            {
              id: "v2-assistant",
              type: "assistant",
              time: { created: 2 },
              agent: "orchestrator",
              model: { providerID: "test", modelID: "test" },
              content: [{ type: "text", text: "This is unrelated to this change." }],
            },
          ];
        },
        async synthetic(input) {
          remediation = input.text;
          resolve();
          return {};
        },
      },
    };

    Promise.resolve(OpencodeGuardian.setup(context)).then((cleanup) => {
      remediated.finally(() => cleanup?.());
    });
  });

  await Promise.race([
    remediated,
    new Promise((_, reject) => setTimeout(() => reject(new Error("v2 remediation timeout")), 1000)),
  ]);

  assert.ok(subscribeOptions?.signal instanceof AbortSignal);
  assert.equal(contextCalls, 1);
  assert.ok(remediation.startsWith("[opencode-guardian remediation]"));
});


test("OpenCode v2 setup silently no-ops on partial v2 contexts", async () => {
  const { OpencodeGuardian } = await import("../dist/index.js");
  const originalError = console.error;
  const errors = [];
  console.error = (...args) => {
    errors.push(args);
  };

  try {
    const missingEvent = await OpencodeGuardian.setup({
      location: { directory: process.cwd() },
      session: {},
    });
    assert.equal(missingEvent, undefined);

    const nonIterableSubscription = await OpencodeGuardian.setup({
      location: { directory: process.cwd() },
      event: {
        subscribe() {
          return {};
        },
      },
      session: {
        async context() {
          return [];
        },
        async synthetic() {
          return {};
        },
      },
    });
    assert.equal(nonIterableSubscription, undefined);

    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.deepEqual(
      errors,
      [],
      "partial v2 capability detection must not emit terminal errors"
    );
  } finally {
    console.error = originalError;
  }
});


function makeEvidenceContext(parts, text = "") {
  const currentTurn = [
    { info: { id: "u-evidence", role: "user" }, parts: [{ type: "text", text: "verify it" }] },
    {
      info: { id: "a-evidence", role: "assistant" },
      parts: [...parts, ...(text ? [{ type: "text", text }] : [])],
    },
  ];
  return {
    sessionID: "evidence-session",
    directory: process.cwd(),
    messages: currentTurn,
    currentTurn,
    ruleConfig: {},
    evidence: collectTurnEvidence(currentTurn),
  };
}

test("evidence collector classifies verification commands and preserves explicit exit codes", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      tool: "bash",
      state: {
        status: "completed",
        input: { command: "npm test" },
        output: "ok",
        metadata: { exit: 0 },
      },
    },
    {
      type: "tool",
      tool: "bash",
      state: {
        status: "completed",
        input: { command: "npm audit" },
        output: "audit failed",
        metadata: { exit: 1 },
      },
    },
  ]);

  const testEvidence = context.evidence.records.find((record) => record.kind === "test");
  const auditEvidence = context.evidence.records.find((record) => record.kind === "audit");
  assert.equal(testEvidence.status, "success");
  assert.equal(testEvidence.exitCode, 0);
  assert.equal(auditEvidence.status, "failure");
  assert.equal(auditEvidence.exitCode, 1);
});

test("integrity/no-unverified-claims accepts a success claim backed by tool evidence", () => {
  const context = makeEvidenceContext(
    [
      {
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command: "npm test" },
          output: "53 passing",
          metadata: { exit: 0 },
        },
      },
    ],
    "All tests passed."
  );
  const result = noUnverifiedClaimsRule.inspect(context);
  assert.equal(result.decision, "pass");
  assert.equal(result.findings.length, 0);
});

test("integrity/no-unverified-claims blocks a claim contradicted by the latest tool result", () => {
  const context = makeEvidenceContext(
    [
      {
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command: "npm test" },
          output: "1 failing",
          metadata: { exit: 1 },
        },
      },
    ],
    "All tests pass."
  );
  const result = noUnverifiedClaimsRule.inspect(context);
  assert.equal(result.decision, "block");
  assert.equal(result.findings[0].confidence, "high");
  assert.match(result.remediationPrompt, /contradictory completion claim/i);
});

test("integrity/no-unverified-claims does not block an unsupported claim by default", () => {
  const context = makeEvidenceContext([], "The build succeeded.");
  const result = noUnverifiedClaimsRule.inspect(context);
  assert.equal(result.decision, "pass");
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].confidence, "medium");
});

test("integrity/no-unverified-claims permits explicit uncertainty and hypotheses", () => {
  for (const text of [
    "Tests probably pass, but I haven't run them.",
    "I suspect the bug is fixed, but I cannot verify it in this environment.",
    "Sanırım testler geçti ama çalıştırmadım.",
  ]) {
    const context = makeEvidenceContext([], text);
    const result = noUnverifiedClaimsRule.inspect(context);
    assert.equal(result.decision, "pass", text);
    assert.equal(result.findings.length, 0, text);
  }
});

test("discipline/no-evasion accepts pre-existing claims after a successful baseline check", () => {
  const context = makeEvidenceContext(
    [
      {
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command: "git show origin/main:src/index.ts" },
          output: "existing source",
          metadata: { exit: 0 },
        },
      },
    ],
    "This is a pre-existing issue."
  );
  const result = noEvasionRule.inspect(context);
  assert.equal(result.decision, "pass");
});

test("integrity/no-silent-failure blocks masked verification exit status", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      tool: "bash",
      state: {
        status: "completed",
        input: { command: "npm test || true" },
        output: "",
        metadata: { exit: 0 },
      },
    },
  ]);
  const result = noSilentFailureRule.inspect(context);
  assert.equal(result.decision, "block");
  assert.equal(result.findings[0].confidence, "high");
});

test("integrity/no-silent-failure treats empty catch as advisory unless strict", () => {
  const parts = [
    {
      type: "tool",
      state: {
        status: "completed",
        input: {
          path: "src/cache.ts",
          content: "try { await cache.refresh(); } catch {}",
        },
      },
    },
  ];
  const advisory = makeEvidenceContext(parts);
  let result = noSilentFailureRule.inspect(advisory);
  assert.equal(result.decision, "pass");
  assert.equal(result.findings.length, 1);

  const strict = { ...advisory, ruleConfig: { blockEmptyHandlers: true } };
  result = noSilentFailureRule.inspect(strict);
  assert.equal(result.decision, "block");
});

test("safety/destructive-operations flags unrequested destructive commands", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      tool: "bash",
      state: {
        status: "completed",
        input: { command: "git reset --hard HEAD~1" },
        metadata: { exit: 0 },
      },
    },
  ]);
  const result = destructiveOperationsRule.inspect(context);
  assert.equal(result.decision, "block");
  assert.equal(result.findings[0].confidence, "high");
});

test("safety/destructive-operations permits explicitly requested destructive action", () => {
  const currentTurn = [
    {
      info: { id: "u-destructive", role: "user" },
      parts: [{ type: "text", text: "Bu branch'i hard reset ile sıfırla." }],
    },
    {
      info: { id: "a-destructive", role: "assistant" },
      parts: [
        {
          type: "tool",
          state: {
            status: "completed",
            input: { command: "git reset --hard origin/main" },
            metadata: { exit: 0 },
          },
        },
      ],
    },
  ];
  const context = {
    sessionID: "destructive-authorized",
    directory: process.cwd(),
    messages: currentTurn,
    currentTurn,
    ruleConfig: {},
    evidence: collectTurnEvidence(currentTurn),
  };
  assert.equal(destructiveOperationsRule.inspect(context).decision, "pass");
});

test("testing/no-cheat detects assertion weakening in a test patch", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      state: {
        input: {
          patch: [
            "--- a/tests/value.test.ts",
            "+++ b/tests/value.test.ts",
            "-expect(result).toEqual({ ok: true, value: 42 });",
            "+expect(result).toBeTruthy();",
          ].join("\n"),
        },
      },
    },
  ]);
  const result = noCheatRule.inspect({
    ...context,
    ruleConfig: { blockStructuralTestChanges: true },
  });
  assert.equal(result.decision, "block");
  assert.ok(result.findings.some((finding) => finding.pattern === "assertion weakened"));
});

test("testing/no-cheat allows an equally specific assertion change", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      state: {
        input: {
          patch: [
            "--- a/tests/value.test.ts",
            "+++ b/tests/value.test.ts",
            "-expect(result).toEqual({ ok: true });",
            "+expect(result).toEqual({ ok: true, value: 42 });",
          ].join("\n"),
        },
      },
    },
  ]);
  assert.equal(noCheatRule.inspect(context).decision, "pass");
});

test("testing/no-cheat detects test deletion and coverage threshold reduction", () => {
  const deletion = makeEvidenceContext([
    {
      type: "tool",
      state: {
        input: {
          path: "tests/broken.test.ts",
          action: "delete",
        },
      },
    },
  ]);
  assert.equal(
    noCheatRule.inspect({
      ...deletion,
      ruleConfig: { blockStructuralTestChanges: true },
    }).decision,
    "block"
  );

  const coverage = makeEvidenceContext([
    {
      type: "tool",
      state: {
        input: {
          path: "vitest.config.ts",
          patch: [
            "--- a/vitest.config.ts",
            "+++ b/vitest.config.ts",
            "-coverage: { lines: 90, functions: 90 }",
            "+coverage: { lines: 50, functions: 50 }",
          ].join("\n"),
        },
      },
    },
  ]);
  assert.equal(
    noCheatRule.inspect({
      ...coverage,
      ruleConfig: { blockStructuralTestChanges: true },
    }).decision,
    "block"
  );
});

test("testing/no-cheat keeps snapshot update advisory by default", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      state: {
        status: "completed",
        input: { command: "vitest -u" },
        metadata: { exit: 0 },
      },
    },
  ]);
  let result = noCheatRule.inspect(context);
  assert.equal(result.decision, "pass");
  assert.ok(result.findings.some((finding) => finding.pattern === "snapshot update"));

  result = noCheatRule.inspect({
    ...context,
    ruleConfig: { blockSnapshotUpdates: true },
  });
  assert.equal(result.decision, "block");
});

test("security/no-secrets detects npm, GitLab, Google, Stripe and bearer credentials", () => {
  const cases = [
    "const x = 'npm_" + "abcdefghijklmnopqrstuvwxyz0123456789ABCD';",
    "const x = 'glpat-" + "abcdefghijklmnopqrstuvwx';",
    "const x = 'AI" + "za12345678901234567890123456789012345';",
    "const x = 'sk_" + "live_abcdefghijklmnopqrstuvwxyz123456';",
    "const h = 'Authorization: Bearer " + "abcdefghijklmnopqrstuvwxyz0123456789';",
  ];

  for (const content of cases) {
    const context = makeEvidenceContext([
      {
        type: "tool",
        state: { input: { path: "src/secret.ts", content } },
      },
    ]);
    assert.equal(noSecretsRule.inspect(context).decision, "block", content);
  }
});

test("manifest/no-ghost-deps supports Python pyproject dependencies and local modules", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-python-deps-"));
  try {
    fs.writeFileSync(
      path.join(root, "pyproject.toml"),
      '[project]\ndependencies = ["requests>=2.0"]\n'
    );
    fs.mkdirSync(path.join(root, "src", "localpkg"), { recursive: true });
    fs.writeFileSync(path.join(root, "src", "localpkg", "__init__.py"), "");
    clearDeclaredDepsCache();

    const okContext = {
      sessionID: "python-ok",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-python-ok", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "src", "app.py"),
                  content: "import requests\nimport localpkg\nimport json\n",
                },
              },
            },
          ],
        },
      ],
    };
    assert.equal(noGhostDepsRule.inspect(okContext).decision, "pass");

    const badContext = structuredClone(okContext);
    badContext.sessionID = "python-bad";
    badContext.currentTurn[0].parts[0].state.input.content = "import httpx\n";

    const advisory = noGhostDepsRule.inspect(badContext);
    assert.equal(advisory.decision, "pass");
    assert.equal(advisory.findings.length, 1);
    assert.equal(advisory.findings[0].confidence, "medium");

    const strict = noGhostDepsRule.inspect({
      ...badContext,
      ruleConfig: { blockPythonGhostDeps: true },
    });
    assert.equal(strict.decision, "block");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("manifest/no-ghost-deps supports Go modules", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-go-deps-"));
  try {
    fs.writeFileSync(
      path.join(root, "go.mod"),
      "module example.com/app\n\ngo 1.23\n\nrequire github.com/google/uuid v1.6.0\n"
    );

    const context = {
      sessionID: "go-deps",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-go", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "main.go"),
                  content:
                    'package main\nimport "github.com/stretchr/testify/require"\nfunc main() {}\n',
                },
              },
            },
          ],
        },
      ],
    };
    assert.equal(noGhostDepsRule.inspect(context).decision, "block");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("manifest/no-ghost-deps supports Rust Cargo dependencies and local modules", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-rust-deps-"));
  try {
    fs.mkdirSync(path.join(root, "src"), { recursive: true });
    fs.writeFileSync(
      path.join(root, "Cargo.toml"),
      '[package]\nname = "demo"\nversion = "0.1.0"\n[dependencies]\nserde = "1"\n'
    );
    fs.writeFileSync(path.join(root, "src", "local.rs"), "");

    const context = {
      sessionID: "rust-deps",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-rust", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "src", "main.rs"),
                  content: "use serde::Serialize;\nuse local::Thing;\nuse anyhow::Result;\n",
                },
              },
            },
          ],
        },
      ],
    };
    const result = noGhostDepsRule.inspect(context);
    assert.equal(result.decision, "block");
    assert.ok(result.findings.some((finding) => finding.pattern === "anyhow"));
    assert.ok(!result.findings.some((finding) => finding.pattern === "local"));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("runtime/circuit-breaker detects cosmetic command changes with the same root-cause", () => {
  const commands = [
    ["curl http://localhost:1234", "connect ECONNREFUSED 127.0.0.1:1234"],
    ["curl -v http://localhost:1234", "connect ECONNREFUSED 127.0.0.1:1235"],
    ["curl http://localhost:1234 2>&1", "connect ECONNREFUSED 127.0.0.1:1236"],
  ];
  const context = makeEvidenceContext(
    commands.map(([command, error]) => ({
      type: "tool",
      tool: "bash",
      state: {
        status: "error",
        input: { command },
        error,
      },
    }))
  );
  assert.equal(circuitBreakerRule.inspect(context).decision, "block");
});

test("runtime/circuit-breaker resets semantic streak after successful progress", () => {
  const parts = [
    {
      type: "tool",
      tool: "bash",
      state: { status: "error", input: { command: "curl /a" }, error: "connection refused 1001" },
    },
    {
      type: "tool",
      tool: "bash",
      state: { status: "error", input: { command: "curl -v /a" }, error: "connection refused 1002" },
    },
    {
      type: "tool",
      tool: "bash",
      state: { status: "completed", input: { command: "curl /health" }, metadata: { exit: 0 } },
    },
    {
      type: "tool",
      tool: "bash",
      state: { status: "error", input: { command: "curl /a 2>&1" }, error: "connection refused 1003" },
    },
  ];
  const context = makeEvidenceContext(parts);
  assert.equal(circuitBreakerRule.inspect(context).decision, "pass");
});

test("GuardEngine remediation budget prevents repeated blocking within the same human turn and resets on a new turn", async () => {
  const engine = new GuardEngine({
    enabled: true,
    remediationBudget: 1,
    rules: {
      "discipline/no-evasion": "error",
      "discipline/no-apology": "off",
      "quality/no-shortcuts": "off",
      "integrity/no-stubs": "off",
      "integrity/no-unverified-claims": "off",
      "integrity/no-silent-failure": "off",
      "safety/no-truncation": "off",
      "safety/destructive-operations": "off",
      "testing/no-cheat": "off",
      "security/no-secrets": "off",
      "manifest/no-ghost-deps": "off",
      "runtime/circuit-breaker": "off",
    },
  });

  const first = [
    { info: { id: "budget-u1", role: "user" }, parts: [{ type: "text", text: "fix it" }] },
    { info: { id: "budget-a1", role: "assistant" }, parts: [{ type: "text", text: "This is unrelated to this change." }] },
  ];
  assert.equal((await engine.inspect("budget", process.cwd(), first)).decision, "block");

  const sameTurn = [
    ...first,
    { info: { id: "budget-a2", role: "assistant" }, parts: [{ type: "text", text: "It is outside the scope of this task." }] },
  ];
  assert.equal((await engine.inspect("budget", process.cwd(), sameTurn)).decision, "pass");

  const newTurn = [
    ...sameTurn,
    { info: { id: "budget-u2", role: "user" }, parts: [{ type: "text", text: "check again" }] },
    { info: { id: "budget-a3", role: "assistant" }, parts: [{ type: "text", text: "This is unrelated to this task." }] },
  ];
  assert.equal((await engine.inspect("budget", process.cwd(), newTurn)).decision, "block");
});

test("GuardEngine default destructive-operation severity is warn and does not block", async () => {
  const engine = new GuardEngine({
    enabled: true,
    rules: {
      "discipline/no-evasion": "off",
      "discipline/no-apology": "off",
      "quality/no-shortcuts": "off",
      "integrity/no-stubs": "off",
      "integrity/no-unverified-claims": "off",
      "integrity/no-silent-failure": "off",
      "safety/no-truncation": "off",
      "testing/no-cheat": "off",
      "security/no-secrets": "off",
      "manifest/no-ghost-deps": "off",
      "runtime/circuit-breaker": "off",
    },
  });

  const messages = [
    { info: { id: "warn-u", role: "user" }, parts: [{ type: "text", text: "inspect repo" }] },
    {
      info: { id: "warn-a", role: "assistant" },
      parts: [
        {
          type: "tool",
          state: {
            status: "completed",
            input: { command: "git reset --hard HEAD~1" },
            metadata: { exit: 0 },
          },
        },
      ],
    },
  ];
  const result = await engine.inspect("warn-destructive", process.cwd(), messages);
  assert.equal(result.decision, "pass");
  const destructive = result.results.find((item) => item.ruleId === "safety/destructive-operations");
  assert.equal(destructive.decision, "block");
});


test("integrity/no-unverified-claims treats verification before a later mutation as stale", () => {
  const context = makeEvidenceContext(
    [
      {
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command: "npm test" },
          metadata: { exit: 0 },
        },
      },
      {
        type: "tool",
        tool: "write",
        state: {
          status: "completed",
          input: { path: "src/index.ts", content: "export const changed = true;" },
        },
      },
    ],
    "All tests passed."
  );
  const result = noUnverifiedClaimsRule.inspect(context);
  assert.equal(result.decision, "pass");
  assert.equal(result.findings.length, 1);
  assert.match(result.findings[0].description, /no matching verification/i);
});

test("integrity/no-unverified-claims checks git status content, not only exit code", () => {
  const dirty = makeEvidenceContext(
    [
      {
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command: "git status --short --branch" },
          output: "## main...origin/main\n M src/index.ts",
          metadata: { exit: 0 },
        },
      },
    ],
    "The working tree is clean."
  );
  assert.equal(noUnverifiedClaimsRule.inspect(dirty).decision, "block");

  const clean = makeEvidenceContext(
    [
      {
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command: "git status --short --branch" },
          output: "## main...origin/main",
          metadata: { exit: 0 },
        },
      },
    ],
    "The working tree is clean."
  );
  const result = noUnverifiedClaimsRule.inspect(clean);
  assert.equal(result.decision, "pass");
  assert.equal(result.findings.length, 0);
});

test("testing/no-cheat detects CI test-step removal without replacement", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      state: {
        input: {
          path: ".github/workflows/ci.yml",
          patch: [
            "--- a/.github/workflows/ci.yml",
            "+++ b/.github/workflows/ci.yml",
            "-      - run: npm test",
            "+      - run: echo done",
          ].join("\n"),
        },
      },
    },
  ]);
  const result = noCheatRule.inspect({
    ...context,
    ruleConfig: { blockStructuralTestChanges: true },
  });
  assert.equal(result.decision, "block");
  assert.ok(result.findings.some((finding) => finding.pattern === "CI test step removed"));
});


test("integrity/no-stubs detects placeholder constant returns only with explicit stub context", () => {
  const blocked = {
    sessionID: "stub-return",
    directory: process.cwd(),
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "a-stub-return", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                path: "src/feature.ts",
                content: "export function ready() { return true; // placeholder }",
              },
            },
          },
        ],
      },
    ],
  };
  assert.equal(noStubsRule.inspect(blocked).decision, "block");

  const legitimate = structuredClone(blocked);
  legitimate.currentTurn[0].parts[0].state.input.content =
    "export function ready() { return true; }";
  assert.equal(noStubsRule.inspect(legitimate).decision, "pass");
});

test("manifest/no-ghost-deps does not flag Python standard-library imports", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-python-stdlib-"));
  try {
    fs.writeFileSync(
      path.join(root, "pyproject.toml"),
      '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = []\n'
    );
    clearDeclaredDepsCache();
    const context = {
      sessionID: "python-stdlib",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-python-stdlib", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "app.py"),
                  content:
                    "import email\nimport zoneinfo\nimport ipaddress\nimport graphlib\n",
                },
              },
            },
          ],
        },
      ],
    };
    assert.equal(noGhostDepsRule.inspect(context).decision, "pass");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});


test("testing/no-cheat keeps structural test changes advisory without failed-test evidence", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      state: {
        input: {
          patch: [
            "--- a/tests/value.test.ts",
            "+++ b/tests/value.test.ts",
            "-expect(result).toEqual({ ok: true, value: 42 });",
            "+expect(result).toBeTruthy();",
          ].join("\n"),
        },
      },
    },
  ]);

  const result = noCheatRule.inspect(context);
  assert.equal(result.decision, "pass");
  assert.ok(result.findings.some((finding) => finding.pattern === "assertion weakened"));
});

test("testing/no-cheat blocks structural weakening when the same turn contains failed-test evidence", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      tool: "bash",
      state: {
        status: "completed",
        input: { command: "npm test" },
        output: "1 failing",
        metadata: { exit: 1 },
      },
    },
    {
      type: "tool",
      state: {
        input: {
          patch: [
            "--- a/tests/value.test.ts",
            "+++ b/tests/value.test.ts",
            "-expect(result).toEqual({ ok: true, value: 42 });",
            "+expect(result).toBeTruthy();",
          ].join("\n"),
        },
      },
    },
  ]);

  assert.equal(noCheatRule.inspect(context).decision, "block");
});


test("integrity/no-silent-failure does not treat set +e alone as proof of masked failure", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      tool: "bash",
      state: {
        status: "completed",
        input: {
          command: "set +e; npm test; code=$?; set -e; exit $code",
        },
        metadata: { exit: 0 },
      },
    },
  ]);
  assert.equal(noSilentFailureRule.inspect(context).decision, "pass");
});

test("safety/destructive-operations does not mistake a negative request for authorization", () => {
  const currentTurn = [
    {
      info: { id: "u-no-delete", role: "user" },
      parts: [{ type: "text", text: "Do not delete anything; only inspect the directory." }],
    },
    {
      info: { id: "a-no-delete", role: "assistant" },
      parts: [
        {
          type: "tool",
          state: {
            status: "completed",
            input: { command: "sudo rm -rf ./cache" },
            metadata: { exit: 0 },
          },
        },
      ],
    },
  ];
  const context = {
    sessionID: "negative-destructive",
    directory: process.cwd(),
    messages: currentTurn,
    currentTurn,
    ruleConfig: {},
    evidence: collectTurnEvidence(currentTurn),
  };
  assert.equal(destructiveOperationsRule.inspect(context).decision, "block");
});

test("runtime/circuit-breaker resets exact failure streak after successful progress", () => {
  const fail = {
    type: "tool",
    tool: "bash",
    state: {
      status: "error",
      input: { command: "curl http://localhost:1234" },
      error: "connection refused 1234",
    },
  };
  const context = makeEvidenceContext([
    structuredClone(fail),
    structuredClone(fail),
    {
      type: "tool",
      tool: "bash",
      state: {
        status: "completed",
        input: { command: "curl http://localhost:9999" },
        output: "ok",
        metadata: { exit: 0 },
      },
    },
    structuredClone(fail),
  ]);
  assert.equal(circuitBreakerRule.inspect(context).decision, "pass");
});

test("GuardEngine remediationBudget zero disables remediation without disabling findings", async () => {
  const engine = new GuardEngine({
    enabled: true,
    remediationBudget: 0,
    rules: {
      "discipline/no-evasion": "error",
      "discipline/no-apology": "off",
      "quality/no-shortcuts": "off",
      "integrity/no-stubs": "off",
      "integrity/no-unverified-claims": "off",
      "integrity/no-silent-failure": "off",
      "safety/no-truncation": "off",
      "safety/destructive-operations": "off",
      "testing/no-cheat": "off",
      "security/no-secrets": "off",
      "manifest/no-ghost-deps": "off",
      "runtime/circuit-breaker": "off",
    },
  });

  const messages = [
    { info: { id: "budget0-u", role: "user" }, parts: [{ type: "text", text: "check it" }] },
    { info: { id: "budget0-a", role: "assistant" }, parts: [{ type: "text", text: "This is unrelated to this change." }] },
  ];

  const result = await engine.inspect("budget-zero", process.cwd(), messages);
  assert.equal(result.decision, "pass");
  assert.equal(
    result.results.find((item) => item.ruleId === "discipline/no-evasion")?.decision,
    "block"
  );
});

test("manifest/no-ghost-deps recognizes common Python import/distribution aliases", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-python-aliases-"));
  try {
    fs.writeFileSync(
      path.join(root, "pyproject.toml"),
      [
        "[project]",
        'name = "demo"',
        'version = "0.1.0"',
        'dependencies = ["python-dateutil", "python-dotenv", "PyJWT", "google-cloud-storage"]',
        "",
      ].join("\n")
    );
    clearDeclaredDepsCache();

    const context = {
      sessionID: "python-aliases",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-python-aliases", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "app.py"),
                  content:
                    "import dateutil\nimport dotenv\nimport jwt\nfrom google.cloud import storage\n",
                },
              },
            },
          ],
        },
      ],
    };

    assert.equal(noGhostDepsRule.inspect(context).decision, "pass");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});


test("evidence collector never treats masked verification as successful proof", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      tool: "bash",
      state: {
        status: "completed",
        input: { command: "npm test || true" },
        output: "1 failing",
        metadata: { exit: 0 },
      },
    },
  ]);

  const record = context.evidence.records.find((item) => item.kind === "test");
  assert.equal(record.status, "unknown");
  assert.match(record.error, /masked/i);
});

test("integrity/no-unverified-claims treats git status from before a later mutation as stale", () => {
  const context = makeEvidenceContext(
    [
      {
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command: "git status --short --branch" },
          output: "## main...origin/main",
          metadata: { exit: 0 },
        },
      },
      {
        type: "tool",
        tool: "write",
        state: {
          status: "completed",
          input: { path: "src/changed.ts", content: "export const changed = true;" },
        },
      },
    ],
    "The working tree is clean."
  );

  const result = noUnverifiedClaimsRule.inspect(context);
  assert.equal(result.decision, "pass");
  assert.equal(result.findings.length, 1);
});


test("evidence collector records every verification kind in a compound command", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      tool: "bash",
      state: {
        status: "completed",
        input: { command: "npm run build && npm test && npm audit" },
        metadata: { exit: 0 },
      },
    },
  ]);

  const kinds = new Set(context.evidence.records.map((record) => record.kind));
  assert.ok(kinds.has("build"));
  assert.ok(kinds.has("test"));
  assert.ok(kinds.has("audit"));
});

test("evidence collector does not infer shell success without an explicit exit code", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      tool: "bash",
      state: {
        status: "completed",
        input: { command: "npm test" },
        output: "looks complete",
      },
    },
  ]);

  const record = context.evidence.records.find((item) => item.kind === "test");
  assert.equal(record.status, "unknown");
  assert.match(record.error, /without an explicit exit code/i);
});

test("circuit-breaker fingerprint keeps semantic HTTP and exit codes distinct", () => {
  assert.notEqual(
    normalizeErrorFingerprint("HTTP status 404"),
    normalizeErrorFingerprint("HTTP status 500")
  );
  assert.notEqual(
    normalizeErrorFingerprint("exit code 1"),
    normalizeErrorFingerprint("exit code 2")
  );
  assert.equal(
    normalizeErrorFingerprint("connect ECONNREFUSED 127.0.0.1:1234"),
    normalizeErrorFingerprint("connect ECONNREFUSED 127.0.0.1:5678")
  );
});

test("runtime/circuit-breaker counts a compound tool invocation only once", () => {
  const parts = [1, 2].map(() => ({
    type: "tool",
    tool: "bash",
    state: {
      status: "error",
      input: { command: "npm run build && npm test" },
      error: "shared failure 12345",
    },
  }));

  const context = makeEvidenceContext(parts);
  assert.equal(circuitBreakerRule.inspect(context).decision, "pass");
});

test("manifest/no-ghost-deps uses real Node builtin semantics for test/sqlite", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-node-builtins-"));
  try {
    fs.writeFileSync(
      path.join(root, "package.json"),
      JSON.stringify({ name: "demo", dependencies: {} })
    );
    clearDeclaredDepsCache();

    const bare = {
      sessionID: "node-bare",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-node-bare", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "src.js"),
                  content: 'import x from "test";\nimport y from "sqlite";\n',
                },
              },
            },
          ],
        },
      ],
    };
    assert.equal(noGhostDepsRule.inspect(bare).decision, "block");

    const prefixed = structuredClone(bare);
    prefixed.currentTurn[0].parts[0].state.input.content =
      'import test from "node:test";\nimport sqlite from "node:sqlite";\n';
    assert.equal(noGhostDepsRule.inspect(prefixed).decision, "pass");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("manifest/no-ghost-deps ignores Python imports inside comments and strings", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-python-mask-"));
  try {
    fs.writeFileSync(
      path.join(root, "pyproject.toml"),
      '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = []\n'
    );
    clearDeclaredDepsCache();

    const context = {
      sessionID: "python-mask",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-python-mask", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "app.py"),
                  content: [
                    '# import httpx',
                    'example = "import requests"',
                    '"""',
                    'from pandas import DataFrame',
                    '"""',
                    'import json  # import httpx',
                  ].join("\n"),
                },
              },
            },
          ],
        },
      ],
    };

    assert.equal(noGhostDepsRule.inspect(context).decision, "pass");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("manifest/no-ghost-deps follows requirements -r includes", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-requirements-include-"));
  try {
    fs.writeFileSync(path.join(root, "requirements.txt"), "-r requirements-base.txt\n");
    fs.writeFileSync(path.join(root, "requirements-base.txt"), "requests>=2\n");
    clearDeclaredDepsCache();

    const context = {
      sessionID: "python-requirements-include",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-python-requirements-include", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "app.py"),
                  content: "import requests\n",
                },
              },
            },
          ],
        },
      ],
    };
    assert.equal(noGhostDepsRule.inspect(context).decision, "pass");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("testing/no-cheat coverage check ignores unrelated numeric config changes", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      state: {
        input: {
          path: "vitest.config.ts",
          patch: [
            "--- a/vitest.config.ts",
            "+++ b/vitest.config.ts",
            "-coverage: { lines: 90 }, timeout: 5000",
            "+coverage: { lines: 95 }, timeout: 4000",
          ].join("\n"),
        },
      },
    },
  ]);

  const result = noCheatRule.inspect({
    ...context,
    ruleConfig: { blockStructuralTestChanges: true },
  });
  assert.equal(result.decision, "pass");
  assert.ok(
    !result.findings.some((finding) => finding.pattern === "coverage threshold reduced")
  );
});

test("testing/no-cheat only pairs assertion weakening within the same diff hunk", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      state: {
        input: {
          path: "tests/value.test.ts",
          patch: [
            "--- a/tests/value.test.ts",
            "+++ b/tests/value.test.ts",
            "@@ -1,1 +1,1 @@",
            "-expect(a).toEqual({ ok: true });",
            "+expect(a).toEqual({ ok: true, value: 1 });",
            "@@ -20,0 +21,1 @@",
            "+expect(b).toBeTruthy();",
          ].join("\n"),
        },
      },
    },
  ]);

  const result = noCheatRule.inspect({
    ...context,
    ruleConfig: { blockStructuralTestChanges: true },
  });
  assert.equal(result.decision, "pass");
  assert.ok(
    !result.findings.some((finding) => finding.pattern === "assertion weakened")
  );
});

test("safety/destructive-operations does not broaden narrow delete authorization to rm -rf dot", () => {
  const currentTurn = [
    {
      info: { id: "u-narrow-delete", role: "user" },
      parts: [{ type: "text", text: "Delete the old cache file only." }],
    },
    {
      info: { id: "a-narrow-delete", role: "assistant" },
      parts: [
        {
          type: "tool",
          state: {
            status: "completed",
            input: { command: "rm -rf ." },
            metadata: { exit: 0 },
          },
        },
      ],
    },
  ];
  const context = {
    sessionID: "narrow-delete",
    directory: process.cwd(),
    messages: currentTurn,
    currentTurn,
    ruleConfig: {},
    evidence: collectTurnEvidence(currentTurn),
  };
  assert.equal(destructiveOperationsRule.inspect(context).decision, "block");
});

test("safety/destructive-operations recognizes long-form destructive flags", () => {
  for (const command of [
    "git clean --force -d",
    "docker system prune --all --force",
    "rm --recursive --force ./cache",
  ]) {
    const context = makeEvidenceContext([
      {
        type: "tool",
        state: {
          status: "completed",
          input: { command },
          metadata: { exit: 0 },
        },
      },
    ]);
    assert.equal(destructiveOperationsRule.inspect(context).decision, "block", command);
  }
});

test("integrity/no-unverified-claims recognizes tests are passing phrasing", () => {
  const result = noUnverifiedClaimsRule.inspect(
    makeEvidenceContext([], "The tests are passing.")
  );
  assert.equal(result.decision, "pass");
  assert.equal(result.findings.length, 1);
});

test("integrity/no-unverified-claims does not let failed git status become clean evidence", () => {
  const context = makeEvidenceContext(
    [
      {
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command: "git status --short --branch" },
          output: "## main...origin/main",
          metadata: { exit: 1 },
        },
      },
    ],
    "The working tree is clean."
  );

  assert.equal(noUnverifiedClaimsRule.inspect(context).decision, "block");
});

test("failed file mutation does not invalidate earlier successful verification", () => {
  const context = makeEvidenceContext(
    [
      {
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command: "npm test" },
          metadata: { exit: 0 },
        },
      },
      {
        type: "tool",
        tool: "write",
        state: {
          status: "error",
          input: { path: "src/index.ts", content: "broken write" },
          error: "permission denied",
        },
      },
    ],
    "All tests passed."
  );

  const result = noUnverifiedClaimsRule.inspect(context);
  assert.equal(result.decision, "pass");
  assert.equal(result.findings.length, 0);
});


test("GuardEngine does not treat foreign synthetic prompts as Guardian remediation", async () => {
  const engine = new GuardEngine({
    enabled: true,
    rules: {
      "discipline/no-evasion": "error",
      "discipline/no-apology": "off",
      "quality/no-shortcuts": "off",
      "integrity/no-stubs": "off",
      "integrity/no-unverified-claims": "off",
      "integrity/no-silent-failure": "off",
      "safety/no-truncation": "off",
      "safety/destructive-operations": "off",
      "testing/no-cheat": "off",
      "security/no-secrets": "off",
      "manifest/no-ghost-deps": "off",
      "runtime/circuit-breaker": "off",
    },
  });

  const messages = [
    { info: { id: "foreign-u1", role: "user" }, parts: [{ type: "text", text: "check it" }] },
    {
      info: { id: "foreign-synth", role: "user" },
      parts: [{ type: "text", text: "[other-plugin] continue", synthetic: true }],
    },
    {
      info: { id: "foreign-a1", role: "assistant" },
      parts: [{ type: "text", text: "This is unrelated to this change." }],
    },
  ];

  const result = await engine.inspect("foreign-synthetic", process.cwd(), messages);
  assert.equal(result.decision, "block");
});

test("Guardian remediation marker remains the loop-guard authority", async () => {
  const engine = new GuardEngine({ enabled: true });
  const messages = [
    { info: { id: "marker-u1", role: "user" }, parts: [{ type: "text", text: "check it" }] },
    {
      info: { id: "marker-remediation", role: "user" },
      parts: [{ type: "text", text: REMEDIATION_MARKER + "\nFix the finding.", synthetic: false }],
    },
    {
      info: { id: "marker-a1", role: "assistant" },
      parts: [{ type: "text", text: "This is unrelated to this change." }],
    },
  ];
  const result = await engine.inspect("marker-remediation", process.cwd(), messages);
  assert.equal(result.decision, "pass");
});


test("quality/no-shortcuts does not flag shortcut words inside identifiers or string literals", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      state: {
        input: {
          path: "src/names.ts",
          content: [
            "const temporaryValue = 1;",
            "const isHardcodedSecret = false;",
            'const label = "temporary fix";',
            'const marker = "TODO";',
          ].join("\n"),
        },
      },
    },
  ]);

  assert.equal(noShortcutsRule.inspect(context).decision, "pass");
});

test("quality/no-shortcuts still blocks actual shortcut comments", () => {
  for (const content of [
    "const x = 1; // TODO: replace this",
    "# FIXME: temporary fix\nx = 1",
    "/* HACK: workaround */\nconst x = 1;",
  ]) {
    const context = makeEvidenceContext([
      {
        type: "tool",
        state: { input: { path: "src/file.ts", content } },
      },
    ]);
    assert.equal(noShortcutsRule.inspect(context).decision, "block", content);
  }
});

test("GuardEngine invalid explicit severity fails open to warn", async () => {
  const engine = new GuardEngine({
    enabled: true,
    rules: {
      "discipline/no-evasion": "definitely-not-a-severity",
      "discipline/no-apology": "off",
      "quality/no-shortcuts": "off",
      "integrity/no-stubs": "off",
      "integrity/no-unverified-claims": "off",
      "integrity/no-silent-failure": "off",
      "safety/no-truncation": "off",
      "safety/destructive-operations": "off",
      "testing/no-cheat": "off",
      "security/no-secrets": "off",
      "manifest/no-ghost-deps": "off",
      "runtime/circuit-breaker": "off",
    },
  });

  const messages = [
    { info: { id: "bad-severity-u", role: "user" }, parts: [{ type: "text", text: "check" }] },
    { info: { id: "bad-severity-a", role: "assistant" }, parts: [{ type: "text", text: "This is unrelated to this change." }] },
  ];

  const result = await engine.inspect("bad-severity", process.cwd(), messages);
  assert.equal(result.decision, "pass");
  assert.equal(
    result.results.find((item) => item.ruleId === "discipline/no-evasion")?.decision,
    "block"
  );
});

test("testing/no-cheat treats pre-existing skip in whole-file write as advisory by default", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      state: {
        input: {
          path: "tests/legacy.test.ts",
          content: [
            'test.skip("legacy unsupported platform", () => {});',
            'test("new behavior", () => expect(1).toBe(1));',
          ].join("\n"),
        },
      },
    },
  ]);

  const result = noCheatRule.inspect(context);
  assert.equal(result.decision, "pass");
  assert.ok(result.findings.some((finding) => finding.pattern.includes("test.skip")));
});

test("testing/no-cheat still blocks targeted addition of test.skip", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      state: {
        input: {
          path: "tests/new.test.ts",
          new_string: 'test.skip("newly disabled", () => {});',
        },
      },
    },
  ]);

  assert.equal(noCheatRule.inspect(context).decision, "block");
});

test("safety/destructive-operations treats rm -rf ./ as broad deletion", () => {
  const currentTurn = [
    {
      info: { id: "u-rm-dot-slash", role: "user" },
      parts: [{ type: "text", text: "Delete the old cache file only." }],
    },
    {
      info: { id: "a-rm-dot-slash", role: "assistant" },
      parts: [
        {
          type: "tool",
          state: {
            status: "completed",
            input: { command: "rm -rf ./" },
            metadata: { exit: 0 },
          },
        },
      ],
    },
  ];
  const context = {
    sessionID: "rm-dot-slash",
    directory: process.cwd(),
    messages: currentTurn,
    currentTurn,
    ruleConfig: {},
    evidence: collectTurnEvidence(currentTurn),
  };

  assert.equal(destructiveOperationsRule.inspect(context).decision, "block");
});


test("foreign synthetic prompts do not reset the human-turn remediation budget", async () => {
  const engine = new GuardEngine({
    enabled: true,
    remediationBudget: 1,
    rules: {
      "discipline/no-evasion": "error",
      "discipline/no-apology": "off",
      "quality/no-shortcuts": "off",
      "integrity/no-stubs": "off",
      "integrity/no-unverified-claims": "off",
      "integrity/no-silent-failure": "off",
      "safety/no-truncation": "off",
      "safety/destructive-operations": "off",
      "testing/no-cheat": "off",
      "security/no-secrets": "off",
      "manifest/no-ghost-deps": "off",
      "runtime/circuit-breaker": "off",
    },
  });

  const first = [
    { info: { id: "synthetic-budget-u", role: "user" }, parts: [{ type: "text", text: "check" }] },
    { info: { id: "synthetic-budget-a1", role: "assistant" }, parts: [{ type: "text", text: "This is unrelated to this change." }] },
  ];
  assert.equal(
    (await engine.inspect("synthetic-budget", process.cwd(), first)).decision,
    "block"
  );

  const second = [
    ...first,
    {
      info: { id: "other-plugin-synthetic", role: "user" },
      parts: [{ type: "text", text: "[other-plugin] continue", synthetic: true }],
    },
    {
      info: { id: "synthetic-budget-a2", role: "assistant" },
      parts: [{ type: "text", text: "This is outside the scope of this task." }],
    },
  ];
  assert.equal(
    (await engine.inspect("synthetic-budget", process.cwd(), second)).decision,
    "pass"
  );
});

test("destructive authorization survives foreign synthetic prompts in the same human turn", () => {
  const currentTurn = [
    {
      info: { id: "human-reset", role: "user" },
      parts: [{ type: "text", text: "Bu branch'i hard reset ile sıfırla." }],
    },
    {
      info: { id: "foreign-reset-synthetic", role: "user" },
      parts: [{ type: "text", text: "[other-plugin] metadata", synthetic: true }],
    },
    {
      info: { id: "assistant-reset", role: "assistant" },
      parts: [
        {
          type: "tool",
          state: {
            status: "completed",
            input: { command: "git reset --hard origin/main" },
            metadata: { exit: 0 },
          },
        },
      ],
    },
  ];

  const context = {
    sessionID: "foreign-synthetic-reset",
    directory: process.cwd(),
    messages: currentTurn,
    currentTurn,
    ruleConfig: {},
    evidence: collectTurnEvidence(currentTurn),
  };
  assert.equal(destructiveOperationsRule.inspect(context).decision, "pass");
});

test("quality/no-shortcuts detects markers inside multiline comments", () => {
  const context = makeEvidenceContext([
    {
      type: "tool",
      state: {
        input: {
          path: "src/file.ts",
          content: "/*\n * TODO: finish migration\n */\nexport const x = 1;",
        },
      },
    },
  ]);

  assert.equal(noShortcutsRule.inspect(context).decision, "block");
});

test("GuardEngine invalid object severity also fails open to warn", async () => {
  const engine = new GuardEngine({
    enabled: true,
    rules: {
      "discipline/no-evasion": { severity: "broken-value" },
      "discipline/no-apology": "off",
      "quality/no-shortcuts": "off",
      "integrity/no-stubs": "off",
      "integrity/no-unverified-claims": "off",
      "integrity/no-silent-failure": "off",
      "safety/no-truncation": "off",
      "safety/destructive-operations": "off",
      "testing/no-cheat": "off",
      "security/no-secrets": "off",
      "manifest/no-ghost-deps": "off",
      "runtime/circuit-breaker": "off",
    },
  });

  const result = await engine.inspect("bad-object-severity", process.cwd(), [
    { info: { id: "bad-object-u", role: "user" }, parts: [{ type: "text", text: "check" }] },
    { info: { id: "bad-object-a", role: "assistant" }, parts: [{ type: "text", text: "This is unrelated to this change." }] },
  ]);

  assert.equal(result.decision, "pass");
  assert.equal(
    result.results.find((item) => item.ruleId === "discipline/no-evasion")?.decision,
    "block"
  );
});


test("quality/no-shortcuts keeps ambiguous descriptive wording advisory", () => {
  for (const text of [
    "The current implementation uses a workaround documented by the upstream project.",
    "The placeholder is removed during compilation.",
    "This value is hardcoded by the protocol specification.",
    "The first version of the file format used a different header.",
    "This approach is not ideal for low-memory devices.",
  ]) {
    const result = noShortcutsRule.inspect(makeEvidenceContext([], text));
    assert.equal(result.decision, "pass", text);
    assert.ok(result.findings.length >= 1, text);
    assert.ok(result.findings.every((finding) => finding.confidence === "medium"), text);
  }
});

test("quality/no-shortcuts custom phrases remain blocking even when normally advisory", () => {
  const context = makeEvidenceContext([], "This uses a workaround.");
  const result = noShortcutsRule.inspect({
    ...context,
    ruleConfig: { customPhrases: ["workaround"] },
  });
  assert.equal(result.decision, "block");
});

test("integrity/no-silent-failure does not block exploratory test discovery commands", () => {
  for (const command of [
    "pytest --collect-only || true",
    "jest --listTests || true",
    "vitest --help || true",
  ]) {
    const result = noSilentFailureRule.inspect(
      makeEvidenceContext([
        {
          type: "tool",
          tool: "bash",
          state: {
            status: "completed",
            input: { command },
            metadata: { exit: 0 },
          },
        },
      ])
    );
    assert.equal(result.decision, "pass", command);
    assert.equal(result.findings.length, 0, command);
  }
});


test("integrity/no-unverified-claims keeps failed compound verification outcomes advisory", () => {
  const context = makeEvidenceContext(
    [
      {
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command: "npm run build && npm test" },
          output: "build failed before tests ran",
          metadata: { exit: 1 },
        },
      },
    ],
    "All tests passed."
  );

  const testRecord = context.evidence.records.find((record) => record.kind === "test");
  assert.equal(testRecord.status, "failure");
  assert.equal(testRecord.ambiguousOutcome, true);

  const result = noUnverifiedClaimsRule.inspect(context);
  assert.equal(result.decision, "pass");
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].confidence, "medium");
});

test("integrity/no-unverified-claims does not treat unrelated verification failure as contradiction to generic bug-fixed claim", () => {
  const context = makeEvidenceContext(
    [
      {
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command: "npm run lint" },
          output: "unrelated formatting failure",
          metadata: { exit: 1 },
        },
      },
    ],
    "The bug is fixed."
  );

  const result = noUnverifiedClaimsRule.inspect(context);
  assert.equal(result.decision, "pass");
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].confidence, "medium");
});


test("discipline/no-evasion does not block negated unrelated phrasing", () => {
  const result = noEvasionRule.inspect(
    makeEvidenceContext([], "This is not unrelated to the change; it is directly caused by it.")
  );
  assert.equal(result.decision, "pass");
  assert.equal(result.findings.length, 0);
});

test("discipline/no-apology does not block factual reporting of sorry token", () => {
  for (const text of [
    "The upstream server returned sorry as its payload.",
    "The response contains sorry after rate limiting.",
    "The output text is sorry.",
  ]) {
    const result = noApologyRule.inspect(makeEvidenceContext([], text));
    assert.equal(result.decision, "pass", text);
    assert.equal(result.findings.length, 0, text);
  }

  assert.equal(
    noApologyRule.inspect(makeEvidenceContext([], "Sorry, I made a mistake.")).decision,
    "block"
  );
});


test("integrity/no-unverified-claims catches dirty long-form git status", () => {
  for (const output of [
    "On branch main\nChanges not staged for commit:\n  modified:   src/index.ts",
    "On branch main\nUntracked files:\n  notes.txt",
    "On branch main\nChanges to be committed:\n  new file:   src/test.ts",
  ]) {
    const context = makeEvidenceContext(
      [{
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command: "git status" },
          output,
          metadata: { exit: 0 },
        },
      }],
      "The working tree is clean."
    );
    const result = noUnverifiedClaimsRule.inspect(context);
    assert.equal(result.decision, "block", output);
    assert.equal(result.findings[0].confidence, "high");
  }
});

test("safety/destructive-operations handles split recursive force flags and git clean -fd", () => {
  for (const command of [
    "rm -r -f ./cache",
    "rm --recursive --force ./cache",
    "rm -rf ./cache",
    "git clean -fd",
    "git clean -df",
    "git clean --force -d",
  ]) {
    const context = makeEvidenceContext([{
      type: "tool",
      tool: "bash",
      state: {
        status: "completed",
        input: { command },
        metadata: { exit: 0 },
      },
    }]);
    assert.equal(destructiveOperationsRule.inspect(context).decision, "block", command);
  }
});

test("safety/destructive-operations does not broaden project-cache deletion into project deletion", () => {
  const currentTurn = [
    {
      info: { id: "scope-user", role: "user" },
      parts: [{ type: "text", text: "Delete the project cache only." }],
    },
    {
      info: { id: "scope-agent", role: "assistant" },
      parts: [{
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command: "rm -rf ." },
          metadata: { exit: 0 },
        },
      }],
    },
  ];
  const context = {
    sessionID: "scope-delete",
    directory: process.cwd(),
    messages: currentTurn,
    currentTurn,
    ruleConfig: {},
    evidence: collectTurnEvidence(currentTurn),
  };
  assert.equal(destructiveOperationsRule.inspect(context).decision, "block");
  currentTurn[0].parts[0].text = "Delete the entire project.";
  assert.equal(destructiveOperationsRule.inspect(context).decision, "pass");
});


test("evidence collector does not treat piped or semicolon-chained verification as proof", () => {
  for (const command of [
    "npm test | tee test.log",
    "npm test; npm audit",
    "npm test || npm audit",
  ]) {
    const context = makeEvidenceContext([{
      type: "tool",
      tool: "bash",
      state: {
        status: "completed",
        input: { command },
        metadata: { exit: 0 },
      },
    }]);
    const verification = context.evidence.records.filter(
      (record) => ["test", "build", "typecheck", "lint", "audit"].includes(record.kind)
    );
    assert.ok(verification.length, command);
    assert.ok(verification.every((record) => record.status === "unknown"), command);
  }
});

test("evidence collector accepts explicitly pipefail-protected and && chained commands", () => {
  for (const command of [
    "set -o pipefail; npm test | tee test.log",
    "npm run build && npm test && npm audit",
  ]) {
    const context = makeEvidenceContext([{
      type: "tool",
      tool: "bash",
      state: {
        status: "completed",
        input: { command },
        metadata: { exit: 0 },
      },
    }]);
    const verification = context.evidence.records.filter(
      (record) => ["test", "build", "typecheck", "lint", "audit"].includes(record.kind)
    );
    assert.ok(verification.length, command);
    assert.ok(verification.every((record) => record.status === "success"), command);
  }
});

test("integrity/no-unverified-claims requires a successful git status exit for empty short output", () => {
  const context = makeEvidenceContext(
    [{
      type: "tool",
      tool: "bash",
      state: {
        status: "completed",
        input: { command: "git status --short" },
        output: "",
      },
    }],
    "The working tree is clean."
  );

  const result = noUnverifiedClaimsRule.inspect(context);
  assert.equal(result.decision, "pass");
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].confidence, "medium");
});


test("discipline/no-apology continues past a reported token to detect a real apology", () => {
  const result = noApologyRule.inspect(
    makeEvidenceContext(
      [],
      "The server returned sorry as payload. Sorry, I made a mistake."
    )
  );
  assert.equal(result.decision, "block");
  assert.ok(result.findings.some((finding) => finding.pattern === "English"));
});

test("discipline/no-evasion continues past negated wording to detect a later dismissal", () => {
  const result = noEvasionRule.inspect(
    makeEvidenceContext(
      [],
      "This is not unrelated to this change. The failing test is unrelated to this change."
    )
  );
  assert.equal(result.decision, "block");
  assert.ok(
    result.findings.some((finding) => finding.pattern === "unrelated to this change")
  );
});


test("safety/destructive-operations recognizes explicit git clean authorization", async () => {
  for (const [request, command] of [
    ["git clean -fd yap", "git clean -fd"],
    ["Please run git clean -f", "git clean -f"],
    ["git clean -fdx uygula", "git clean -fdx"],
    ["git clean -fX uygula", "git clean -fX"],
  ]) {
    const context = makeEvidenceContext([
      {
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command },
          metadata: { exit: 0 },
        },
      },
    ]);
    context.currentTurn[0].parts[0].text = request;
    const result = destructiveOperationsRule.inspect(context);
    assert.equal(result.decision, "pass", request + ": " + command);
    assert.equal(result.findings.length, 0, request + ": " + command);

    const engine = new GuardEngine();
    const inspected = await engine.inspect(
      "authorized-clean-" + command,
      process.cwd(),
      context.currentTurn
    );
    const finding = inspected.results.find(
      (item) => item.ruleId === "safety/destructive-operations"
    );
    assert.equal(finding?.decision, "pass", command);
  }
});

test("safety/destructive-operations does not broaden or fabricate git clean authorization", () => {
  for (const [request, command] of [
    ["Just inspect the repository.", "git clean -fd"],
    ["git clean yapma", "git clean -fd"],
    ["Do not run git clean.", "git clean -fd"],
    ["git clean -fd yap", "git clean -fdx"],
    ["git clean -fd yap", "git clean -fX"],
    ["git clean -fd yap", "git clean -fd && rm -rf ."],
  ]) {
    const context = makeEvidenceContext([
      {
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command },
          metadata: { exit: 0 },
        },
      },
    ]);
    context.currentTurn[0].parts[0].text = request;
    const result = destructiveOperationsRule.inspect(context);
    assert.equal(result.decision, "block", request + ": " + command);
    assert.equal(result.findings.length, 1, request + ": " + command);
  }
});


test("safety/destructive-operations rejects shell substitutions hidden inside authorized git clean", () => {
  const nested = "rm" + " -" + "rf .";
  for (const command of [
    "git clean -fd $(" + nested + ")",
    "git clean -fd " + String.fromCharCode(96) + nested + String.fromCharCode(96),
    "git clean -fd ${FLAGS}",
    "git clean -fd $FLAGS",
    "git clean -fd <(echo data)",
  ]) {
    const context = makeEvidenceContext([{
      type: "tool",
      tool: "bash",
      state: { status: "completed", input: { command }, metadata: { exit: 0 } },
    }]);
    context.currentTurn[0].parts[0].text = "git clean -fd yap";
    const result = destructiveOperationsRule.inspect(context);
    assert.equal(result.decision, "block", command);
  }
});

test("safety/destructive-operations distinguishes explicit git clean consent from prohibition or discussion", () => {
  for (const request of [
    "git clean -fd kullanma",
    "git clean -fd yerine git status çalıştır",
    "Please use git status instead of git clean.",
    "What does git clean -fd do?",
    "git clean -fd --help",
  ]) {
    const context = makeEvidenceContext([{
      type: "tool",
      tool: "bash",
      state: { status: "completed", input: { command: "git clean -fd" }, metadata: { exit: 0 } },
    }]);
    context.currentTurn[0].parts[0].text = request;
    assert.equal(destructiveOperationsRule.inspect(context).decision, "block", request);
  }

  for (const request of ["git clean -fd", "git clean -fd yap", "Please run git clean -fd"]) {
    const context = makeEvidenceContext([{
      type: "tool",
      tool: "bash",
      state: { status: "completed", input: { command: "git clean -fd" }, metadata: { exit: 0 } },
    }]);
    context.currentTurn[0].parts[0].text = request;
    assert.equal(destructiveOperationsRule.inspect(context).decision, "pass", request);
  }
});

test("safety/destructive-operations recognizes scoped git clean and requires scope-specific consent", () => {
  const commands = ["git -C other-repo clean -fd", "git -c core.quotepath=false clean -fd"];
  for (const command of commands) {
    const context = makeEvidenceContext([{
      type: "tool",
      tool: "bash",
      state: { status: "completed", input: { command }, metadata: { exit: 0 } },
    }]);
    assert.ok(context.evidence.records.some((r) => r.kind === "destructive-operation"));

    context.currentTurn[0].parts[0].text = "git clean -fd yap";
    assert.equal(destructiveOperationsRule.inspect(context).decision, "block", command);

    context.currentTurn[0].parts[0].text = command + " yap";
    assert.equal(destructiveOperationsRule.inspect(context).decision, "pass", command);
  }
});

test("safety/destructive-operations does not flag git clean dry-runs as destructive", () => {
  for (const command of [
    "git clean -nfd",
    "git clean -fdn",
    "git clean -f -d --dry-run",
    "git -C other-repo clean --dry-run --force",
  ]) {
    const context = makeEvidenceContext([{
      type: "tool",
      tool: "bash",
      state: { status: "completed", input: { command }, metadata: { exit: 0 } },
    }]);
    assert.ok(!context.evidence.records.some((r) => r.kind === "destructive-operation"), command);
    assert.equal(destructiveOperationsRule.inspect(context).decision, "pass", command);
  }
  const chained = "git clean -nfd && git clean -fd";
  const context = makeEvidenceContext([{
    type: "tool",
    tool: "bash",
    state: { status: "completed", input: { command: chained }, metadata: { exit: 0 } },
  }]);
  assert.ok(context.evidence.records.some((r) => r.kind === "destructive-operation"));
  assert.equal(destructiveOperationsRule.inspect(context).decision, "block");
});

// --- Task contract and completion control (conservative, evidence-driven) ---
function taskTurn(instruction, assistantParts, userID = "task-user") {
  return [
    { info: { id: userID, role: "user" }, parts: [{ type: "text", text: instruction }] },
    { info: { id: "task-assistant", role: "assistant" }, parts: assistantParts },
  ];
}

function taskCtx(instruction, parts) {
  const currentTurn = taskTurn(instruction, parts);
  return {
    sessionID: "task-test",
    directory: process.cwd(),
    messages: currentTurn,
    currentTurn,
    ruleConfig: {},
    evidence: collectTurnEvidence(currentTurn),
  };
}

function completedTool(name, input, output = "", exit = 0) {
  return {
    type: "tool",
    tool: name,
    state: {
      status: "completed",
      input,
      output,
      metadata: { exit },
    },
  };
}

test("task contract records explicit Turkish/English iteration but not inferred review loops", () => {
  const cases = [
    ["Bir hata bulduğunda düzelt ve incelemeyi baştan başlat; hata kalmayana kadar devam et.", true],
    ["Whenever you find a bug, fix it and repeat the full audit until there are no more issues.", true],
    ["İlk hatayı düzelt ve tekrar debug turuna başla.", true],
    ["Lütfen yalnız ilk hatayı düzelt, tekrar başlama.", false],
    ["Please inspect the source code once.", false],
    ["What would happen if an audit were repeated?", false],
  ];
  for (const [text, expected] of cases) {
    const contract = extractTaskContract(taskTurn(text, []));
    assert.equal(contract.iterativeReview, expected, text);
  }
});

test("task contract prioritizes the latest genuine human prompt over earlier deferrals and synthetic prompts", () => {
  const messages = [
    ...taskTurn("We suspended this work earlier.", []),
    { info: { id: "u-current", role: "user" }, parts: [{ type: "text", text: "Implement this now and run tests." }] },
    { info: { id: "other-plugin", role: "user" }, parts: [{ type: "text", text: "Do nothing", synthetic: true }] },
  ];
  const contract = extractTaskContract(messages);
  assert.equal(contract.turnKey, "u-current");
  assert.deepEqual(contract.requiredVerifications, ["test"]);
  assert.match(taskGuidance(contract), /latest explicit human instructions/);
  assert.doesNotMatch(taskGuidance(contract), /suspended this work/);
});

test("task contract ignores synthetic-only histories and negated verification requirements", () => {
  const synthetic = [{ info: { id: "s", role: "user" }, parts: [{ type: "text", text: "run tests", synthetic: true }] }];
  assert.equal(extractTaskContract(synthetic), undefined);
  const contract = extractTaskContract(taskTurn("Do not run tests.", []));
  assert.deepEqual(contract.requiredVerifications, []);
});

test("task/instruction-fidelity catches refusal based on old paused decisions", () => {
  const scenarios = [
    ["Implement the feature now.", "You previously paused this feature, so I won't implement it."],
    ["Bu özelliği şimdi geliştir.", "Daha önce bu özelliği askıya almıştın, bu yüzden yapmıyorum."],
  ];
  for (const [instruction, reply] of scenarios) {
    const result = instructionFidelityRule.inspect(taskCtx(instruction, [{ type: "text", text: reply }]));
    assert.equal(result.decision, "block", reply);
    assert.equal(result.findings[0].confidence, "high");
  }
});

test("task/instruction-fidelity permits historical context without refusal and explanatory questions", () => {
  const cases = [
    ["Implement the feature now.", "You previously paused it, but I implemented it as requested."],
    ["Why did we pause the feature?", "We paused it because the earlier tests failed."],
    ["Bu özelliği şimdi geliştir.", "Önceden askıya almıştın, ama şimdi uyguluyorum."],
  ];
  for (const [instruction, reply] of cases) {
    const result = instructionFidelityRule.inspect(taskCtx(instruction, [{ type: "text", text: reply }]));
    assert.equal(result.decision, "pass", reply);
  }
});

test("task/instruction-fidelity blocks redundant choice handoff after an explicit Turkish action", async () => {
  const engine = new GuardEngine({ enabled: true });
  const result = await engine.inspect("redundant-handoff-tr", process.cwd(), taskTurn(
    "Devam et, gerekli kontrolleri yap ve işi tamamla.",
    [{ type: "text", text: "İstersen bu iki aksiyonu hemen tek sprintte kapatırım, ya da önce SentinelX/RDC tarafını ölçüp karşılaştırırım. Hangisini tercih edersin?" }]
  ));
  assert.equal(result.decision, "block");
  const finding = result.results
    .find((item) => item.ruleId === "task/instruction-fidelity")?.findings[0];
  assert.equal(finding?.pattern, "redundant confirmation after explicit action");
});

test("task/instruction-fidelity blocks redundant English permission request before work starts", () => {
  const result = instructionFidelityRule.inspect(taskCtx(
    "Continue with the implementation and finish the task.",
    [{ type: "text", text: "Would you like me to proceed with the implementation, or should I stop here?" }]
  ));
  assert.equal(result.decision, "block");
  assert.equal(result.findings[0]?.pattern, "redundant confirmation after explicit action");
});

test("task/instruction-fidelity does not turn exploratory user questions into mandatory action", () => {
  const result = instructionFidelityRule.inspect(taskCtx(
    "Should we implement the feature now?",
    [{ type: "text", text: "Would you like me to compare the two approaches first?" }]
  ));
  assert.equal(result.decision, "pass");
});

test("task/instruction-fidelity permits a real blocker that requires missing credentials or permission", () => {
  for (const reply of [
    "I need the deployment token to continue. Please provide it.",
    "I cannot continue until repository write permission is granted.",
  ]) {
    const result = instructionFidelityRule.inspect(taskCtx(
      "Continue with deployment and finish the task.",
      [{ type: "text", text: reply }]
    ));
    assert.equal(result.decision, "pass", reply);
  }
});

test("task/instruction-fidelity permits a genuinely unresolved technical choice", () => {
  const result = instructionFidelityRule.inspect(taskCtx(
    "Implement the storage layer now.",
    [{ type: "text", text: "I need one architectural choice before I can proceed: SQLite and PostgreSQL require different migration paths. Which database should I target?" }]
  ));
  assert.equal(result.decision, "pass");
});

test("task/instruction-fidelity permits optional follow-up questions after observable work", () => {
  const result = instructionFidelityRule.inspect(taskCtx(
    "Implement the feature now.",
    [
      completedTool("write_to_file", {
        path: "src/feature.ts",
        content: "export const feature = true;",
      }, "saved", 0),
      { type: "text", text: "Implemented the requested feature. Would you like me to add documentation too?" },
    ]
  ));
  assert.equal(result.decision, "pass");
});

test("task/completion-gate catches stopping immediately after a fix when a second review was required", () => {
  const result = taskCompletionRule.inspect(taskCtx(
    "Her hata bulduğunda düzelt ve incelemeyi baştan başlat; hata kalmayana kadar devam et.",
    [completedTool("write", { filePath: "src/feature.ts", content: "export const fixed = true;" }),
      { type: "text", text: "İlk hatayı düzelttim, iş bitti." }]
  ));
  assert.equal(result.decision, "block");
  assert.equal(result.findings[0].confidence, "high");
});

test("task/completion-gate passes an actual subsequent review with supported completion", () => {
  const result = taskCompletionRule.inspect(taskCtx(
    "Her hata bulduğunda düzelt ve incelemeyi baştan başlat.",
    [completedTool("write", { filePath: "src/feature.ts", content: "export const fixed = true;" }),
      completedTool("read", { filePath: "src/feature.ts" }, "export const fixed = true;"),
      { type: "text", text: "Tekrar inceledim; başka hata yok, denetim tamamlandı." }]
  ));
  assert.equal(result.decision, "pass");
  assert.equal(result.findings.length, 0);
});

test("task/completion-gate never loops on a concrete blocker or transparent unfinished report", () => {
  for (const response of [
    "Erişim gerekiyor; bu nedenle devam edemiyorum.",
    "I cannot run the test suite: required service is unavailable.",
    "The audit is not yet complete; I need permission to proceed.",
  ]) {
    const result = taskCompletionRule.inspect(taskCtx(
      "Her hata bulduğunda düzelt, sonra incelemeyi baştan başlat.",
      [completedTool("write", { filePath: "src/feature.ts", content: "export const fixed = true;" }),
        { type: "text", text: response }]
    ));
    assert.equal(result.decision, "pass", response);
  }
});

test("task/completion-gate preserves requested verification as advisory if evidence is unavailable", () => {
  const result = taskCompletionRule.inspect(taskCtx(
    "Fix the implementation and run tests.",
    [completedTool("write", { filePath: "src/feature.ts", content: "export const fixed = true;" }),
      { type: "text", text: "Task completed." }]
  ));
  assert.equal(result.decision, "pass");
  assert.ok(result.findings.some((finding) => finding.confidence === "medium"));
});

test("task/completion-gate blocks claiming completion after explicitly requested tests failed", () => {
  const result = taskCompletionRule.inspect(taskCtx(
    "Fix it and run tests.",
    [completedTool("write", { filePath: "src/feature.ts", content: "export const fixed = true;" }),
      completedTool("bash", { command: "npm test" }, "1 test failed", 1),
      { type: "text", text: "Task completed." }]
  ));
  assert.equal(result.decision, "block");
  assert.ok(result.findings.some((finding) => finding.confidence === "high"));
});

test("GuardEngine uses an independent bounded iterative continuation budget", async () => {
  const engine = new GuardEngine({
    enabled: true,
    remediationBudget: 0,
    iterationBudget: 2,
    rules: {
      "task/completion-gate": "error",
      ...Object.fromEntries(
        Object.keys(BUILTIN_RULES)
          .filter((name) => name !== "task/completion-gate")
          .map((name) => [name, "off"])
      ),
    },
  });
  const instruction = "Her hata bulduğunda düzelt ve incelemeyi baştan başlat.";
  const initial = taskTurn(instruction, [
    completedTool("write", { filePath: "src/a.ts", content: "export const a = 1;" }),
    { type: "text", text: "Denetim tamamlandı." },
  ], "human-iteration");
  assert.equal((await engine.inspect("iteration-session", process.cwd(), initial)).decision, "block");
  const synthetic = { info: { id: "guardian-synthetic", role: "user" },
    parts: [{ type: "text", text: REMEDIATION_MARKER + "\nReview again.", synthetic: true }] };
  const resumed = [
    ...initial,
    synthetic,
    { info: { id: "a-resumed", role: "assistant" }, parts: [
      completedTool("write", { filePath: "src/b.ts", content: "export const b = 2;" }),
      { type: "text", text: "Denetim tamamlandı." },
    ] },
  ];
  assert.equal((await engine.inspect("iteration-session", process.cwd(), resumed)).decision, "block");
  const stalled = [
    ...resumed,
    { info: { id: "a-stalled", role: "assistant" },
      parts: [{ type: "text", text: "Denetim tamamlandı." }] },
  ];
  assert.equal((await engine.inspect("iteration-session", process.cwd(), stalled)).decision, "pass");
});

test("OpenCode V1 chat.message and system.transform preserve explicit task guidance", async () => {
  const request = "Her hata bulduğunda düzelt, ardından incelemeyi baştan başlat.";
  const injected = [];
  const messages = taskTurn(request, [
    completedTool("write", { filePath: "src/item.ts", content: "export const item = 1;" }),
    { type: "text", text: "İnceleme tamamlandı." },
  ]);
  const hooks = await OpencodeGuardian.server({
    directory: process.cwd(),
    client: {
      session: {
        messages: async () => ({ data: messages }),
        promptAsync: async (input) => { injected.push(input.body.parts[0].text); },
      },
    },
  });
  await hooks["chat.message"](
    { sessionID: "v1-task", messageID: "task-user" },
    { message: { role: "user" }, parts: [{ type: "text", text: request }] }
  );
  const output = { system: [] };
  await hooks["experimental.chat.system.transform"]({ sessionID: "v1-task" }, output);
  assert.equal(output.system.length, 1);
  assert.match(output.system[0], /another review pass/);
  await hooks["experimental.chat.system.transform"]({ sessionID: "v1-task" }, output);
  assert.equal(output.system.length, 1, "must not duplicate guidance");
  await hooks["experimental.chat.system.transform"]({ sessionID: "another-session" }, output);
  assert.equal(output.system.length, 1, "must not leak tasks to other sessions");

  await hooks.event({ event: { type: "session.idle", properties: { sessionID: "v1-task" } } });
  assert.equal(injected.length, 1);
  assert.match(injected[0], /another substantive review/);
  await hooks.event({ event: { type: "session.deleted", properties: { sessionID: "v1-task" } } });
  const cleared = { system: [] };
  await hooks["experimental.chat.system.transform"]({ sessionID: "v1-task" }, cleared);
  assert.deepEqual(cleared.system, []);
});

test("OpenCode V2 prompt/context hooks and idle subscription use real domain signatures", async () => {
  const request = "Her hata bulduğunda düzelt ve incelemeyi baştan başlat.";
  const hooks = new Map();
  const disposed = [];
  const synthetic = [];
  let currentDirectory;
  let eventController;
  const context = {
    location: { directory: process.cwd() },
    event: {
      subscribe({ signal }) {
        eventController = signal;
        return (async function* () {
          yield { type: "session.idle", data: { sessionID: "v2-task" } };
          await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
        })();
      },
    },
    session: {
      async hook(name, callback) {
        hooks.set(name, callback);
        return { async dispose() { disposed.push(name); } };
      },
      async get({ sessionID }) {
        assert.equal(sessionID, "v2-task");
        currentDirectory = process.cwd();
        return { location: { directory: currentDirectory } };
      },
      async context({ sessionID }) {
        assert.equal(sessionID, "v2-task");
        return [
          { id: "v2-user", type: "user", text: request },
          { id: "v2-agent", type: "assistant", agent: "orchestrator", content: [
            { type: "tool", name: "write", state: {
              status: "completed",
              input: { filePath: "src/item.ts", content: "export const item = 1;" },
            } },
            { type: "text", text: "İnceleme tamamlandı." },
          ] },
        ];
      },
      async synthetic(input) { synthetic.push(input); return {}; },
    },
  };
  const cleanup = await OpencodeGuardian.setup(context);
  assert.equal(typeof hooks.get("prompt"), "function");
  assert.equal(typeof hooks.get("context"), "function");
  await hooks.get("prompt")({
    sessionID: "v2-task", messageID: "v2-user",
    prompt: { text: request }, delivery: "queue",
  });
  const modelRequest = { sessionID: "v2-task", system: [], tools: {} };
  await hooks.get("context")(modelRequest);
  await hooks.get("context")(modelRequest);
  assert.equal(modelRequest.system.length, 1, "system prompt should be idempotent");
  assert.match(modelRequest.system[0].text, /another review pass/);
  const unrelated = { sessionID: "v2-other", system: [], tools: {} };
  await hooks.get("context")(unrelated);
  assert.deepEqual(unrelated.system, []);

  // The idle event loop is asynchronous; the fake host yields the event once.
  for (let i = 0; i < 50 && synthetic.length === 0; i++) {
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  assert.equal(synthetic.length, 1);
  assert.equal(synthetic[0].delivery, "queue");
  assert.equal(synthetic[0].resume, true);
  assert.match(synthetic[0].text, /another substantive review/);
  assert.equal(currentDirectory, process.cwd());
  await cleanup();
  assert.equal(eventController.aborted, true);
  assert.deepEqual(disposed.sort(), ["context", "prompt"]);
});

test("V2 context normalizer retains synthetic Guardian marker and real user-turn boundaries", () => {
  const normalized = normalizeV2Messages([
    { id: "u", type: "user", text: "Fix and re-review." },
    { id: "s", type: "synthetic", text: REMEDIATION_MARKER + "\nRestart the review." },
    { id: "a", type: "assistant", content: [{ type: "text", text: "I continued." }] },
  ]);
  assert.equal(normalized[1].parts[0].synthetic, true);
  assert.equal(extractTaskContract(normalized).turnKey, "u");
});

test("task contract does not convert exploratory questions or explicit prohibitions into actions", () => {
  const prompts = [
    "Should we repeat the full audit after every bug?",
    "What if we run tests and review the code again?",
    "Do not implement the feature yet.",
    "Lütfen tekrar başlama, ilk hatayı düzelt.",
  ];
  for (const prompt of prompts) {
    const contract = extractTaskContract(taskTurn(prompt, []));
    assert.equal(contract.iterativeReview, false, prompt);
  }
  for (const prompt of prompts.slice(0, 2)) {
    assert.deepEqual(extractTaskContract(taskTurn(prompt, [])).requiredVerifications, []);
  }
});

test("task contract retains lint when only tests are forbidden", () => {
  const contract = extractTaskContract(taskTurn("Do not run tests; run lint instead.", []));
  assert.deepEqual(contract.requiredVerifications, ["lint"]);
  assert.equal(contract.iterativeReview, false);
});

test("task/instruction-fidelity never overrides the current user's explicit prohibition", () => {
  const context = taskCtx(
    "Do not implement the feature yet.",
    [{ type: "text", text: "You previously paused the work, so I won't implement it." }]
  );
  assert.equal(instructionFidelityRule.inspect(context).decision, "pass");
  context.currentTurn[0].parts[0].text = "Should we implement the feature?";
  assert.equal(instructionFidelityRule.inspect(context).decision, "pass");
});

test("task/completion-gate requires new source inspection for an explicitly repeated source review", () => {
  const context = taskCtx(
    "Her hata bulduğunda düzelt, sonra incelemeyi baştan başlat.",
    [completedTool("write", { filePath: "src/a.ts", content: "export const a = true;" }),
      completedTool("bash", { command: "npm test" }, "All passing", 0),
      { type: "text", text: "Testler geçti. İnceleme tamamlandı." }]
  );
  assert.equal(extractTaskContract(context.currentTurn).requiresSourceReview, true);
  assert.equal(taskCompletionRule.inspect(context).decision, "block");
});

test("task/completion-gate recognizes repeated test-only verification without demanding a new source read", () => {
  const context = taskCtx(
    "Fix errors and rerun tests until clean.",
    [completedTool("write", { filePath: "src/a.ts", content: "export const a = true;" }),
      completedTool("bash", { command: "npm test" }, "All passing", 0),
      { type: "text", text: "Task completed." }]
  );
  assert.equal(extractTaskContract(context.currentTurn).requiresSourceReview, false);
  assert.equal(taskCompletionRule.inspect(context).decision, "pass");
});

test("task/completion-gate resumes after a promise to review when the agent stopped idle", () => {
  const context = taskCtx(
    "Her hata bulduğunda düzelt ve incelemeyi baştan başlat.",
    [completedTool("write", { filePath: "src/a.ts", content: "export const a = true;" }),
      { type: "text", text: "Düzelttim; tekrar inceleyeceğim." }]
  );
  assert.equal(taskCompletionRule.inspect(context).decision, "block");
});

test("task/completion-gate does not accept empty read outputs as proof of a full source review", () => {
  const context = taskCtx(
    "Fix issues and restart the full source review.",
    [completedTool("write", { filePath: "src/a.ts", content: "export const a = true;" }),
      completedTool("read", { filePath: "src/a.ts" }, ""),
      { type: "text", text: "Task completed." }]
  );
  assert.equal(taskCompletionRule.inspect(context).decision, "block");
});

test("iterative Guardian continuation still inspects new security violations", async () => {
  const engine = new GuardEngine({ enabled: true, iterationBudget: 2 });
  const request = "Her hata bulduğunda düzelt, ardından incelemeyi baştan başlat.";
  const initial = taskTurn(request, [
    completedTool("write", { filePath: "src/feature.ts", content: "export const ready = true;" }),
    { type: "text", text: "İnceleme tamamlandı." },
  ], "security-loop-user");
  assert.equal((await engine.inspect("security-loop", process.cwd(), initial)).decision, "block");

  const synthetic = { info: { id: "security-loop-remediation", role: "user" },
    parts: [{ type: "text", text: REMEDIATION_MARKER + "\nReview again.", synthetic: true }] };
  const fakeToken = "sk-" + "a".repeat(40);
  const resumed = [
    ...initial,
    synthetic,
    { info: { id: "security-loop-assistant", role: "assistant" }, parts: [
      completedTool("write", {
        filePath: "src/secret.ts",
        content: 'export const TOKEN = "' + fakeToken + '";',
      }),
      completedTool("read", { filePath: "src/secret.ts" }, 'export const TOKEN = "' + fakeToken + '";'),
      { type: "text", text: "Tekrar inceledim; inceleme tamamlandı." },
    ] },
  ];
  const result = await engine.inspect("security-loop", process.cwd(), resumed);
  assert.equal(result.decision, "block");
  assert.equal(
    result.results.find((rule) => rule.ruleId === "security/no-secrets")?.decision,
    "block",
    "new violations in the continuation must still be inspected"
  );
  assert.equal(
    result.results.find((rule) => rule.ruleId === "task/completion-gate")?.decision,
    "pass",
    "the completion gate must use cumulative post-change review evidence"
  );
});

test("iterationBudget zero retains completion findings without sending synthetic continuations", async () => {
  const engine = new GuardEngine({ enabled: true, iterationBudget: 0 });
  const messages = taskTurn(
    "Her hata bulduğunda düzelt ve incelemeyi baştan başlat.",
    [completedTool("write", { filePath: "src/x.ts", content: "export const x = 1;" }),
      { type: "text", text: "İnceleme tamamlandı." }],
    "budget-zero-user"
  );
  const result = await engine.inspect("budget-zero-task", process.cwd(), messages);
  assert.equal(result.decision, "pass");
  assert.equal(
    result.results.find((item) => item.ruleId === "task/completion-gate")?.decision,
    "block"
  );
});

test("task/completion-gate blocks claiming completion while admitting incomplete checks (B-08)", () => {
  const result = taskCompletionRule.inspect(taskCtx(
    "Fix the bug and run tests.",
    [completedTool("write", { filePath: "src/feature.ts", content: "export const fixed = true;" }),
      { type: "text", text: "The work is completed. Note that module B tests are not complete." }]
  ));
  assert.equal(result.decision, "block");
  assert.ok(result.findings.some((finding) => finding.confidence === "high" && finding.pattern.includes("test verification")));
});

test("engine rollback allows re-inspecting the same assistant message after delivery failure (B-09)", async () => {
  const engine = new GuardEngine({ enabled: true });
  const messages = [
    { info: { id: "user-1", role: "user" }, parts: [{ type: "text", text: "Fix the checkout page" }] },
    {
      info: { id: "asst-1", role: "assistant" },
      parts: [
        {
          type: "text",
          text: "I finished the changes. The test failure is unrelated to this change and already broken on main.",
        },
      ],
    },
  ];

  const firstResult = await engine.inspect("retry-session", process.cwd(), messages);
  assert.equal(firstResult.decision, "block");
  assert.ok(typeof firstResult.rollback === "function");

  // Simulate delivery failure: promptAsync failed, rollback called
  firstResult.rollback();

  // Next inspection attempt on the same message must NOT return pass/empty
  const retryResult = await engine.inspect("retry-session", process.cwd(), messages);
  assert.equal(retryResult.decision, "block");
  assert.equal(retryResult.results.find((r) => r.ruleId === "discipline/no-evasion")?.decision, "block");
});

test("extractCurrentTurn resolves active agent from current turn, not stale session history (B-10)", async () => {
  const { extractCurrentTurn } = await import("../dist/engine.js");
  const messages = [
    { info: { id: "msg-1", role: "user" }, parts: [{ type: "text", text: "Old prompt" }] },
    { info: { id: "msg-2", role: "assistant", agent: "worker" }, parts: [{ type: "text", text: "Subagent reply" }] },
    { info: { id: "msg-3", role: "user" }, parts: [{ type: "text", text: "Current prompt" }] },
    { info: { id: "msg-4", role: "assistant", agent: "orchestrator" }, parts: [{ type: "text", text: "Main reply" }] },
  ];
  const turn = extractCurrentTurn(messages);
  assert.equal(turn.isSubagent, false);
});

test("loadConfig throws GuardianConfigError when config file is malformed rather than falling back (B-11)", async () => {
  const { loadConfig, GuardianConfigError } = await import("../dist/engine.js");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-malformed-cfg-"));
  try {
    fs.writeFileSync(path.join(tmpDir, "opencode-guardian.json"), '{"enabled": true, rules: }');
    assert.throws(
      () => loadConfig(tmpDir),
      (err) => err instanceof GuardianConfigError && err.configPath.includes("opencode-guardian.json")
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("configuration rejects incorrect security field types", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-config-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, "opencode-guardian.json");
  for (const invalid of [
    { enabled: "false" },
    { preflight: { enabled: "false" } },
    { updateNotice: { enabled: 0 } },
    { remediationBudget: "1" },
    { iterationBudget: -1 },
    { rules: { "security/no-secrets": "allow" } },
    { rules: { "security/no-secrets": { customPhrases: [1] } } },
  ]) {
    fs.writeFileSync(file, JSON.stringify(invalid));
    assert.throws(() => loadConfig(dir), GuardianConfigError);
  }
  fs.writeFileSync(file, JSON.stringify({
    enabled: false, preflight: { enabled: true },
    remediationBudget: 1, rules: { "security/no-secrets": "warn" },
  }));
  assert.equal(loadConfig(dir).enabled, false);
});

test("OpenCode V2 foreground subagent handoff waits for Guardian remediation and replaces stale parent output", async () => {
  const hooks = new Map();
  let releaseIdle;
  const idleReady = new Promise((resolve) => { releaseIdle = resolve; });
  let phase = 0;
  let syntheticCalls = 0;
  let waitCalls = 0;
  const remediationTexts = [];
  let cleanup;

  const initial = [
    { id: "v2-u-audit", type: "user", text: "Run the security audit completely and report every issue." },
    { id: "v2-a-audit-1", type: "assistant", agent: "explore",
      content: [{ type: "text", text: "The remaining test failure is unrelated to this change." }] },
  ];
  const finalContext = () => [
    ...initial,
    { id: "v2-g-audit", type: "synthetic", text: remediationTexts[0] },
    { id: "v2-a-audit-2", type: "assistant", agent: "explore",
      content: [{ type: "text", text: "Re-ran the security audit. Found two additional minor issues and reported both." }] },
  ];

  const context = {
    location: { directory: process.cwd() },
    event: {
      subscribe({ signal }) {
        return (async function* () {
          await idleReady;
          yield { type: "session.idle", data: { sessionID: "v2-child-audit" } };
          await new Promise((resolve) => {
            if (signal.aborted) return resolve();
            signal.addEventListener("abort", resolve, { once: true });
          });
        })();
      },
    },
    tool: {
      async hook(name, callback) {
        const list = hooks.get(name) ?? [];
        list.push(callback);
        hooks.set(name, list);
        return { async dispose() {} };
      },
    },
    session: {
      async hook() { return { async dispose() {} }; },
      async get({ sessionID }) {
        if (sessionID === "v2-child-audit") {
          return { id: sessionID, parentID: "v2-parent-audit", location: { directory: process.cwd() } };
        }
        return { id: sessionID, location: { directory: process.cwd() } };
      },
      async context({ sessionID }) {
        assert.equal(sessionID, "v2-child-audit");
        return phase === 0 ? initial : finalContext();
      },
      async synthetic(input) {
        syntheticCalls++;
        remediationTexts.push(input.text);
        phase = 1;
        return {};
      },
      async wait({ sessionID }) {
        assert.equal(sessionID, "v2-child-audit");
        waitCalls++;
      },
    },
  };

  try {
    cleanup = await OpencodeGuardian.setup(context);
    const before = hooks.get("execute.before");
    const after = hooks.get("execute.after");
    assert.ok(before?.length);
    assert.ok(after?.length);

    for (const callback of before) {
      await callback({
        tool: "subagent",
        sessionID: "v2-parent-audit",
        agent: "orchestrator",
        messageID: "v2-parent-message",
        id: "v2-sub-call",
        input: { agent: "explore", description: "security audit", prompt: "audit", background: false },
      });
    }

    releaseIdle();
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.equal(syntheticCalls, 0, "foreground child idle must be deferred to the handoff barrier");

    const event = {
      tool: "subagent",
      sessionID: "v2-parent-audit",
      agent: "orchestrator",
      messageID: "v2-parent-message",
      id: "v2-sub-call",
      input: { agent: "explore", description: "security audit", prompt: "audit", background: false },
      status: "completed",
      result: {
        output: { sessionID: "v2-child-audit", status: "completed",
          output: "The remaining test failure is unrelated to this change." },
        content: '<subagent sessionID="v2-child-audit" state="completed">\nThe remaining test failure is unrelated to this change.\n</subagent>',
        metadata: { sessionID: "v2-child-audit", status: "completed" },
      },
    };
    for (const callback of after) await callback(event);

    assert.equal(syntheticCalls, 1);
    assert.equal(waitCalls, 1, "handoff barrier must wait for the remediation turn to finish");
    assert.match(remediationTexts[0], /^\[opencode-guardian remediation\]/);
    assert.match(event.result.output.output, /Found two additional minor issues/);
    assert.match(event.result.content, /Found two additional minor issues/);
    assert.doesNotMatch(event.result.content, /remaining test failure is unrelated/);
  } finally {
    await cleanup?.();
  }
});

test("OpenCode V2 background subagent keeps idle remediation outside the foreground barrier", async () => {
  const hooks = new Map();
  let releaseIdle;
  const idleReady = new Promise((resolve) => { releaseIdle = resolve; });
  let syntheticCalls = 0;
  let cleanup;
  const context = {
    location: { directory: process.cwd() },
    event: {
      subscribe({ signal }) {
        return (async function* () {
          await idleReady;
          yield { type: "session.idle", data: { sessionID: "v2-child-bg" } };
          await new Promise((resolve) => {
            if (signal.aborted) return resolve();
            signal.addEventListener("abort", resolve, { once: true });
          });
        })();
      },
    },
    tool: {
      async hook(name, callback) {
        const list = hooks.get(name) ?? [];
        list.push(callback);
        hooks.set(name, list);
        return { async dispose() {} };
      },
    },
    session: {
      async hook() { return { async dispose() {} }; },
      async get({ sessionID }) {
        if (sessionID === "v2-child-bg") {
          return { id: sessionID, parentID: "v2-parent-bg", location: { directory: process.cwd() } };
        }
        return { id: sessionID, location: { directory: process.cwd() } };
      },
      async context() {
        return [
          { id: "v2-u-bg", type: "user", text: "Run the audit." },
          { id: "v2-a-bg", type: "assistant", agent: "explore",
            content: [{ type: "text", text: "The failure is unrelated to this change." }] },
        ];
      },
      async synthetic() { syntheticCalls++; return {}; },
    },
  };
  try {
    cleanup = await OpencodeGuardian.setup(context);
    for (const callback of hooks.get("execute.before") ?? []) {
      await callback({
        tool: "subagent", sessionID: "v2-parent-bg", agent: "orchestrator",
        messageID: "v2-parent-bg-message", id: "v2-sub-bg",
        input: { agent: "explore", description: "background audit", prompt: "audit", background: true },
      });
    }
    releaseIdle();
    for (let i = 0; i < 60 && syntheticCalls === 0; i++) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(syntheticCalls, 1, "background child must retain normal idle remediation");
  } finally {
    await cleanup?.();
  }
});
