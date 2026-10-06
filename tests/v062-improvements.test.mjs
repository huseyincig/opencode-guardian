import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { noGhostDepsRule, isHallucinatedOrSuspiciousPackage } from "../dist/rules/no-ghost-deps.js";
import { noCheatRule } from "../dist/rules/no-cheat.js";
import { noShortcutsRule } from "../dist/rules/no-shortcuts.js";
import {
  evaluatePreflight, enforcePreflight,
  isLazyCommitMessage, isHallucinatedOrMalformedPackageInstall,
} from "../dist/preflight.js";
import { guardianCommandReport, GUARDIAN_COMMANDS } from "../dist/commands.js";

// --- 1. Multi-language Manifest & Ghost Dependencies ---

test("manifest/no-ghost-deps: PHP composer.json support", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-php-deps-"));
  try {
    fs.writeFileSync(
      path.join(root, "composer.json"),
      JSON.stringify({
        require: {
          "php": "^8.2",
          "guzzlehttp/guzzle": "^7.8"
        },
        "require-dev": {
          "phpunit/phpunit": "^10.0"
        },
        autoload: {
          "psr-4": {
            "App\\": "src/"
          }
        }
      })
    );

    // Declared dependency + built-in + local namespace -> pass
    const okContext = {
      sessionID: "php-ok",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-php-1", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "src/Controller.php"),
                  content: "<?php\nnamespace App;\nuse GuzzleHttp\\Client;\nuse App\\Services\\AuthService;\nuse DateTime;\nuse Exception;\n",
                },
              },
            },
          ],
        },
      ],
    };
    assert.equal(noGhostDepsRule.inspect(okContext).decision, "pass");

    // Undeclared third-party dependency -> block
    const badContext = {
      sessionID: "php-bad",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-php-2", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "src/Controller.php"),
                  content: "<?php\nnamespace App;\nuse Symfony\\Component\\HttpFoundation\\Request;\n",
                },
              },
            },
          ],
        },
      ],
    };
    const badResult = noGhostDepsRule.inspect(badContext);
    assert.equal(badResult.decision, "block");
    assert.ok(badResult.findings.some((f) => f.pattern.includes("symfony/component-http-foundation") || f.pattern.includes("Symfony\\Component")));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("manifest/no-ghost-deps: C# / .NET .csproj support", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-dotnet-deps-"));
  try {
    fs.writeFileSync(
      path.join(root, "MyApp.csproj"),
      `<Project Sdk="Microsoft.NET.Sdk">
        <ItemGroup>
          <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
        </ItemGroup>
      </Project>`
    );

    // Declared package + framework namespaces -> pass
    const okContext = {
      sessionID: "cs-ok",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-cs-1", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "Services/DataService.cs"),
                  content: "using System;\nusing System.Collections.Generic;\nusing Microsoft.Extensions.Logging;\nusing Newtonsoft.Json;\n",
                },
              },
            },
          ],
        },
      ],
    };
    assert.equal(noGhostDepsRule.inspect(okContext).decision, "pass");

    // Undeclared NuGet package -> block
    const badContext = {
      sessionID: "cs-bad",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-cs-2", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "Services/DataService.cs"),
                  content: "using System;\nusing Dapper;\n",
                },
              },
            },
          ],
        },
      ],
    };
    const badResult = noGhostDepsRule.inspect(badContext);
    assert.equal(badResult.decision, "block");
    assert.ok(badResult.findings.some((f) => f.pattern === "Dapper"));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("manifest/no-ghost-deps: JVM (pom.xml and build.gradle) support", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-jvm-deps-"));
  try {
    fs.writeFileSync(
      path.join(root, "pom.xml"),
      `<project>
        <dependencies>
          <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-lang3</artifactId>
            <version>3.14.0</version>
          </dependency>
        </dependencies>
      </project>`
    );

    // Declared package + standard java/javax/kotlin -> pass
    const okContext = {
      sessionID: "jvm-ok",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-jvm-1", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "src/main/java/App.java"),
                  content: "package com.example;\nimport java.util.List;\nimport javax.crypto.Cipher;\nimport org.apache.commons.lang3.StringUtils;\n",
                },
              },
            },
          ],
        },
      ],
    };
    assert.equal(noGhostDepsRule.inspect(okContext).decision, "pass");

    // Undeclared third-party Java package -> block
    const badContext = {
      sessionID: "jvm-bad",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-jvm-2", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "src/main/java/App.java"),
                  content: "package com.example;\nimport org.joda.time.DateTime;\n",
                },
              },
            },
          ],
        },
      ],
    };
    const badResult = noGhostDepsRule.inspect(badContext);
    assert.equal(badResult.decision, "block");
    assert.ok(badResult.findings.some((f) => f.pattern.includes("org.joda.time") || f.pattern.includes("joda-time")));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("manifest/no-ghost-deps: Ruby Gemfile support", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-ruby-deps-"));
  try {
    fs.writeFileSync(
      path.join(root, "Gemfile"),
      `source "https://rubygems.org"\ngem "faraday", "~> 2.0"\n`
    );

    // Declared gem + standard library requires -> pass
    const okContext = {
      sessionID: "rb-ok",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-rb-1", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "app.rb"),
                  content: "require 'json'\nrequire 'fileutils'\nrequire 'uri'\nrequire 'faraday'\n",
                },
              },
            },
          ],
        },
      ],
    };
    assert.equal(noGhostDepsRule.inspect(okContext).decision, "pass");

    // Undeclared gem -> block
    const badContext = {
      sessionID: "rb-bad",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-rb-2", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "app.rb"),
                  content: "require 'redis'\n",
                },
              },
            },
          ],
        },
      ],
    };
    const badResult = noGhostDepsRule.inspect(badContext);
    assert.equal(badResult.decision, "block");
    assert.ok(badResult.findings.some((f) => f.pattern === "redis"));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("manifest/no-ghost-deps: Dart / Flutter pubspec.yaml support", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-dart-deps-"));
  try {
    fs.writeFileSync(
      path.join(root, "pubspec.yaml"),
      `name: my_app\ndependencies:\n  flutter:\n    sdk: flutter\n  http: ^1.2.0\n`
    );

    // Declared package + sdk imports -> pass
    const okContext = {
      sessionID: "dart-ok",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-dart-1", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "lib/main.dart"),
                  content: "import 'dart:async';\nimport 'dart:convert';\nimport 'package:http/http.dart';\n",
                },
              },
            },
          ],
        },
      ],
    };
    assert.equal(noGhostDepsRule.inspect(okContext).decision, "pass");

    // Undeclared package import -> block
    const badContext = {
      sessionID: "dart-bad",
      directory: root,
      messages: [],
      ruleConfig: {},
      currentTurn: [
        {
          info: { id: "a-dart-2", role: "assistant" },
          parts: [
            {
              type: "tool",
              state: {
                input: {
                  path: path.join(root, "lib/main.dart"),
                  content: "import 'package:dio/dio.dart';\n",
                },
              },
            },
          ],
        },
      ],
    };
    const badResult = noGhostDepsRule.inspect(badContext);
    assert.equal(badResult.decision, "block");
    assert.ok(badResult.findings.some((f) => f.pattern === "dio"));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// --- 2. Package Hallucination & Typosquatting Guard ---

test("hallucination and typosquatting detection in preflight and no-ghost-deps", () => {
  // npm hallucinated uppercase or security suffixes
  assert.equal(isHallucinatedOrMalformedPackageInstall("npm install React"), true);
  assert.equal(isHallucinatedOrMalformedPackageInstall("npm i lodash-security-patch"), true);
  assert.equal(isHallucinatedOrMalformedPackageInstall("pnpm add express-official"), true);
  assert.equal(isHallucinatedOrMalformedPackageInstall("yarn add chalk-fixed-version"), true);

  // valid installs
  assert.equal(isHallucinatedOrMalformedPackageInstall("npm install react react-dom"), false);
  assert.equal(isHallucinatedOrMalformedPackageInstall("npm i -D @types/node typescript"), false);

  // evaluatePreflight blocks hallucinated installs
  assert.equal(
    evaluatePreflight("bash", { command: "npm install express-security-patch" }),
    "hallucinated-or-malformed-package"
  );
  assert.throws(
    () => enforcePreflight("bash", { command: "npm install express-security-patch" }),
    (err) => err.reason === "hallucinated-or-malformed-package"
  );

  // no-ghost-deps helper function
  assert.equal(isHallucinatedOrSuspiciousPackage("npm", "React"), true);
  assert.equal(isHallucinatedOrSuspiciousPackage("npm", "lodash-official"), true);
  assert.equal(isHallucinatedOrSuspiciousPackage("npm", "lodash"), false);
});

// --- 3. Empty / Assertion-less Test Cheat Detection ---

test("testing/no-cheat: detects empty test bodies without assertions", () => {
  // Empty JS test function in edit mutation
  const emptyJsContext = {
    sessionID: "cheat-empty-js",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "a-cheat-1", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                path: "/tmp/app.test.js",
                new_string: "describe('Suite', () => {\n  test('should pass without doing anything', () => {});\n});\n",
              },
            },
          },
        ],
      },
    ],
  };
  const emptyJsResult = noCheatRule.inspect(emptyJsContext);
  assert.equal(emptyJsResult.decision, "block");
  assert.ok(emptyJsResult.findings.some((f) => f.pattern.includes("empty test block")));

  // Empty Python test function with pass in edit mutation
  const emptyPyContext = {
    sessionID: "cheat-empty-py",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "a-cheat-2", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                path: "/tmp/test_service.py",
                new_string: "def test_database_connection():\n    pass\n",
              },
            },
          },
        ],
      },
    ],
  };
  const emptyPyResult = noCheatRule.inspect(emptyPyContext);
  assert.equal(emptyPyResult.decision, "block");
  assert.ok(emptyPyResult.findings.some((f) => f.pattern.includes("empty def test_...: pass")));

  // Valid test with real assertion is allowed
  const validContext = {
    sessionID: "cheat-valid-test",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "a-cheat-3", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                path: "/tmp/app.test.js",
                content: "test('valid math', () => {\n  expect(1 + 1).toBe(2);\n});\n",
              },
            },
          },
        ],
      },
    ],
  };
  assert.equal(noCheatRule.inspect(validContext).decision, "pass");
});

// --- 4. Git Commit Message Discipline ---

test("git commit discipline in preflight and no-shortcuts", () => {
  // Preflight detector
  assert.equal(isLazyCommitMessage('git commit -m "fix"'), true);
  assert.equal(isLazyCommitMessage('git commit -m "wip"'), true);
  assert.equal(isLazyCommitMessage('git commit -m "update"'), true);
  assert.equal(isLazyCommitMessage('git commit -m "changes"'), true);
  assert.equal(isLazyCommitMessage('git commit -m "hotfix"'), true);
  assert.equal(isLazyCommitMessage('git commit -m "feat(core): implement robust error handling"'), false);

  // evaluatePreflight blocks lazy commit
  assert.equal(
    evaluatePreflight("bash", { command: 'git commit -m "fix"' }),
    "lazy-commit-message"
  );
  assert.throws(
    () => enforcePreflight("bash", { command: 'git commit -m "wip"' }),
    (err) => err.reason === "lazy-commit-message"
  );

  // no-shortcuts inspects shell commands
  const lazyShellContext = {
    sessionID: "lazy-git",
    directory: "/tmp",
    messages: [],
    ruleConfig: {},
    currentTurn: [
      {
        info: { id: "a-shortcut-1", role: "assistant" },
        parts: [
          {
            type: "tool",
            state: {
              input: {
                command: 'git add . && git commit -m "update"',
              },
            },
          },
        ],
      },
    ],
  };
  const result = noShortcutsRule.inspect(lazyShellContext);
  assert.equal(result.decision, "block");
  assert.ok(result.findings.some((f) => f.pattern.includes('commit: "update"')));
});

// --- 5. Autonomous Protection Mode Indicator ---

test("protection mode is reported in doctor and config commands while preserving 7 pinned commands", async () => {
  assert.equal(GUARDIAN_COMMANDS.length, 7);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-mode-test-"));
  try {
    const doctor = await guardianCommandReport("doctor", tmp, "0.6.2");
    assert.match(doctor.message, /Protection mode: Autonomous \(Standard\)/);

    const config = await guardianCommandReport("config", tmp, "0.6.2");
    assert.match(config.message, /Protection mode: Autonomous \(Standard\)/);

    // With strict preflight enabled
    fs.writeFileSync(path.join(tmp, "opencode-guardian.json"), JSON.stringify({ preflight: { enabled: true } }));
    const strictDoctor = await guardianCommandReport("doctor", tmp, "0.6.2");
    assert.match(strictDoctor.message, /Protection mode: Autonomous \(Strict\)/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
