import test from "node:test";
import assert from "node:assert/strict";
import {
  evaluatePreflight, isDestructiveCommand, isSimpleFileRemoval,
  noSecretsRule,
} from "../dist/index.js";

const tick = String.fromCharCode(96);
const target = "/tmp/guardian-disposable-fixture";

test("V1/V2 common preflight detects literal command-name substitutions", () => {
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
  return noSecretsRule.inspect({
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
