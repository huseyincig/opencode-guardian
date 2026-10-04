import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { noGhostDepsRule } from "../dist/rules/no-ghost-deps.js";
import { evaluatePreflight, isDestructiveCommand } from "../dist/index.js";

test("Go dependencies in every require block are recognized; undeclared imports remain blocked", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-go-multi-require-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, "go.mod"), [
    "module example.com/app", "go 1.24", "",
    "require (", "example.com/first v1.0.0", ")",
    "require (", "example.com/second v1.0.0 // indirect", ")",
  ].join("\n"));
  const inspect = (dependency) => noGhostDepsRule.inspect({
    sessionID: "go-require-blocks",
    directory,
    messages: [],
    ruleConfig: {},
    currentTurn: [{
      info: { id: "assistant", role: "assistant" },
      parts: [{ type: "tool", state: { input: {
        path: path.join(directory, "main.go"),
        content: 'package main\nimport "' + dependency + '"\n',
      } } }],
    }],
  });
  assert.equal(inspect("example.com/first").decision, "pass");
  assert.equal(inspect("example.com/second").decision, "pass");
  const undeclared = inspect("example.com/missing");
  assert.equal(undeclared.decision, "block");
  assert.equal(undeclared.findings[0].pattern, "example.com/missing");
});


test("scoped Git hard resets and force pushes cannot bypass strict preflight", () => {
  const blocked = [
    "git -C /repo reset --hard HEAD",
    "git -c color.ui=never reset --hard HEAD",
    "sudo git -C /repo push --force-with-lease origin main",
    "git -C '/tmp/other repo' push --force origin main",
    "git -C /repo reset -q --hard HEAD",
  ];
  for (const command of blocked) {
    assert.equal(isDestructiveCommand(command), true, command);
    assert.equal(evaluatePreflight("bash", { command }), "destructive-command", command);
    assert.equal(evaluatePreflight("mcp__Node_Command__shell_exec", { command }), "destructive-command", command);
  }
  for (const command of [
    "git -C /repo status",
    "git -C /repo clean -nfd",
    "git -c color.ui=never diff --stat",
    "git -C /repo push origin main",
  ]) {
    assert.equal(isDestructiveCommand(command), false, command);
    assert.equal(evaluatePreflight("bash", { command }), undefined, command);
  }
});


test("preflight blocks known filesystem formatters and literal fork bombs without flagging examples", () => {
  const dangerous = [
    "mkfs.ext4 /dev/sda",
    "sudo mkfs -t ext4 /dev/sdb",
    "/usr/sbin/mkfs.xfs /dev/sdc",
    ":(){ :|:& };:",
    "f(){ f|f& }; f",
    "bash -c ':(){ :|:& };:'",
  ];
  for (const command of dangerous) {
    assert.equal(isDestructiveCommand(command), true, command);
    assert.equal(evaluatePreflight("bash", { command }), "destructive-command", command);
  }
  for (const command of [
    "mkfs --help",
    "mkfs.ext4 -V",
    "echo 'mkfs.ext4 /dev/sda'",
    "echo ':(){ :|:& };:'",
    "printf '%s\n' 'f(){ f|f& }; f'",
  ]) {
    assert.equal(isDestructiveCommand(command), false, command);
    assert.equal(evaluatePreflight("bash", { command }), undefined, command);
  }
});
