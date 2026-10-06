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

  const rawImport = noGhostDepsRule.inspect({
    sessionID: "go-raw-import",
    directory,
    messages: [],
    ruleConfig: {},
    currentTurn: [{
      info: { id: "assistant-raw", role: "assistant" },
      parts: [{ type: "tool", state: { input: {
        path: path.join(directory, "raw.go"),
        content: "package main\nimport `example.com/raw-missing`\n",
      } } }],
    }],
  });
  assert.equal(rawImport.decision, "block");
  assert.equal(rawImport.findings[0]?.pattern, "example.com/raw-missing");

  for (const declaration of [
    'import _ "example.com/blank-missing"',
    'import . "example.com/dot-missing"',
    'import alias "example.com/alias-missing"',
  ]) {
    const aliased = noGhostDepsRule.inspect({
      sessionID: "go-aliased-import",
      directory,
      messages: [],
      ruleConfig: {},
      currentTurn: [{
        info: { id: "assistant-alias", role: "assistant" },
        parts: [{ type: "tool", state: { input: {
          path: path.join(directory, "alias.go"),
          content: `package main\n${declaration}\n`,
        } } }],
      }],
    });
    assert.equal(aliased.decision, "block", declaration);
  }
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


test("Go dependency scanner ignores imports that appear only in comments or strings", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-go-noncode-import-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, "go.mod"), "module example.com/app\ngo 1.24\n");

  const inspect = (content) => noGhostDepsRule.inspect({
    sessionID: "go-noncode-import",
    directory,
    messages: [],
    ruleConfig: {},
    currentTurn: [{
      info: { id: "assistant", role: "assistant" },
      parts: [{ type: "tool", state: { input: {
        path: path.join(directory, "main.go"),
        content,
      } } }],
    }],
  });

  assert.equal(
    inspect('package main\n// example: import "example.com/comment-only"\nfunc main() {}\n').decision,
    "pass"
  );
  assert.equal(
    inspect('package main\nvar example = \'import "example.com/string-only"\'\nfunc main() {}\n').decision,
    "pass"
  );
  assert.equal(
    inspect('package main\nimport (\n  // "example.com/comment-only-group"\n  "fmt"\n)\nfunc main() {}\n').decision,
    "pass"
  );

  const commentClose = inspect(
    'package main\nimport (\n  // documentation ) must not close the import block\n  "example.com/missing-after-comment"\n)\nfunc main() {}\n'
  );
  assert.equal(commentClose.decision, "block");
  assert.equal(commentClose.findings[0]?.pattern, "example.com/missing-after-comment");
});

test("Rust dependency scanner ignores use statements inside block comments", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-rust-noncode-use-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.mkdirSync(path.join(directory, "src"), { recursive: true });
  fs.writeFileSync(path.join(directory, "Cargo.toml"), [
    "[package]",
    'name = "app"',
    'version = "0.1.0"',
  ].join("\n"));

  const result = noGhostDepsRule.inspect({
    sessionID: "rust-noncode-use",
    directory,
    messages: [],
    ruleConfig: {},
    currentTurn: [{
      info: { id: "assistant", role: "assistant" },
      parts: [{ type: "tool", state: { input: {
        path: path.join(directory, "src", "main.rs"),
        content: "/*\nuse serde::Serialize;\n*/\nfn main() {}\n",
      } } }],
    }],
  });

  assert.equal(result.decision, "pass");

  const nestedComment = noGhostDepsRule.inspect({
    sessionID: "rust-nested-comment",
    directory,
    messages: [],
    ruleConfig: {},
    currentTurn: [{
      info: { id: "assistant-2", role: "assistant" },
      parts: [{ type: "tool", state: { input: {
        path: path.join(directory, "src", "nested.rs"),
        content: "/* outer\n  /* inner */\n  use tokio::runtime;\n*/\nfn main() {}\n",
      } } }],
    }],
  });
  assert.equal(nestedComment.decision, "pass");

  const rawString = noGhostDepsRule.inspect({
    sessionID: "rust-raw-string",
    directory,
    messages: [],
    ruleConfig: {},
    currentTurn: [{
      info: { id: "assistant-3", role: "assistant" },
      parts: [{ type: "tool", state: { input: {
        path: path.join(directory, "src", "raw.rs"),
        content: 'const DOC: &str = r#"quoted " text\nuse serde::Serialize;\n"#;\nfn main() {}\n',
      } } }],
    }],
  });
  assert.equal(rawString.decision, "pass");
});


test("Node package-import aliases are not treated as external ghost dependencies", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-node-package-import-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, "package.json"), JSON.stringify({
    name: "example-app",
    type: "module",
    imports: { "#internal": "./src/internal.js" },
  }));

  const result = noGhostDepsRule.inspect({
    sessionID: "node-package-import",
    directory,
    messages: [],
    ruleConfig: {},
    currentTurn: [{
      info: { id: "assistant-node", role: "assistant" },
      parts: [{ type: "tool", state: { input: {
        path: path.join(directory, "src", "main.js"),
        content: 'import "#internal";\n',
      } } }],
    }],
  });

  assert.equal(result.decision, "pass");
});


test("Node package self-references are not treated as external ghost dependencies", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-node-self-reference-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, "package.json"), JSON.stringify({
    name: "@example/app",
    type: "module",
    exports: { "./feature": "./src/feature.js" },
  }));

  const result = noGhostDepsRule.inspect({
    sessionID: "node-self-reference",
    directory,
    messages: [],
    ruleConfig: {},
    currentTurn: [{
      info: { id: "assistant-self", role: "assistant" },
      parts: [{ type: "tool", state: { input: {
        path: path.join(directory, "src", "main.js"),
        content: 'import "@example/app/feature";\n',
      } } }],
    }],
  });

  assert.equal(result.decision, "pass");
});


test("Rust proc_macro standard crate is not treated as a ghost dependency", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-rust-proc-macro-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.mkdirSync(path.join(directory, "src"), { recursive: true });
  fs.writeFileSync(path.join(directory, "Cargo.toml"), [
    "[package]",
    'name = "derive-example"',
    'version = "0.1.0"',
    "",
    "[lib]",
    "proc-macro = true",
  ].join("\n"));

  const result = noGhostDepsRule.inspect({
    sessionID: "rust-proc-macro",
    directory,
    messages: [],
    ruleConfig: {},
    currentTurn: [{
      info: { id: "assistant-proc", role: "assistant" },
      parts: [{ type: "tool", state: { input: {
        path: path.join(directory, "src", "lib.rs"),
        content: "use proc_macro::TokenStream;\n",
      } } }],
    }],
  });

  assert.equal(result.decision, "pass");
});


test("Rust package self-references are not treated as external ghost dependencies", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-rust-self-reference-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.mkdirSync(path.join(directory, "src"), { recursive: true });
  fs.writeFileSync(path.join(directory, "Cargo.toml"), [
    "[package]",
    'name = "example-app"',
    'version = "0.1.0"',
  ].join("\n"));

  const result = noGhostDepsRule.inspect({
    sessionID: "rust-self-reference",
    directory,
    messages: [],
    ruleConfig: {},
    currentTurn: [{
      info: { id: "assistant-rust-self", role: "assistant" },
      parts: [{ type: "tool", state: { input: {
        path: path.join(directory, "src", "main.rs"),
        content: "use example_app::feature;\n",
      } } }],
    }],
  });

  assert.equal(result.decision, "pass");
});
