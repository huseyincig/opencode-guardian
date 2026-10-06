import test from "node:test";
import assert from "node:assert/strict";
import { destructiveOperationsRule } from "../dist/rules/destructive-operations.js";
import { evaluatePreflight } from "../dist/preflight.js";

function inspect(request, command) {
  const currentTurn = [
    { info: { id: "human", role: "user" }, parts: [{ type: "text", text: request }] },
    { info: { id: "assistant", role: "assistant" }, parts: [{
      type: "tool", tool: "bash", state: {
        status: "completed", input: { command }, metadata: { exit: 0 },
      },
    }] },
  ];
  return destructiveOperationsRule.inspect({
    sessionID: "owasp-scope", directory: process.cwd(), messages: currentTurn,
    currentTurn, ruleConfig: {},
  });
}

test("ASI02/ASI03: permission to remove one path does not authorize a different path", () => {
  for (const [request, command] of [
    ["Delete only src/cache-old.", "rm -rf src/cache"],
    ["Delete src/cache.", "rm -rf src/cache-other"],
    ["Delete src/cache.", "sudo rm -rf src/cache"],
    ["Remove only src/cache.", "rm --recursive --force src/secrets"],
    ["src/cache klasörünü sil.", "rm -rf src/other"],
    ["Delete src/cache.", "rm -rf src/cache src/private"],
    ["Delete src/cache.", "rm -rf src/cache && echo success"],
    ["Delete the entire project.", "rm -rf . /tmp/unrelated"],
    ["Delete the entire project.", "sudo rm -rf ."],
    ["Delete the entire project.", "rm -rf . && echo other-command"],
  ]) {
    assert.equal(inspect(request, command).decision, "block", request + " / " + command);
  }
});

test("ASI02/ASI03: exact scoped authorization preserves normal workflows", () => {
  for (const [request, command] of [
    ["Delete src/cache.", "rm -rf src/cache"],
    ["Remove src/cache.", "rm --recursive --force src/cache"],
    ["src/cache klasörünü sil.", "rm -rf src/cache"],
    ["Please run rm -rf src/cache", "rm -rf src/cache"],
    ["Please run sudo rm -rf src/cache", "sudo rm -rf src/cache"],
    ["rm -rf src/cache", "rm -rf src/cache"],
    ["Delete the entire project.", "rm -rf ."],
    ["Delete the entire project using sudo.", "sudo rm -rf ."],
  ]) {
    assert.equal(inspect(request, command).decision, "pass", request + " / " + command);
  }
});

test("ASI01/ASI02: discussion and prohibitions cannot authorize destructive shell commands", () => {
  for (const request of [
    "What does rm -rf src/cache do?",
    "Do not run rm -rf src/cache.",
    "Use git status instead of rm -rf src/cache.",
    "The report includes rm -rf src/cache as an example.",
  ]) {
    assert.equal(inspect(request, "rm -rf src/cache").decision, "block", request);
  }
});

test("opt-in preflight remains strict regardless of post-turn path consent", () => {
  assert.equal(evaluatePreflight("bash", { command: "rm -rf src/cache" }),
    "destructive-command");
  assert.equal(evaluatePreflight("bash", { command: "npm test" }), undefined);
});

test("ASI03: mentioning sudo in a prohibition never grants elevated deletion", () => {
  for (const request of [
    "Delete src/cache without sudo.",
    "Delete src/cache; do not use sudo.",
    "src/cache klasörünü sil; sudo kullanma.",
  ]) {
    assert.equal(inspect(request, "sudo rm -rf src/cache").decision, "block", request);
  }
  assert.equal(inspect("Delete src/cache using sudo.", "sudo rm -rf src/cache").decision, "pass");
});


test("ASI02/ASI03: destructive authorization is scoped to the requested target", () => {
  for (const [request, command] of [
    ["Hard reset the current repo.", "git -C /tmp/other reset --hard HEAD"],
    ["Force push the current repo.", "git -C /tmp/other push --force origin main"],
    ["Delete namespace test.", "kubectl delete namespace prod"],
    ["Unpublish alpha-pkg.", "npm unpublish beta-pkg --force"],
    ["Delete repo owner/alpha.", "gh repo delete owner/beta --yes"],
    ["Drop table users.", "psql -c 'DROP TABLE payments'"],
  ]) {
    assert.equal(inspect(request, command).decision, "block", request + " / " + command);
  }

  for (const [request, command] of [
    ["Hard reset the current repo.", "git reset --hard HEAD"],
    ["Force push the current repo.", "git push --force origin main"],
    ["Delete namespace test.", "kubectl delete namespace test"],
    ["Unpublish alpha-pkg.", "npm unpublish alpha-pkg --force"],
    ["Delete repo owner/alpha.", "gh repo delete owner/alpha --yes"],
    ["Drop table users.", "psql -c 'DROP TABLE users'"],
  ]) {
    assert.equal(inspect(request, command).decision, "pass", request + " / " + command);
  }
});


test("ASI02/ASI03: scoped destructive requests cannot expand to extra targets", () => {
  for (const [request, command] of [
    ["Delete namespace test.", "kubectl delete namespace test prod"],
    ["Run terraform destroy -target=module.test.", "terraform destroy"],
    ["Run terraform destroy -target=module.test.", "terraform destroy -target=module.prod"],
    ["Drop table users.", "psql -c 'DROP TABLE users; DROP TABLE payments'"],
  ]) {
    assert.equal(inspect(request, command).decision, "block", request + " / " + command);
  }

  for (const [request, command] of [
    ["Delete namespaces test and prod.", "kubectl delete namespace test prod"],
    ["Run terraform destroy -target=module.test.", "terraform destroy -target=module.test"],
    ["Destroy the infrastructure.", "terraform destroy"],
    ["Drop tables users and payments.", "psql -c 'DROP TABLE users; DROP TABLE payments'"],
  ]) {
    assert.equal(inspect(request, command).decision, "pass", request + " / " + command);
  }
});
