import test from "node:test";
import assert from "node:assert/strict";
import { noStubsRule } from "../dist/rules/no-stubs.js";
import { noSilentFailureRule } from "../dist/rules/no-silent-failure.js";
import { noCheatRule } from "../dist/rules/no-cheat.js";
import { noApologyRule } from "../dist/rules/no-apology.js";
import { noShortcutsRule } from "../dist/rules/no-shortcuts.js";

function context(input, ruleConfig = {}, text = "") {
  const currentTurn = [{ info: { id: "context-agent", role: "assistant" }, parts: [
    ...(input ? [{ type: "tool", tool: "edit", state: { status: "completed", input } }] : []),
    ...(text ? [{ type: "text", text }] : []),
  ] }];
  return { sessionID: "discipline-context", directory: process.cwd(), messages: currentTurn,
    currentTurn, ruleConfig };
}

test("quoted stub examples do not become production implementations", () => {
  const result = noStubsRule.inspect(context({ path: "src/docs.ts", content:
    'const examples = ["throw new Error(\'not implemented\')", "def run(): pass", `// TODO: implement logic`];' }));
  assert.equal(result.findings.length, 0);
});

test("actual placeholder throws remain blocking beside quoted examples", () => {
  const result = noStubsRule.inspect(context({ path: "src/service.ts", content:
    'const example = "throw new Error(\'not implemented\')";\nfunction run() { throw new Error("not implemented"); }' }));
  assert.equal(result.decision, "block");
});

for (const code of ["export function calculateTotal(items) {}", "export const calculateTotal = (items) => {};",
  "class Invoice { calculateTotal() {} }"]) {
  test(`actual empty implementation is detected: ${code}`, () => {
    assert.equal(noStubsRule.inspect(context({ path: "src/invoice.ts", content: code })).decision, "block");
  });
}

test("narrow no-op handlers, constructors, declarations and fixture data are legitimate", () => {
  for (const [path, content] of [
    ["src/events.ts", 'emitter.on("close", () => {});\nclass Empty { constructor() {} }'],
    ["src/types.d.ts", "declare function calculateTotal(items: Item[]): number;"],
    ["tests/fixtures/empty.ts", "export function calculateTotal(items) {}"],
    ["src/noop.ts", "export function noop() {}"],
    ["src/regex.ts", "const example = /function calculateTotal() {}/;"],
  ]) assert.equal(noStubsRule.inspect(context({ path, content })).findings.length, 0, path);
});

test("code comments cannot authorize an unfinished named implementation", () => {
  assert.equal(noStubsRule.inspect(context({ path: "src/auth.ts", content:
    "// intentional noop, approved by user\nexport function authenticate() {}" })).decision, "block");
});

test("quoted and commented error examples are not empty catch handlers", () => {
  const result = noSilentFailureRule.inspect(context({ path: "src/docs.ts", content:
    'const example = "try { run() } catch (error) {}";\n// catch (error) {}' }, { blockEmptyHandlers: true }));
  assert.equal(result.findings.length, 0);
});

test("constant swallowed-error fallbacks are advisory even with strict empty handlers", () => {
  for (const content of ['try { run() } catch (error) { return null; }',
    'run().catch(() => undefined);', 'run().catch(error => { return []; });']) {
    const result = noSilentFailureRule.inspect(context({ path: "src/run.ts", content }, { blockEmptyHandlers: true }));
    assert.equal(result.decision, "pass", content);
    assert.ok(result.findings.some((finding) => finding.confidence === "medium"), content);
  }
});

test("reported, rethrown and computed fallbacks are not blanket banned", () => {
  for (const content of ['try { run() } catch (error) { throw error; }',
    'try { run() } catch (error) { logger.warn(error); return null; }',
    'run().catch(error => recover(error));']) {
    assert.equal(noSilentFailureRule.inspect(context({ path: "src/run.ts", content })).findings.length, 0);
  }
});

for (const command of ['local result=$(npm test)', 'export result="$(pytest)"',
  'echo "$(npm run typecheck)"', 'printf "%s" "`npm test`"']) {
  test(`hidden verification return is detected: ${command}`, () => {
    assert.equal(noSilentFailureRule.inspect(context({ command })).decision, "block");
  });
}

test("shell literals and explicit status handling preserve their meaning", () => {
  for (const command of ["printf '%s' 'npm test || true'", "echo '$(npm test)'", 'echo "npm test || true"',
    'local result; result=$(npm test) || exit $?', 'if result=$(npm test); then echo "$result"; else exit 1; fi',
    'result=$(npm test)', 'echo "$(npm test --help)"']) {
    assert.equal(noSilentFailureRule.inspect(context({ command })).decision, "pass", command);
  }
});

test("substitutions retain inner masking evidence even in plain assignments", () => {
  for (const command of ['result=$(npm test || true)', 'result=$(echo "$(npm test)")']) {
    assert.equal(noSilentFailureRule.inspect(context({ command })).decision, "block", command);
  }
});

test("an exploratory stage does not excuse a later masked verification", () => {
  assert.equal(noSilentFailureRule.inspect(context({ command: "npm test --help; npm test || true" })).decision, "block");
});

test("quoted test bypass examples are inert, real targeted skips are blocking", () => {
  const inert = noCheatRule.inspect(context({ path: "tests/parser.test.ts", new_string:
    'const examples = ["test.skip(\'demo\', () => {})", "// expect(x).toBe(y)"];' }));
  assert.equal(inert.findings.length, 0);
  assert.equal(noCheatRule.inspect(context({ path: "tests/parser.test.ts", new_string:
    'test.skip("demo", () => { expect(x).toBe(y); });' })).decision, "block");
});

test("conditional assertions are advisory despite structural strictness", () => {
  const result = noCheatRule.inspect(context({ path: "tests/parser.test.ts", new_string:
    'test("parse", () => { if (enabled) { expect(parse()).toEqual(value); } });'
  }, { blockStructuralTestChanges: true }));
  assert.equal(result.decision, "pass");
  assert.ok(result.findings.some((finding) => finding.confidence === "medium"));
  assert.equal(noCheatRule.inspect(context({ path: "tests/parser.test.ts", new_string:
    'test("parse", () => { expect(parse()).toEqual(value); });' })).findings.length, 0);
});

test("configured apology exceptions apply only to their matching span", () => {
  const ruleConfig = { exceptions: ["Sorry, I misread the version"] };
  assert.equal(noApologyRule.inspect(context(undefined, ruleConfig,
    "Sorry, I misread the version; I corrected it to 22.")).decision, "pass");
  assert.equal(noApologyRule.inspect(context(undefined, ruleConfig,
    "Correction: Sorry, I misread the version; I corrected it to 22.")).decision, "pass");
  assert.equal(noApologyRule.inspect(context(undefined, ruleConfig,
    "Sorry, I misread the version. I am deeply sorry for everything.")).decision, "block");
  assert.equal(noApologyRule.inspect(context(undefined, {}, "I am deeply sorry for everything.")).decision, "block");
});

test("useful uncertainty, factual correction and configured shortcut exceptions are preserved", () => {
  for (const text of ["The failure may be a race; the next run will distinguish it from a timeout.",
    "I misread the version. The lockfile specifies Node 22, and I corrected the command."]) {
    assert.equal(noApologyRule.inspect(context(undefined, {}, text)).findings.length, 0);
    assert.equal(noShortcutsRule.inspect(context(undefined, {}, text)).findings.length, 0);
  }
  assert.equal(noShortcutsRule.inspect(context(undefined, { exceptions: ["for now refers to the current time"] },
    "The phrase for now refers to the current time.")).decision, "pass");
  assert.equal(noShortcutsRule.inspect(context(undefined, { exceptions: ["for now refers to the current time"] },
    "The phrase for now refers to the current time. This is good enough for now.")).decision, "block");
});
