import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { cacheAgentCapability, cacheV2SessionPermissions, clearAllAgentCapabilities, getCachedAgentCapability, getCachedV2SessionPermissions } from "../dist/agent-capability.js";
import { GUARDIAN_COMMANDS, guardianCommandReport } from "../dist/commands.js";
import { BUILTIN_RULES as BUILTIN_RULES_3, GuardEngine } from "../dist/engine.js";
import { VerificationSnapshotStore, collectTurnEvidence as collectTurnEvidence_3, collectTurnEvidence as collectTurnEvidence_4, collectTurnEvidence as collectTurnEvidence_8, extractMutatedFilePaths } from "../dist/evidence.js";
import Guardian, { BUILTIN_RULES, GuardEngine as GuardEngine_5, VerificationSnapshotStore as VerificationSnapshotStore_9, circuitBreakerRule, collectTurnEvidence, destructiveOperationsRule, evaluatePreflight, evaluateTaskPolicy, extractCurrentTurn, guardianEventPath, isDestructiveCommand, isHallucinatedOrMalformedPackageInstall, isLazyCommitMessage, noCheatRule as noCheatRule_2, noCheatRule as noCheatRule_5, noGhostDepsRule as noGhostDepsRule_9, noShortcutsRule as noShortcutsRule_5, noStubsRule as noStubsRule_2, readGuardianStatus, recordGuardianEvent, sanitizeString as sanitizeString_9 } from "../dist/index.js";
import plugin from "../dist/index.js";
import { GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD, GUARDIAN_INTERVENTION_RPC_DEFINITION, GUARDIAN_INTERVENTION_RPC_ID } from "../dist/intervention-rpc.js";
import { sanitizeUserInstruction } from "../dist/locale-intents.js";
import { enforcePreflight, evaluatePreflight as evaluatePreflight_10, evaluatePreflight as evaluatePreflight_8, isHallucinatedOrMalformedPackageInstall as isHallucinatedOrMalformedPackageInstall_10, isLazyCommitMessage as isLazyCommitMessage_10 } from "../dist/preflight.js";
import { noApologyRule } from "../dist/rules/no-apology.js";
import { noCheatRule } from "../dist/rules/no-cheat.js";
import { clearDeclaredDepsCache, isHallucinatedOrSuspiciousPackage, noGhostDepsRule } from "../dist/rules/no-ghost-deps.js";
import { noSecretsRule } from "../dist/rules/no-secrets.js";
import { noShortcutsRule } from "../dist/rules/no-shortcuts.js";
import { noSilentFailureRule } from "../dist/rules/no-silent-failure.js";
import { noStubsRule } from "../dist/rules/no-stubs.js";
import { taskCompletionRule } from "../dist/rules/task-completion.js";
import { resolveSanitizerOptions, sanitizeMessages, sanitizeString as sanitizeString_11 } from "../dist/secrets/index.js";
import { sanitizeObject, sanitizeString, sanitizeToolResult } from "../dist/secrets/sanitizer.js";
import { extractTaskContract, hasPostMutationReview, isSourceReviewEvidence, latestMutationSequence } from "../dist/task-contract.js";
import { DEFAULT_GUARDIAN_LOG_BYTES, clearGuardianTelemetryConfig, guardianEventPath as guardianEventPath_8, readGuardianActivity, readGuardianStatus as readGuardianStatus_8, resolveTelemetrySettings } from "../dist/telemetry.js";
import { dispatchGuardianToast } from "../dist/toast.js";
import { extractToolCommand } from "../dist/tool-input.js";
import tuiPlugin from "../dist/tui.js";
import cleanupMergedBranches from "../scripts/cleanup-merged-branches.cjs";

describe("Balanced 14-Rule Discipline Baseline", () => {
  const prose = text => ({ type: 'text', text });
  const command = (text, exit = 0) => ({ type: 'tool', tool: 'bash', state: {
    status: 'completed', input: { command: text }, metadata: { exit }, output: exit ? 'assertion failed' : 'observed success',
  } });
  const edit = (filePath, new_string, old_string = '') => ({ type: 'tool', tool: 'edit',
    state: { status: 'completed', input: { filePath, old_string, new_string } } });

  // Named positive/legitimate-negative pairs, deliberately independent of the
  // implementation's regex lists. This is a small synthetic corpus, not an
  // estimate of real-world precision/recall or universal language coverage.
  const corpus = [
    ['discipline/no-evasion', [prose('This is a pre-existing issue.')], [prose('The failing assertion is in the changed function.')]],
    ['discipline/no-apology', [prose('I am sorry for the confusion.')], [prose('I used the wrong version; the corrected version is 2.0.')]],
    ['quality/no-shortcuts', [edit('src/a.ts', '// TODO: implement validation')], [edit('src/a.ts', 'const temporaryDirectory = createTempDir();')]],
    ['integrity/no-stubs', [edit('src/a.ts', 'export function calculateTotal(items) {}')], [edit('src/a.ts', 'export function calculateTotal(items) { return items.reduce(sum, 0); }')]],
    ['integrity/no-unverified-claims', [command('npm test', 1), prose('All tests passed.')], [command('npm test'), prose('All tests passed.')]],
    ['integrity/no-silent-failure', [command('npm test || true')], [command('npm test')]],
    ['safety/no-truncation', [edit('src/a.ts', '// ... existing code unchanged ...')], [edit('src/a.ts', 'const example = "// ... existing code unchanged ...";')]],
    ['safety/destructive-operations', [command('rm -rf src/cache')], [command('git status --short')]],
    ['testing/no-cheat', [edit('tests/a.test.js', 'test.skip("validation", () => assert.equal(actual, expected));', 'test("validation", () => assert.equal(actual, expected));')], [edit('tests/a.test.js', 'test("validation", () => assert.equal(actual, expected));')]],
    ['security/no-secrets', [edit('src/a.ts', 'const token = "ghp_' + 'A'.repeat(36) + '";')], [edit('src/a.ts', 'const token = process.env.GITHUB_TOKEN;')]],
    ['manifest/no-ghost-deps', [edit('src/a.ts', 'import missing from "undeclared-package";')], [edit('src/a.ts', 'import fs from "node:fs";')]],
    ['runtime/circuit-breaker', [command('npm test', 1), command('npm test', 1), command('npm test', 1)], [command('npm test', 1), command('npm test'), command('npm test', 1)]],
    ['task/instruction-fidelity', [edit('src/a.ts', 'export const a = 1;')], [command('git diff -- src/a.ts')], 'Research only. Do not edit files.'],
    ['task/completion-gate', [command('npm test', 1), prose('Task completed.')], [command('npm test'), prose('Task completed.')], 'Run tests before finishing.'],
  ];

  test('all fourteen disciplines have an explicit violation and legitimate-negative scenario', async t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-coverage-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    fs.mkdirSync(path.join(dir, 'src'));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'coverage-fixture', dependencies: {} }));
    assert.deepEqual(corpus.map(c => c[0]).sort(), Object.keys(BUILTIN_RULES).sort());
    for (const [id, violation, legitimate, request = 'Investigate and fix the requested issue.'] of corpus) {
      for (const [label, parts, expected] of [['violation', violation, 'block'], ['legitimate', legitimate, 'pass']]) {
        await t.test(`${id}: ${label}`, async () => {
          const messages = [{ info: { id: 'u', role: 'user' }, parts: [prose(request)] },
            { info: { id: 'a', role: 'assistant' }, parts }];
          const result = await BUILTIN_RULES[id].inspect({ sessionID: id, directory: dir,
            messages, currentTurn: messages, ruleConfig: {}, evidence: collectTurnEvidence(messages, dir) });
          assert.equal(result.decision, expected, JSON.stringify(result.findings));
          if (expected === 'block') assert.ok(result.findings.some(f => f.ruleId === id));
          else assert.equal(result.findings.length, 0, 'legitimate pair must not emit a hidden warning');
        });
      }
    }
  });
});

describe("Discipline Context & Prose Boundaries", () => {
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
});

describe("Review & Git Authorization Hardening", () => {
  function ctx(input, filePath = 'src/a.ts', user = 'Implement the requested fix.') {
    const part = typeof input === 'string' ? { type: 'tool', tool: 'edit', state: { status: 'completed', input: { filePath, new_string: input } } } : input;
    const currentTurn = [{ info: { id: 'u', role: 'user' }, parts: [{ type: 'text', text: user }] }, { info: { id: 'a', role: 'assistant' }, parts: [part] }];
    return { sessionID: 'review', directory: process.cwd(), messages: currentTurn, currentTurn, ruleConfig: {}, evidence: collectTurnEvidence(currentTurn) };
  }
  function shell(command, exit = 0, output = '') { return { type: 'tool', tool: 'bash', state: { status: 'completed', input: { command }, metadata: { exit }, output } }; }

  test('JavaScript private fields do not hide later executable stubs', () => {
    assert.equal(noStubsRule_2.inspect(ctx('class A { #x = 1; run() { throw new Error("not implemented"); } }')).decision, 'block');
    assert.equal(noStubsRule_2.inspect(ctx('# raise NotImplementedError()', 'src/a.py')).decision, 'pass');
  });

  test('a TypeScript object return type is not an empty function body', () => {
    assert.equal(noStubsRule_2.inspect(ctx('export function make(): {} { return { ok: true }; }')).decision, 'pass');
  });

  test('template interpolation is executable while literal template examples stay inert', () => {
    assert.equal(noCheatRule_2.inspect(ctx('const result = `${test.skip("broken", () => {})}`;', 'tests/a.test.ts')).decision, 'block');
    assert.equal(noStubsRule_2.inspect(ctx('const result = `${(() => { throw new Error("not implemented"); })()}`;')).decision, 'block');
    assert.equal(noCheatRule_2.inspect(ctx('const example = `test.skip("broken", () => {})`;', 'tests/a.test.ts')).decision, 'pass');
  });

  test('pytest collection failures still trip repeated-error protection', () => {
    const current = ctx(shell('pytest tests', 2, 'ERROR collecting tests/test_app.py\nModuleNotFoundError: missing'));
    current.currentTurn[1].parts = [current.currentTurn[1].parts[0], current.currentTurn[1].parts[0], current.currentTurn[1].parts[0]];
    current.evidence = collectTurnEvidence(current.currentTurn);
    assert.equal(circuitBreakerRule.inspect(current).decision, 'block');
  });

  test('hook-bypass authorization stays scoped to repository and remote', () => {
    for (const [request, command] of [
      ['Run git -C safe commit --no-verify -m fix', 'git -C other commit --no-verify -m fix'],
      ['Push with --no-verify to origin feature.', 'git push --no-verify upstream main'],
      ['Run git -C safe push --no-verify origin feature', 'git -C safe push --no-verify upstream main'],
    ]) assert.equal(destructiveOperationsRule.inspect(ctx(shell(command), undefined, request)).decision, 'block', command);
    assert.equal(destructiveOperationsRule.inspect(ctx(shell('git -C safe commit --no-verify -m fix'), undefined, 'Run git -C safe commit --no-verify -m fix')).decision, 'pass');
  });

  test('force-push authorization does not permit an additional refspec', () => {
    assert.equal(destructiveOperationsRule.inspect(ctx(shell('git push --force origin feature evil'), undefined,
      'Force push origin feature.')).decision, 'block');
  });

  test('short and env-wrapped Git hook bypasses need authorization', () => {
    for (const command of ['git commit -n -m fix', 'env CI=1 git commit --no-verify -m fix', 'CI=1 git commit --no-verify -m fix']) {
      assert.equal(destructiveOperationsRule.inspect(ctx(shell(command))).decision, 'block', command);
    }
    assert.equal(destructiveOperationsRule.inspect(ctx(shell('echo "git commit -n"'))).decision, 'pass');
  });
});

describe("Report Audit Regressions", () => {
  function context(parts, response = "") {
    const currentTurn = [
      { info: { id: "audit-human", role: "user" }, parts: [{ type: "text", text: "Check this." }] },
      { info: { id: "audit-agent", role: "assistant" }, parts: [
        ...parts,
        ...(response ? [{ type: "text", text: response }] : []),
      ] },
    ];
    return {
      sessionID: "report-regression", directory: process.cwd(), messages: currentTurn,
      currentTurn, ruleConfig: {}, evidence: collectTurnEvidence_3(currentTurn),
    };
  }

  function tool(input, toolName = "write", output = "") {
    return { type: "tool", tool: toolName, state: {
      status: "completed", input, output, metadata: { exit: 0 },
    } };
  }

  test("Python distributions only authorize exact imports or known aliases, not matching prefixes", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-dep-boundary-"));
    try {
      fs.writeFileSync(path.join(root, "pyproject.toml"),
        '[project]\ndependencies = ["requests-oauthlib", "python-dateutil"]\n');
      clearDeclaredDepsCache();
      const ctx = context([tool({
        path: path.join(root, "app.py"), content: "import requests\nimport python\nimport dateutil\n",
      })]);
      ctx.directory = root;
      const result = noGhostDepsRule.inspect({
        ...ctx, ruleConfig: { blockPythonGhostDeps: true },
      });
      assert.equal(result.decision, "block");
      assert.deepEqual(result.findings.map((f) => f.pattern).sort(), ["python", "requests"]);
    } finally {
      clearDeclaredDepsCache();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test("VCS requirement URLs cannot create a fake 'git' distribution", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-vcs-boundary-"));
    try {
      fs.writeFileSync(path.join(root, "requirements.txt"),
        "git+https://example.invalid/org/package.git@v1#egg=package\n");
      clearDeclaredDepsCache();
      const ctx = context([tool({ path: path.join(root, "app.py"), content: "import git\n" })]);
      ctx.directory = root;
      const result = noGhostDepsRule.inspect({
        ...ctx, ruleConfig: { blockPythonGhostDeps: true },
      });
      assert.equal(result.decision, "block");
      assert.equal(result.findings[0].pattern, "git");
    } finally {
      clearDeclaredDepsCache();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test("JavaScript named and default dollar imports retain dependency boundaries", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-js-dollar-"));
    try {
      fs.writeFileSync(path.join(root, "package.json"),
        JSON.stringify({ dependencies: { jquery: "1.0.0" } }));
      clearDeclaredDepsCache();
      const ctx = context([tool({
        path: path.join(root, "app.js"),
        content: [
          'import $ from "jquery";',
          'import { $ } from "missing-named";',
          'import $other from "missing-default";',
          'export { $ } from "missing-export";',
        ].join("\n"),
      })]);
      ctx.directory = root;
      const result = noGhostDepsRule.inspect(ctx);
      assert.equal(result.decision, "block");
      assert.deepEqual(result.findings.map((f) => f.pattern).sort(),
        ["missing-default", "missing-export", "missing-named"]);
    } finally {
      clearDeclaredDepsCache();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test("Python typed, tuple, aliased exceptions swallowing errors are detected", () => {
    for (const snippet of [
      "try:\n    work()\nexcept (OSError, ValueError) as e:\n    pass\n",
      "try:\n    work()\nexcept ValueError:\n    pass\n",
      "try:\n    work()\nexcept thirdparty.SomeError as e:\n    # this is a comment\n    pass\n",
    ]) {
      const result = noSilentFailureRule.inspect(context([tool({
        path: "src/work.py", content: snippet,
      })]));
      assert.equal(result.findings.length, 1, snippet);
      assert.equal(result.findings[0].pattern, "Python except: pass");
    }
    const legitimate = noSilentFailureRule.inspect(context([tool({
      path: "src/work.py", content: "try:\n    work()\nexcept ValueError:\n    log_error()\n",
    })]));
    assert.equal(legitimate.findings.length, 0);
  });

  test("reported apology terms are ignored across languages without hiding a later real apology", () => {
    for (const phrase of [
      "The response contained entschuldigung as an error message.",
      "The output text is désolé.",
      "The payload returned özür dilerim.",
      "The message contains disculpas as a quoted token.",
    ]) {
      assert.equal(noApologyRule.inspect(context([], phrase)).findings.length, 0, phrase);
    }
    const actual = noApologyRule.inspect(context([],
      "The response contained entschuldigung as an error message. Entschuldigung, I made a mistake."));
    assert.ok(actual.findings.some((finding) => finding.pattern === "German"));
  });

  test("deletion commands and explicit delete actions invalidate earlier verification", () => {
    const successfulTest = tool({ command: "npm test" }, "bash", "267 passed");
    const cases = [
      tool({ action: "delete", path: "src/a.ts" }, "file"),
      tool({ action: "remove", path: "src/a.ts" }, "file"),
      tool({ command: "rm -f src/a.ts" }, "bash"),
      tool({ command: "unlink src/a.ts" }, "bash"),
      tool({ command: "git clean -fd" }, "bash"),
      tool({ command: "git reset --hard HEAD" }, "bash"),
    ];
    for (const deletion of cases) {
      const evidence = collectTurnEvidence_3(context([successfulTest, deletion]).currentTurn);
      assert.ok(evidence.fileMutations.length >= 1, JSON.stringify(deletion.state.input));
      assert.ok(latestMutationSequence(evidence) > evidence.successfulVerifications[0].sequence);
    }
    for (const harmless of [
      tool({ command: "git clean -nfd" }, "bash"),
      tool({ command: "rm --help" }, "bash"),
    ]) {
      assert.equal(collectTurnEvidence_3(context([harmless]).currentTurn).fileMutations.length, 0);
    }
  });

  test("a failed delete does not masquerade as a successful file change", () => {
    const deletion = tool({ action: "delete", path: "src/a.ts" }, "file");
    deletion.state.status = "error";
    deletion.state.metadata.exit = 1;
    const evidence = collectTurnEvidence_3(context([deletion]).currentTurn);
    assert.equal(evidence.fileMutations.length, 1);
    assert.equal(latestMutationSequence(evidence), -1);
  });

  test("PEP 420 namespace packages under project root and src are local without __init__.py", () => {
    for (const prefix of ["", "src"]) {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-pep420-"));
      try {
        fs.writeFileSync(path.join(root, "pyproject.toml"),
          '[project]\ndependencies = []\n');
        const moduleDirectory = path.join(root, prefix, "mypkg");
        fs.mkdirSync(moduleDirectory, { recursive: true });
        fs.writeFileSync(path.join(moduleDirectory, "foo.py"), "answer = 42\n");
        assert.equal(fs.existsSync(path.join(moduleDirectory, "__init__.py")), false);
        clearDeclaredDepsCache();

        const present = context([tool({
          path: path.join(root, prefix, "app.py"),
          content: "import mypkg\nfrom mypkg.foo import answer\n",
        })]);
        present.directory = root;
        const found = noGhostDepsRule.inspect({
          ...present, ruleConfig: { blockPythonGhostDeps: true },
        });
        assert.equal(found.decision, "pass", prefix);
        assert.equal(found.findings.length, 0, prefix);

        const missing = context([tool({
          path: path.join(root, prefix, "app.py"),
          content: "import missing_external\n",
        })]);
        missing.directory = root;
        const absent = noGhostDepsRule.inspect({
          ...missing, ruleConfig: { blockPythonGhostDeps: true },
        });
        assert.equal(absent.decision, "block");
        assert.equal(absent.findings[0].pattern, "missing-external");
      } finally {
        clearDeclaredDepsCache();
        fs.rmSync(root, { recursive: true, force: true });
      }
    }
  });

  test("PEP 508 extras in PEP 621 TOML arrays do not truncate later dependencies", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-pep508-"));
    try {
      fs.writeFileSync(path.join(root, "pyproject.toml"), [
        "[project]",
        "dependencies = [",
        '  "requests>=2",',
        '  "fastapi[all]>=1", # bracket within quoted extra',
        '  "uvicorn[standard]>=0.20",',
        '  "httpx>=0.2",',
        "]",
        "",
      ].join("\n"));
      clearDeclaredDepsCache();
      const valid = context([tool({
        path: path.join(root, "app.py"),
        content: "import requests\nimport fastapi\nimport uvicorn\nimport httpx\n",
      })]);
      valid.directory = root;
      const result = noGhostDepsRule.inspect({
        ...valid, ruleConfig: { blockPythonGhostDeps: true },
      });
      assert.equal(result.decision, "pass");
      assert.equal(result.findings.length, 0);

      const undeclared = context([tool({
        path: path.join(root, "app.py"),
        content: "import httpcore\n",
      })]);
      undeclared.directory = root;
      const missing = noGhostDepsRule.inspect({
        ...undeclared, ruleConfig: { blockPythonGhostDeps: true },
      });
      assert.equal(missing.decision, "block");
      assert.equal(missing.findings[0].pattern, "httpcore");
    } finally {
      clearDeclaredDepsCache();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test("PEP 508 extras and another requirement remain visible on the same TOML line", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-pep508-inline-"));
    try {
      fs.writeFileSync(path.join(root, "pyproject.toml"),
        '[project]\ndependencies = ["fastapi[all]>=1", "httpx>=1"]\n');
      clearDeclaredDepsCache();
      const ctx = context([tool({
        path: path.join(root, "app.py"),
        content: "import fastapi\nimport httpx\n",
      })]);
      ctx.directory = root;
      const result = noGhostDepsRule.inspect({
        ...ctx, ruleConfig: { blockPythonGhostDeps: true },
      });
      assert.equal(result.decision, "pass");
      assert.equal(result.findings.length, 0);
    } finally {
      clearDeclaredDepsCache();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });


  test("VCS requirements use only explicitly declared egg names, never URL schemes", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-vcs-egg-"));
    try {
      fs.writeFileSync(path.join(root, "requirements.txt"), [
        "git+https://example.invalid/org/project.git@v1#egg=realpkg",
        "-e git+ssh://git@example.invalid/project.git#egg=editablepkg&subdirectory=backend",
        "file:///tmp/local-package#egg=localpkg",
        "hg+https://example.invalid/unnamed-project",
        "ssh://example.invalid/somewhere",
        "",
      ].join("\n"));
      clearDeclaredDepsCache();

      const ctx = context([tool({
        path: path.join(root, "app.py"),
        content: "import realpkg\nimport editablepkg\nimport localpkg\n",
      })]);
      ctx.directory = root;
      const found = noGhostDepsRule.inspect({
        ...ctx, ruleConfig: { blockPythonGhostDeps: true },
      });
      assert.equal(found.decision, "pass");
      assert.equal(found.findings.length, 0);

      const falseSchemes = context([tool({
        path: path.join(root, "app.py"),
        content: "import git\nimport hg\nimport ssh\nimport file\n",
      })]);
      falseSchemes.directory = root;
      const absent = noGhostDepsRule.inspect({
        ...falseSchemes, ruleConfig: { blockPythonGhostDeps: true },
      });
      assert.equal(absent.decision, "block");
      assert.deepEqual(absent.findings.map((f) => f.pattern).sort(),
        ["file", "git", "hg", "ssh"]);
    } finally {
      clearDeclaredDepsCache();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });


  test("existing remediation fingerprints prevent duplicate prompts on concurrent idle", async () => {
    const engine = new GuardEngine({
      enabled: true,
      rules: Object.fromEntries(Object.keys(BUILTIN_RULES_3).map((id) => [id, "off"])),
    });
    let calls = 0;
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    engine.registerRule({
      id: "audit/concurrent-prompt",
      description: "Delay completion to exercise concurrent idle events",
      async inspect() {
        calls++;
        await gate;
        return {
          ruleId: "audit/concurrent-prompt",
          decision: "block",
          findings: [{
            ruleId: "audit/concurrent-prompt", pattern: "same-finding",
            description: "Same finding", messageSnippet: "same",
          }],
          remediationPrompt: "Resolve the finding.",
        };
      },
    });
    const messages = context([], "The task is incomplete.").currentTurn;
    const first = engine.inspect("concurrent-observation", process.cwd(), messages);
    const second = engine.inspect("concurrent-observation", process.cwd(), messages);
    assert.equal(calls, 2, "both rule evaluations can start before async inspection yields");
    release();
    const outcomes = await Promise.all([first, second]);
    assert.equal(outcomes.filter((result) => result.decision === "block").length, 1);
    assert.equal(outcomes.filter((result) => result.decision === "pass").length, 1);
  });

  test("Node dependency cache follows package.json edits in the same five-second window", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-node-manifest-edit-"));
    try {
      const manifest = path.join(root, "package.json");
      fs.writeFileSync(manifest, JSON.stringify({ dependencies: {} }));
      clearDeclaredDepsCache();
      const ctx = context([tool({
        path: path.join(root, "app.js"), content: 'import external from "new-lib";',
      })]);
      ctx.directory = root;
      assert.equal(noGhostDepsRule.inspect(ctx).decision, "block");
      fs.writeFileSync(manifest, JSON.stringify({ dependencies: { "new-lib": "1.0.0" } }));
      const checked = noGhostDepsRule.inspect(ctx);
      assert.equal(checked.decision, "pass");
      assert.equal(checked.findings.length, 0);
    } finally {
      clearDeclaredDepsCache();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test("Python dependency cache follows included requirements edits immediately", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-python-manifest-edit-"));
    try {
      fs.writeFileSync(path.join(root, "requirements.txt"), "-r nested.txt\n");
      const nested = path.join(root, "nested.txt");
      fs.writeFileSync(nested, "# empty\n");
      clearDeclaredDepsCache();
      const ctx = context([tool({
        path: path.join(root, "app.py"), content: "import brand_new\n",
      })]);
      ctx.directory = root;
      ctx.ruleConfig = { blockPythonGhostDeps: true };
      assert.equal(noGhostDepsRule.inspect(ctx).decision, "block");
      fs.writeFileSync(nested, "brand-new>=1\n");
      const checked = noGhostDepsRule.inspect(ctx);
      assert.equal(checked.decision, "pass");
      assert.equal(checked.findings.length, 0);
    } finally {
      clearDeclaredDepsCache();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test("Dalga 1 (G-22A): Python requirements include refuses symlinks escaping project root and oversized files", () => {
    const outer = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-req-outer-"));
    const root = path.join(outer, "project");
    fs.mkdirSync(root, { recursive: true });
    try {
      const outside = path.join(outer, "secret-reqs.txt");
      fs.writeFileSync(outside, "escaped-pkg>=1.0\n");
      fs.symlinkSync(outside, path.join(root, "link-reqs.txt"));
      fs.writeFileSync(path.join(root, "requirements.txt"), "-r link-reqs.txt\n");
      clearDeclaredDepsCache();

      const ctx = context([tool({
        path: path.join(root, "app.py"),
        content: "import escaped_pkg\n",
      })]);
      ctx.directory = root;
      ctx.ruleConfig = { blockPythonGhostDeps: true };
      assert.equal(
        noGhostDepsRule.inspect(ctx).decision,
        "block",
        "symlink escaping workspace root must not be read as declared Python dependency"
      );
    } finally {
      clearDeclaredDepsCache();
      fs.rmSync(outer, { recursive: true, force: true });
    }
  });

  test("R3 Dalga 3 (R3-037, R3-038, R3-040): no-ghost-deps stays inside workspace root, treats oversized requirements as indeterminate, and handles Rust lifetimes/pub use and JS template imports", () => {
    const outer = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-r3-ghost-"));
    const proj = path.join(outer, "workspace");
    fs.mkdirSync(proj, { recursive: true });
    try {
      // R3-037: parent package.json outside workspace root must NOT be loaded
      fs.writeFileSync(path.join(outer, "package.json"), JSON.stringify({ name: "outer", dependencies: { "outer-only-pkg": "1.0.0" } }));
      clearDeclaredDepsCache();
      const ctx37 = context([tool({ path: path.join(proj, "app.ts"), content: 'import x from "some-unlisted";\n' })]);
      ctx37.directory = proj;
      assert.equal(noGhostDepsRule.inspect(ctx37).decision, "pass", "R3-037: nearestFile must not walk above workspace root into parent package.json");

      // R3-038: oversized requirements.txt (>256KiB) must fail open (indeterminate), not falsely report every import as ghost
      const pyProj = path.join(outer, "py-big");
      fs.mkdirSync(pyProj, { recursive: true });
      fs.writeFileSync(path.join(pyProj, "requirements.txt"), "requests>=2.0\n" + "# ".padEnd(300 * 1024, "x") + "\n");
      clearDeclaredDepsCache();
      const ctx38 = context([tool({ path: path.join(pyProj, "app.py"), content: "import requests\n" })]);
      ctx38.directory = pyProj;
      ctx38.ruleConfig = { blockPythonGhostDeps: true };
      assert.equal(noGhostDepsRule.inspect(ctx38).decision, "pass", "R3-038: oversized/truncated Python manifest must not produce false-positive ghost-dep block");

      // R3-040a: Rust lifetime `'static` must not swallow subsequent `use` / `pub use`
      const rsProj = path.join(outer, "rs-proj");
      fs.mkdirSync(rsProj, { recursive: true });
      fs.writeFileSync(path.join(rsProj, "Cargo.toml"), '[package]\nname = "demo"\n[dependencies]\nserde = "1"\n');
      clearDeclaredDepsCache();
      const ctx40rs = context([tool({
        path: path.join(rsProj, "lib.rs"),
        content: "const S: &'static str = \"ok\";\npub use ghost_crate::Thing;\n",
      })]);
      ctx40rs.directory = rsProj;
      assert.equal(noGhostDepsRule.inspect(ctx40rs).decision, "block", "R3-040: Rust 'static lifetime must not mask subsequent pub use ghost_crate");

      // R3-040b: JS template interpolation `${await import(...)}` must be inspected
      const jsProj = path.join(outer, "js-proj");
      fs.mkdirSync(jsProj, { recursive: true });
      fs.writeFileSync(path.join(jsProj, "package.json"), JSON.stringify({ name: "js-proj", dependencies: {} }));
      clearDeclaredDepsCache();
      const ctx40js = context([tool({
        path: path.join(jsProj, "index.mjs"),
        content: 'const msg = `${await import("ghost-template-pkg")}`;\n',
      })]);
      ctx40js.directory = jsProj;
      assert.equal(noGhostDepsRule.inspect(ctx40js).decision, "block", "R3-040: dynamic import inside JS template interpolation must be detected");
    } finally {
      clearDeclaredDepsCache();
      fs.rmSync(outer, { recursive: true, force: true });
    }
  });
});

describe("Report Follow-up Regressions", () => {
  const repeatedReview = "Fix every bug, then restart the full source review until no bugs remain.";

  function human(text = repeatedReview) {
    return { info: { id: "human", role: "user" }, parts: [{ type: "text", text }] };
  }

  function action(tool, output = "export const fixed = true;", status = "completed") {
    return {
      type: "tool", tool, state: {
        status,
        input: { filePath: "src/item.ts" }, output,
        metadata: { exit: status === "completed" ? 0 : 1 },
      },
    };
  }

  function turn(tool, output, status = "completed") {
    return [human(), { info: { id: "agent", role: "assistant" }, parts: [
      { type: "tool", tool: "write", state: {
        status: "completed", input: { filePath: "src/item.ts", content: "export const fixed = true;" },
        metadata: { exit: 0 },
      } },
      action(tool, output, status),
      { type: "text", text: "The review is complete." },
    ] }];
  }

  test("successful read_file and view_file are post-change source-review evidence", () => {
    for (const tool of ["read_file", "view_file", "file.read", "read-file", "file:view"]) {
      const messages = turn(tool, "export const fixed = true;");
      const evidence = collectTurnEvidence_4(messages);
      assert.equal(hasPostMutationReview(evidence, true), true, tool);
      const completion = taskCompletionRule.inspect({
        sessionID: "review-" + tool, directory: process.cwd(),
        messages, currentTurn: messages, evidence, ruleConfig: {},
      });
      assert.equal(completion.decision, "pass", tool);
    }
  });

  test("file_search with only file names is not proof of source reinspection", () => {
    const messages = turn("file_search", "src/item.ts\nsrc/other.ts");
    const evidence = collectTurnEvidence_4(messages);
    assert.equal(hasPostMutationReview(evidence, true), false);
    assert.equal(taskCompletionRule.inspect({
      sessionID: "review-search", directory: process.cwd(),
      messages, currentTurn: messages, evidence, ruleConfig: {},
    }).decision, "block");
  });

  test("failed, empty and pre-change reads do not prove a fresh review", () => {
    for (const [output, status] of [["", "completed"], ["permission denied", "error"]]) {
      const evidence = collectTurnEvidence_4(turn("read_file", output, status));
      assert.equal(hasPostMutationReview(evidence, true), false);
    }
    const messages = [human(), { info: { id: "agent", role: "assistant" }, parts: [
      action("read_file", "const oldVersion = true;"),
      { type: "tool", tool: "write", state: {
        status: "completed", input: { filePath: "src/item.ts", content: "const newVersion = true;" },
        metadata: { exit: 0 },
      } },
    ] }];
    assert.equal(hasPostMutationReview(collectTurnEvidence_4(messages), true), false);
  });

  test("quoted examples longer than 300 characters do not become user instructions", () => {
    const request = "Cada vez que encuentres un error, corrígelo y vuelve a revisar todo desde el principio hasta que no queden errores.";
    for (const [open, close] of [["\"", "\""], ["“", "”"], ["«", "»"], ["「", "」"], ["『", "』"]]) {
      const example = `${open}${"example ".repeat(60)}${request}${close}`;
      assert.equal(sanitizeUserInstruction(example).trim(), "", open);
      assert.equal(extractTaskContract([human("Explain this example: " + example)]).iterativeReview, false, open);
    }
  });

  test("quoted examples do not hide an explicit unquoted instruction that follows", () => {
    const quoted = `“${"example ".repeat(60)}${repeatedReview}”`;
    const task = extractTaskContract([human("Explain: " + quoted + "\n" + repeatedReview)]);
    assert.equal(task.iterativeReview, true);
  });

  test("name-only globs, finds, searches and git diff stats are not source-review evidence", () => {
    for (const [tool, input, output] of [
      ["glob", { pattern: "src/**/*.ts" }, "src/index.ts\nsrc/item.ts"],
      ["find", { pattern: "src/*" }, "src/index.ts\nsrc/item.ts"],
      ["file_search", { query: "feature" }, "src/index.ts\nsrc/item.ts"],
      ["bash", { command: "git diff --stat" }, " src/item.ts | 5 +++--"],
      ["bash", { command: "rg -n not_found src" }, "No matches"],
    ]) {
      const messages = [human(), { info: { id: "agent", role: "assistant" }, parts: [
        { type: "tool", tool: "write", state: {
          status: "completed", input: { filePath: "src/item.ts", content: "export const fixed = true;" },
          metadata: { exit: 0 },
        } },
        { type: "tool", tool, state: { status: "completed", input, output, metadata: { exit: 0 } } },
      ] }];
      assert.equal(hasPostMutationReview(collectTurnEvidence_4(messages), true), false, JSON.stringify(input));
    }
  });

  test("real grep matches and source diffs provide post-change inspection evidence", () => {
    for (const [command, output] of [
      ["rg -n fixed src/item.ts", "src/item.ts:1:export const fixed = true;"],
      ["git diff src/item.ts", "diff --git a/src/item.ts b/src/item.ts\n@@ -1 +1 @@\n-export const fixed = false;\n+export const fixed = true;"],
      ["git show HEAD:src/item.ts", "export const fixed = true;"],
      ["sed -n '1,30p' src/item.ts", "export const fixed = true;"],
    ]) {
      const messages = [human(), { info: { id: "agent", role: "assistant" }, parts: [
        { type: "tool", tool: "write", state: {
          status: "completed", input: { filePath: "src/item.ts", content: "export const fixed = true;" },
          metadata: { exit: 0 },
        } },
        { type: "tool", tool: "bash", state: {
          status: "completed", input: { command }, output, metadata: { exit: 0 },
        } },
      ] }];
      assert.equal(hasPostMutationReview(collectTurnEvidence_4(messages), true), true, command);
    }
  });
});

describe("Focused Audit Regressions", () => {
  test("same-call verification cannot certify a mutation that happens later in that call", () => {
    const evidence = collectTurnEvidence([{
      info: { id: "a1", role: "assistant" },
      parts: [{
        type: "tool",
        tool: "bash",
        state: {
          status: "completed",
          input: { command: "npm test && printf 'changed' > src/feature.ts" },
          metadata: { exit: 0 },
        },
      }],
    }]);

    const decision = evaluateTaskPolicy({
      turnKey: "u1",
      explicitAction: true,
      iterativeReview: false,
      requiresSourceReview: false,
      requiredVerifications: ["test"],
      requiresExplicitCompletion: true,
    }, evidence);

    assert.equal(decision.lastMutationSequence, 0);
    assert.equal(decision.verifications[0]?.status, "unknown");
  });

  test("empty test cheat detection covers classic callbacks and whole-file writes", () => {
    const inspect = (input) => noCheatRule_5.inspect({
      sessionID: "empty-test-regression",
      directory: "/tmp",
      messages: [],
      ruleConfig: {},
      currentTurn: [{
        info: { id: "a1", role: "assistant" },
        parts: [{ type: "tool", state: { input } }],
      }],
    });

    assert.equal(inspect({
      path: "/tmp/example.test.js",
      new_string: "it('does work', function() {});",
    }).decision, "block");

    assert.equal(inspect({
      path: "/tmp/new.test.js",
      content: "test('created empty', () => {});",
    }).decision, "block");
  });

  test("lazy commit discipline handles common short-option message forms", () => {
    for (const command of [
      'git commit -am "fix"',
      "git commit -mfix",
      'git -C /tmp/repo commit -m "fix"',
      'git -c color.ui=false commit -am "wip"',
    ]) {
      assert.equal(isLazyCommitMessage(command), true, command);
      const result = noShortcutsRule_5.inspect({
        sessionID: "commit-regression",
        directory: "/tmp",
        messages: [],
        ruleConfig: {},
        currentTurn: [{
          info: { id: command, role: "assistant" },
          parts: [{ type: "tool", state: { input: { command } } }],
        }],
      });
      assert.equal(result.decision, "block", command);
    }
  });

  test("package hallucination checks inspect real package names without rejecting local specs", () => {
    assert.equal(
      isHallucinatedOrMalformedPackageInstall("npm install express-security-patch@1.2.3"),
      true
    );
    assert.equal(
      isHallucinatedOrMalformedPackageInstall("npm install @BadScope/pkg"),
      true
    );
    assert.equal(
      isHallucinatedOrMalformedPackageInstall("npm install ./LocalPkg"),
      false
    );
    assert.equal(
      isHallucinatedOrMalformedPackageInstall("sudo npm install React"),
      true
    );
  });

  test("remediation disk recheck preserves configured rule behavior", async (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-rule-config-recheck-"));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    fs.mkdirSync(path.join(directory, "src"), { recursive: true });
    const target = path.join(directory, "src", "feature.ts");
    fs.writeFileSync(target, "// shipitlater\nexport const value = 2;\n");

    const engine = new GuardEngine_5({
      remediationBudget: 2,
      rules: {
        "quality/no-shortcuts": {
          severity: "error",
          customPhrases: ["shipitlater"],
        },
      },
    });

    const firstTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the file." }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [{
          type: "tool",
          state: {
            status: "completed",
            input: { path: target, content: "// shipitlater\nexport const value = 1;\n" },
          },
        }],
      },
    ];
    const first = await engine.inspect("s1", directory, firstTurn);
    assert.equal(first.decision, "block");
    assert.ok(first.combinedRemediationPrompt);

    const second = await engine.inspect("s1", directory, [
      ...firstTurn,
      {
        info: { id: "guardian-remediation", role: "user" },
        parts: [{
          type: "text",
          text: first.combinedRemediationPrompt,
          synthetic: true,
        }],
      },
      {
        info: { id: "a2", role: "assistant" },
        parts: [{
          type: "tool",
          state: {
            status: "completed",
            input: { path: target, new_string: "export const value = 2;" },
          },
        }],
      },
    ]);

    assert.notEqual(second.remediationStatus, "verified");
  });

  test("disabled update notices also disable sidebar update checks", () => {
    const source = fs.readFileSync(
      new URL("../src/tui.tsx", import.meta.url),
      "utf8"
    );
    assert.match(source, /checkUpdates\?:\s*boolean/);
    assert.match(source, /checkUpdates=\{sessionConfig\(\)\.updateNotice\?\.enabled\s*!==\s*false\}/);
  });
});

describe("Full Audit Regressions", () => {
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
      assert.equal(evaluatePreflight("mcp__provider_a__shell_exec", { command }), "destructive-command", command);
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
});

describe("Release Fix Regressions", () => {
  const name = "huseyincig/opencode-guardian";
  const sha = (letter) => letter.repeat(40);
  const pr = (ref, tip, options = {}) => ({
    merged_at: options.merged === false ? null : "2026-10-04T00:00:00Z",
    head: { ref, sha: tip, repo: { full_name: options.fork ? "foreign/fork" : name } },
  });

  function mockGitHub({ closed = [], open = [], refs = {}, deleteError } = {}) {
    const lookedUp = [];
    const deleted = [];
    const github = {
      paginate: async (_method, args) => args.state === "open" ? open : closed,
      rest: {
        pulls: { list() {} },
        git: {
          async getRef({ ref }) {
            lookedUp.push(ref);
            if (!(ref in refs)) throw Object.assign(new Error("missing"), { status: 404 });
            if (refs[ref] instanceof Error) throw refs[ref];
            return { data: { object: { sha: refs[ref] } } };
          },
          async deleteRef({ ref }) {
            deleted.push(ref);
            if (deleteError) throw deleteError;
          },
        },
      },
    };
    return { github, lookedUp, deleted, core: { info() {} },
      context: { repo: { owner: "huseyincig", repo: "opencode-guardian" },
        payload: { repository: { default_branch: "main" } } } };
  }

  test("merged branch cleanup deletes only unchanged SHA and never reused, open, default or fork refs", async () => {
    const args = mockGitHub({
      closed: [
        pr("fix/merged", sha("a")),
        pr("fix/reused", sha("b")),
        pr("fix/open", sha("c")),
        pr("main", sha("d")),
        pr("fork/work", sha("e"), { fork: true }),
        pr("fix/not-merged", sha("f"), { merged: false }),
      ],
      open: [pr("fix/open", sha("c"), { merged: false })],
      refs: {
        "heads/fix/merged": sha("a"),
        "heads/fix/reused": sha("f"),
        "heads/fix/open": sha("c"),
      },
    });
    await cleanupMergedBranches(args);
    assert.deepEqual(args.deleted, ["heads/fix/merged"]);
    assert.deepEqual(args.lookedUp, ["heads/fix/merged", "heads/fix/reused"]);
  });

  test("merged branch cleanup does not delete if current ref cannot be verified", async () => {
    const args = mockGitHub({
      closed: [pr("fix/unknown", sha("a"))],
      refs: { "heads/fix/unknown": Object.assign(new Error("forbidden"), { status: 403 }) },
    });
    await assert.rejects(() => cleanupMergedBranches(args), /forbidden/);
    assert.deepEqual(args.deleted, []);
  });

  test("merged branch cleanup handles missing and protected refs without touching other branches", async () => {
    const args = mockGitHub({
      closed: [pr("fix/missing", sha("a")), pr("fix/protected", sha("b"))],
      refs: { "heads/fix/protected": sha("b") },
      deleteError: Object.assign(new Error("protected"), { status: 422 }),
    });
    await cleanupMergedBranches(args);
    assert.deepEqual(args.deleted, ["heads/fix/protected"]);
  });

  test("merged branch cleanup never proceeds if open PR discovery fails", async () => {
    const args = mockGitHub({ closed: [pr("fix/merged", sha("a"))], refs: { "heads/fix/merged": sha("a") } });
    args.github.paginate = async (_method, options) => {
      if (options.state === "open") throw new Error("open pull discovery unavailable");
      return [];
    };
    await assert.rejects(() => cleanupMergedBranches(args), /discovery unavailable/);
    assert.deepEqual(args.deleted, []);
  });

  function tempProject(t) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-delivery-regression-"));
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"),
      JSON.stringify({ enabled: true, updateNotice: { enabled: false } }));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    return directory;
  }

  function failedAssistant() {
    return [
      { id: "u1", type: "user", text: "Fix the broken tests." },
      { id: "a1", type: "assistant", content: [{ type: "text", text: "The test failures are unrelated to my changes." }] },
    ];
  }

  test("V2 rejected synthetic response rolls back remediation and a later idle retries", async (t) => {
    const directory = tempProject(t);
    let syntheticAttempts = 0;
    let emitEvent;
    const cleanup = await Guardian.setup({
      location: { directory },
      options: { secrets: { enabled: false } },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              const next = await new Promise((resolve) => { emitEvent = resolve; });
              if (next === null) break;
              yield next;
            }
          })();
        },
      },
      session: {
        async get() { return { id: "retry", parentID: undefined }; },
        async context() { return failedAssistant(); },
        async synthetic() {
          syntheticAttempts++;
          if (syntheticAttempts === 1) throw new Error("simulated host rejection");
        },
      },
    });
    t.after(async () => { emitEvent?.(null); await cleanup?.(); });
    emitEvent({ type: "session.idle", data: { sessionID: "retry" } });
    for (let i = 0; i < 60 && readGuardianStatus(directory).errors === 0; i++) {
      await new Promise((r) => setTimeout(r, 15));
    }
    assert.equal(syntheticAttempts, 1);
    assert.equal(readGuardianStatus(directory).remediations, 0);
    assert.equal(readGuardianStatus(directory).errors, 1);
    emitEvent({ type: "session.idle", data: { sessionID: "retry" } });
    for (let i = 0; i < 60 && readGuardianStatus(directory).remediations === 0; i++) {
      await new Promise((r) => setTimeout(r, 15));
    }
    assert.equal(syntheticAttempts, 2);
    assert.equal(readGuardianStatus(directory).remediations, 1);
  });

  test("V2 session fetch failures are reported without exposing raw exception in console", async (t) => {
    const directory = tempProject(t);
    const marker = "SYNTHETIC_PRIVATE_ERROR_MARKER";
    let emitEvent;
    const cleanup = await Guardian.setup({
      location: { directory },
      options: { secrets: { enabled: false } },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            while (!signal.aborted) {
              const next = await new Promise((resolve) => { emitEvent = resolve; });
              if (next === null) break;
              yield next;
            }
          })();
        },
      },
      session: {
        async get() { return { id: "failed-fetch", parentID: undefined }; },
        async context() { throw new Error(marker); },
        async synthetic() {},
      },
    });
    t.after(async () => { emitEvent?.(null); await cleanup?.(); });
    const old = console.error;
    const captured = [];
    console.error = (...args) => captured.push(args);
    try {
      emitEvent({ type: "session.idle", data: { sessionID: "failed-fetch" } });
      for (let i = 0; i < 60 && readGuardianStatus(directory).errors === 0; i++) {
        await new Promise((r) => setTimeout(r, 15));
      }
    } finally {
      console.error = old;
    }
    const contents = fs.readFileSync(guardianEventPath(directory), "utf8");
    assert.equal(captured.length, 0);
    assert.equal(contents.includes(marker), false);
    assert.equal(readGuardianStatus(directory).errors, 1);
  });

  test("status reports the newest event instead of mistaking past blocked counters for current state", (t) => {
    const directory = tempProject(t);
    process.env.OPENCODE_GUARDIAN_LOG_LEVEL = "all";
    t.after(() => delete process.env.OPENCODE_GUARDIAN_LOG_LEVEL);
    recordGuardianEvent({ kind: "runtime-started", runtime: "v1", preflight: "active" }, directory);
    recordGuardianEvent({ kind: "preflight-blocked", rules: ["destructive-command"] }, directory);
    recordGuardianEvent({ kind: "post-remediation", rules: ["discipline/no-evasion"] }, directory);
    recordGuardianEvent({ kind: "preflight-allowed", tool: "bash" }, directory);
    const status = readGuardianStatus(directory);
    assert.equal(status.blocked, 1);
    assert.equal(status.remediations, 1);
    assert.equal(status.lastKind, "preflight-allowed");
  });

  test("CI cleanup is restricted to main and runs the independently tested safety policy", () => {
    const workflow = fs.readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
    assert.match(workflow, /github\.event_name == 'push' && github\.ref == 'refs\/heads\/main'/);
    assert.match(workflow, /require\('\.\/scripts\/cleanup-merged-branches\.cjs'\)/);
    assert.match(workflow.split("cleanup-merged-branches:")[1], /uses: actions\/checkout@v5/);
  });
});

describe("Feedback Regressions", () => {
  const part=(input,tool='apply_patch')=>({type:'tool',tool,state:{status:'completed',input,metadata:{exitCode:0},output:'ok'}});
  const msg=(role,parts,id='m')=>({info:{id,role},parts});
  const patch=(file,before,after)=>`--- a/${file}\n+++ b/${file}\n@@ -1 +1 @@\n-${before}\n+${after}\n`;
  const first=patch('src/first.js','let x=1;','let x=2;');
  const context=patchText=>({sessionID:'feedback',directory:process.cwd(),messages:[],currentTurn:[msg('assistant',[part({patchText})])],isSubagent:false,ruleConfig:{blockStructuralTestChanges:true}});
  function tmp(t){const p=fs.mkdtempSync(path.join(os.tmpdir(),'guardian-feedback-'));t.after(()=>fs.rmSync(p,{recursive:true,force:true}));return p;}
  test('F01 user and system tool parts never create verification or mutation evidence',()=>{
   for(const role of ['user','system']){
    const ev=collectTurnEvidence_8([msg(role,[part({command:'npm test'},'bash'),part({patchText:first})])]);
    assert.deepEqual(ev.records,[]);assert.equal(ev.mutatedFiles.size,0);
   }
   assert.equal(collectTurnEvidence_8([msg('assistant',[part({command:'npm test'},'bash')])]).successfulVerifications.length,1);
  });
  test('F02 every updated and deleted patch file contributes mutation evidence',()=>{
   const patchText=first+patch('src/second.js','let y=1;','let y=2;')+'--- a/obsolete.js\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n';
   const p=part({patchText});assert.deepEqual(extractMutatedFilePaths(p),['src/first.js','src/second.js','obsolete.js']);
   assert.deepEqual(collectTurnEvidence_8([msg('assistant',[p])]).fileMutations.map(r=>r.filePath),['src/first.js','src/second.js','obsolete.js']);
  });
  test('F02 live verification snapshots include every patch file',t=>{
   const directory=tmp(t);fs.mkdirSync(path.join(directory,'src'));for(const f of ['first','second'])fs.writeFileSync(path.join(directory,'src',f+'.js'),'content');
   const store=new VerificationSnapshotStore();store.observe('s','p','apply_patch',{patchText:first+patch('src/second.js','a','b')},'ok',{},directory);
   store.observe('s','test','bash',{command:'npm test'},'passed',{exitCode:0},directory);
   assert.deepEqual(store.snapshots('s').get('test').files,['src/first.js','src/second.js']);
  });
  test('F03 Error.name is sanitized in direct and nested results',()=>{
   const secret='feedbackCanaryErrorName7654321';const options={includeRuntimeEnv:false,customSecretValues:[secret]};const e=new Error('benign');e.name=secret;
   assert.equal(sanitizeToolResult(e,options).name,'[REDACTED]');assert.equal(sanitizeObject({error:e},options).sanitized.error.name,'[REDACTED]');
  });
  for(const key of ['api_key','access_token','auth_token'])test(`F04 URL ${key} credential is contextually redacted`,()=>{
   const secret='feedbackUnknownCredential7654321';const input=`https://example.test/path?ok=1&${key}=${secret}#part`;
   const output=sanitizeString(input,{includeRuntimeEnv:false}).sanitized;assert.equal(output.includes(secret),false);assert.match(output,/ok=1/);assert.match(output,/#part$/);
  });
  for(const key of ['Authorization','Proxy-Authorization','Cookie','Set-Cookie'])test(`F05 ${key} header values are redacted`,()=>{
   const secret='feedbackHeaderCredential7654321';assert.equal(sanitizeString(`${key}: Basic ${secret}`,{includeRuntimeEnv:false}).sanitized.includes(secret),false);
   assert.equal(JSON.stringify(sanitizeObject({[key]:secret},{includeRuntimeEnv:false}).sanitized).includes(secret),false);
  });
  test('F06 cache boundaries copy profiles and permission rules',()=>{
   clearAllAgentCapabilities();const profile={capability:'read-only',evidence:{reasons:['original'],mutatingTools:[]}};cacheAgentCapability('s',profile);profile.capability='write-allowed';
   assert.equal(getCachedAgentCapability('s').capability,'read-only');const read=getCachedAgentCapability('s');read.capability='write-allowed';read.evidence.reasons.push('forged');assert.deepEqual(getCachedAgentCapability('s').evidence.reasons,['original']);
   cacheV2SessionPermissions('p',[{action:'edit',effect:'deny'}]);getCachedV2SessionPermissions('p')[0].effect='allow';assert.equal(getCachedV2SessionPermissions('p')[0].effect,'deny');clearAllAgentCapabilities();
  });
  test('F07 mixed real and synthetic user parts retain the latest human turn',()=>{
   const messages=[msg('user',[{type:'text',text:'Earlier instruction.'}],'old'),msg('user',[{type:'text',text:'Run tests now.'},{type:'text',text:'synthetic notice',synthetic:true}],'new')];
   assert.equal(extractCurrentTurn(messages).turnKey,'new');
   messages[1].parts[1].text='[opencode-guardian remediation]\nFollowup';assert.equal(extractCurrentTurn(messages).isRemediationResponse,false);
  });
  for(const [name,second,pattern] of [
   ['assertion',patch('tests/example.test.js','assert.strictEqual(result, 42);','assert.ok(result);'),'assertion weakened'],
   ['CI',patch('.github/workflows/ci.yml','      - run: npm test','      - run: echo done'),'CI test step removed'],
   ['deletion','--- a/tests/example.test.js\n+++ /dev/null\n@@ -1 +0,0 @@\n-assert.strictEqual(result, 42);\n','test file deleted'],
  ])test(`F11/F12 later patch ${name} is detected with its own path`,async()=>{
   const result=await noCheatRule.inspect(context(first+second));const finding=result.findings.find(f=>f.pattern===pattern);assert.ok(finding);assert.notEqual(finding.filePath,'src/first.js');assert.equal(result.decision,'block');
  });
  test('F13 secret in second patch file is attributed to the second path',async()=>{
   const result=await noSecretsRule.inspect(context(first+patch('src/second.js','a',`const token='sk-${'a'.repeat(40)}';`)));assert.equal(result.findings[0]?.filePath,'src/second.js');
  });
  test('F15 insecure audit-log modes are excluded from counters as well as activity',t=>{
   const directory=tmp(t);const file=guardianEventPath_8(directory);fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});fs.writeFileSync(file,JSON.stringify({kind:'preflight-blocked',at:'2026-10-14T12:00:00.000Z'})+'\n');fs.chmodSync(file,0o644);
   if(process.platform!=='win32'){assert.equal(readGuardianStatus_8(directory).blocked,0);assert.deepEqual(readGuardianActivity(directory),[]);}
   fs.chmodSync(file,0o600);assert.equal(readGuardianStatus_8(directory).blocked,1);
  });
  for(const output of ['ENOENT: no such file or directory','Not found','Permission denied'])test(`F16 read failure ${output} is not source review`,()=>{
   assert.equal(isSourceReviewEvidence({status:'success',kind:'generic',toolName:'read_file',output,sequence:1,signature:'s'}),false);
  });
  test('F17 POSIX shell positional argv is not executed as script source',()=>{
   assert.equal(evaluatePreflight_8('process_start',{executable:'bash',args:['-c','true','unused-argv0','; rm -rf /']}),undefined);
   assert.equal(evaluatePreflight_8('process_start',{executable:'bash',args:['-c','rm -rf /']}),'destructive-command');
  });
  test('F18 non-shell argv metacharacters remain literal',()=>{
   assert.equal(evaluatePreflight_8('process_start',{executable:'printf',args:['%s','safe && rm -rf /']}),undefined);
   assert.equal(collectTurnEvidence_8([msg('assistant',[part({executable:'printf',args:['%s','safe && npm test']},'process_start')])]).records.some(r=>r.kind==='test'),false);
   assert.equal(evaluatePreflight_8('process_start',{executable:'rm',args:['-rf','/']}),'destructive-command');
   assert.match(extractToolCommand({executable:'printf',args:['a; b']}),/'a; b'/);
  });
  test('F20 second-patch TODO and stub findings use the actual file',async()=>{
   const ctx=context(first+patch('src/second.js','let y=1;','// TODO: implement handler'));
   for(const rule of [noStubsRule,noShortcutsRule]){const result=await rule.inspect(ctx);assert.equal(result.findings[0]?.filePath,'src/second.js');}
  });
  test('F14 repeated idle bursts are coalesced and remain cancellable',async t=>{
   const directory=tmp(t);fs.writeFileSync(path.join(directory,'opencode-guardian.json'),JSON.stringify({enabled:true,secrets:{enabled:false},updateNotice:{enabled:false}}));
   let calls=0,done;const drained=new Promise(r=>{done=r;});
   const cleanup=await Guardian.setup({location:{directory},event:{subscribe({signal}){return(async function*(){for(let i=0;i<251;i++)yield{type:'session.idle',data:{sessionID:'same'}};done();await new Promise(r=>signal.aborted?r():signal.addEventListener('abort',r,{once:true}));})();}},session:{async context(){calls++;return[];},async synthetic(){}}});
   try{await drained;await new Promise(r=>setTimeout(r,40));assert.ok(calls>0&&calls<=2,`burst caused ${calls} inspections`);}finally{await cleanup();}
  });

  test('file patch boundaries preserve native add/update/delete paths',async()=>{
   const patchText='*** Begin Patch\n*** Update File: src/first.js\n@@\n-a\n+b\n*** Add File: tests/new.test.js\n+test.skip("case",()=>{});\n*** Delete File: tests/old.test.js\n*** End Patch';
   assert.deepEqual(extractMutatedFilePaths(part({patchText})),['src/first.js','tests/new.test.js','tests/old.test.js']);
   const result=await noCheatRule.inspect(context(patchText));assert.ok(result.findings.some(f=>f.filePath==='tests/old.test.js'&&f.pattern==='test file deleted'));
  });

  test('idle queue does not starve a continuous burst and cancels pending work',async()=>{
   const {createIdleQueue}=await import('../dist/idle-queue.js');const controller=new AbortController();const queue=createIdleQueue(controller.signal,()=>assert.fail('unexpected queue error'));let calls=0;
   for(let i=0;i<8;i++){queue.enqueue('s',async()=>{calls++;});await new Promise(r=>setTimeout(r,5));}
   assert.ok(calls>0,'continuous notifications must still inspect');
   const before=calls;queue.enqueue('cancelled',async()=>{calls++;});queue.forget('cancelled');controller.abort();await new Promise(r=>setTimeout(r,20));assert.equal(calls,before);
  });

  test('idle queue serializes same-session work and coalesces one follow-up',async()=>{
   const {createIdleQueue}=await import('../dist/idle-queue.js');const controller=new AbortController();const queue=createIdleQueue(controller.signal,()=>assert.fail('unexpected queue error'));let release,started;const entered=new Promise(r=>{started=r;});const held=new Promise(r=>{release=r;});let calls=0;
   queue.enqueue('s',async()=>{calls++;started();await held;});await entered;
   for(let i=0;i<250;i++)queue.enqueue('s',async()=>{calls++;});assert.equal(calls,1);release();await new Promise(r=>setTimeout(r,30));assert.equal(calls,2);controller.abort();
  });

  test('unified hunk content cannot forge a new file boundary',async()=>{
   const patchText='--- a/tests/example.test.js\n+++ b/tests/example.test.js\n@@ -1,3 +1,4 @@\n const marker = `\n--- a/src/decoy.js\n+++ b/src/decoy.js\n `;\n+test.skip("case", () => {});\n';
   assert.deepEqual(extractMutatedFilePaths(part({patchText})),['tests/example.test.js']);
   const result=await noCheatRule.inspect(context(patchText));assert.ok(result.findings.some(f=>f.filePath==='tests/example.test.js'));
  });

  test('native move tracks old and new paths and inspects the new test target',async()=>{
   const patchText='*** Begin Patch\n*** Update File: src/old.js\n*** Move to: tests/new.test.js\n@@\n-a\n+test.skip("case", () => {});\n*** End Patch';
   assert.deepEqual(extractMutatedFilePaths(part({patchText})),['src/old.js','tests/new.test.js']);
   const result=await noCheatRule.inspect(context(patchText));assert.ok(result.findings.some(f=>f.filePath==='tests/new.test.js'));
  });
});

describe("Source Audit Fixes", () => {
  function projects(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-source-fixes-"));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const create = (name, config) => {
      const directory = path.join(root, name);
      fs.mkdirSync(directory);
      fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
        updateNotice: { enabled: false }, ...config,
      }));
      return directory;
    };
    return { root, create };
  }

  async function host(t, directory, sessionDirectory, overrides = {}) {
    const tools = new Map(), sessions = new Map();
    const events = [];
    let wake;
    const cleanup = await Guardian.setup({
      location: { directory },
      tool: { async hook(name, handler) {
        tools.set(name, handler);
        return { dispose() { tools.delete(name); } };
      } },
      session: {
        async get() { return { location: { directory: sessionDirectory } }; },
        async context() { return []; },
        async synthetic() {},
        async hook(name, handler) {
          sessions.set(name, handler);
          return { dispose() { sessions.delete(name); } };
        },
        ...overrides,
      },
      event: { subscribe({ signal }) { return (async function* () {
        const onAbort = () => wake?.();
        signal.addEventListener("abort", onAbort, { once: true });
        try {
          while (!signal.aborted) {
            if (!events.length) await new Promise(resolve => { wake = resolve; });
            while (!signal.aborted && events.length) yield events.shift();
          }
        } finally { signal.removeEventListener("abort", onAbort); }
      })(); } },
    });
    t.after(cleanup);
    return { tools, sessions, cleanup, async emit(event) {
      events.push(event); wake?.();
      await new Promise(resolve => setImmediate(resolve));
    } };
  }

  test("native write preflight checks V2 paths, secrets and truncation", async t => {
    const { create } = projects(t);
    const directory = create("strict", { preflight: { enabled: true }, secrets: { enabled: false } });
    const v2 = await host(t, directory, directory);
    for (const field of ["filePath", "path"]) {
      for (const [content, reason] of [
        ["// ... existing code unchanged ...", "truncation-placeholder-in-file-write"],
        ["const token = 'sk-proj-" + "A".repeat(30) + "';", "hardcoded-secret-in-file-write"],
      ]) {
        const args = { [field]: "src/a.ts", content };
        assert.equal(evaluatePreflight("write", args), reason);
        await assert.rejects(async () => v2.tools.get("execute.before")(
          { tool: "write", sessionID: "s", id: "c", input: args }), e => e.reason === reason);
      }
    }
    assert.equal(evaluatePreflight("write", { path: "a.ts", content: "export const value = 1;" }), undefined);
  });

  test("V2 first tool in an existing second-project session uses its own preflight", async t => {
    const { create } = projects(t);
    const base = create("base", { preflight: { enabled: false }, secrets: { enabled: false } });
    const other = create("other", { preflight: { enabled: true }, secrets: { enabled: false } });
    const h = await host(t, base, other);
    await h.emit({ type: "session.created", data: { sessionID: "s" } });
    await assert.rejects(async () => h.tools.get("execute.before")({
      sessionID: "s", id: "c", tool: "bash", input: { command: "rm -rf ./fixture" },
    }), e => e.reason === "destructive-command");
  });

  test("V2 teardown while resolving a tool directory prevents late policy work", async t => {
    const { create } = projects(t);
    const base = create("base", { secrets: { enabled: false }, preflight: { enabled: true } });
    let release;
    const h = await host(t, base, base, { get: () => new Promise(resolve => { release = resolve; }) });
    const pending = h.tools.get("execute.before")({ sessionID: "s", id: "c", tool: "bash", input: { command: "rm -rf fixture" } });
    assert.equal(typeof release, "function");
    await h.cleanup();
    release({ location: { directory: base } });
    await pending;
  });

  test("V2 incomplete session lookups and move events never cache a guessed project", async t => {
    const { create } = projects(t);
    const base = create("base", { secrets: { enabled: false }, preflight: { enabled: false } });
    const other = create("other", { secrets: { enabled: false }, preflight: { enabled: true } });
    for (const first of [{}, { location: { directory: " " } }, { location: { directory: base } }]) {
      let calls = 0;
      const h = await host(t, base, other, { async get() {
        return ++calls === 1 ? first : { location: { directory: other } };
      } });
      await h.tools.get("execute.before")({ sessionID: "s", id: "c1", tool: "bash", input: { command: "npm test" } });
      if (first.location?.directory === base) {
        await h.emit({ type: "session.moved", data: { sessionID: "s" } });
      }
      await assert.rejects(async () => h.tools.get("execute.before")({
        sessionID: "s", id: "c2", tool: "bash", input: { command: "rm -rf fixture" },
      }), e => e.reason === "destructive-command");
      assert.equal(calls, 2);
      await h.cleanup();
    }
  });

  test("V2 auxiliary registration failure rolls back even when initial secrets are off", async t => {
    const { create } = projects(t);
    const base = create("base", { secrets: { enabled: false } });
    for (const failure of ["compaction", "generate", "title"]) {
      const active = new Set();
      await assert.rejects(host(t, base, base, { async hook(name) {
        if (name === failure) throw new Error("fixture registration failure");
        active.add(name);
        return { dispose() { active.delete(name); } };
      } }), /session context security hook registration failed/);
      assert.deepEqual([...active], []);
    }
  });

  test("native empty-file writes remain inspectable while missing content is rejected", () => {
    assert.equal(evaluatePreflight("write", { path: "empty.ts", content: "" }), undefined);
    assert.equal(evaluatePreflight("write", { path: "empty.ts" }), "uninspectable-file-input");
  });

  test("V2 auxiliary requests respect each project and subsequent config changes", async t => {
    const { create } = projects(t);
    const base = create("base", { secrets: { enabled: false } });
    const other = create("other", { secrets: { enabled: true } });
    const h = await host(t, base, other);
    for (const kind of ["context", "compaction", "generate", "title"]) {
      assert.equal(typeof h.sessions.get(kind), "function", kind);
      const request = { sessionID: "s", messages: [{ type: "user", text: "TOKEN=audit_dummy_secret_123" }], system: [{ type: "text", text: "TOKEN=audit_dummy_secret_123" }] };
      await h.sessions.get(kind)(request);
      assert.ok(!JSON.stringify(request).includes("audit_dummy_secret_123"), kind);
    }
    fs.writeFileSync(path.join(other, "opencode-guardian.json"), JSON.stringify({ secrets: { enabled: false } }));
    await h.emit({ type: "config.updated", data: {} });
    const disabled = { sessionID: "s", messages: [{ type: "user", text: "TOKEN=audit_dummy_secret_123" }], system: [] };
    await h.sessions.get("title")(disabled);
    assert.ok(JSON.stringify(disabled).includes("audit_dummy_secret_123"));
    fs.writeFileSync(path.join(other, "opencode-guardian.json"), JSON.stringify({ secrets: { enabled: true } }));
    await h.emit({ type: "config.updated", data: {} });
    await h.sessions.get("title")(disabled);
    assert.ok(!JSON.stringify(disabled).includes("audit_dummy_secret_123"));
  });

  test("connection-string redaction handles empty usernames, missing paths and IPv6", () => {
    for (const url of [
      "redis://:audit_dummy_pass_123@localhost:6379",
      "redis://:audit_dummy_pass_123@localhost:6379/0",
      "mysql://user:audit_dummy_pass_123@localhost:3306",
      "postgresql://user:audit_dummy_pass_123@[::1]:5432/db?sslmode=require",
      "mongodb+srv://user:audit_dummy_pass_123@cluster.example/db",
    ]) {
      assert.equal(sanitizeString_9(`Connect to (${url}).`, { includeRuntimeEnv: false }).sanitized,
        `Connect to (${url.replace("audit_dummy_pass_123", "[REDACTED]")}).`);
    }
    assert.equal(sanitizeString_9("https://example.com/public", { includeRuntimeEnv: false }).sanitized, "https://example.com/public");
  });

  test("structured edits invalidate earlier tests and snapshot all edited files including deletions", t => {
    const { root } = projects(t);
    fs.writeFileSync(path.join(root, "a.ts"), "export const a = 1;");
    fs.writeFileSync(path.join(root, "b.ts"), "");
    const input = { edits: [
      { path: "a.ts", oldText: "a = 0", newText: "a = 1" },
      { path: "b.ts", oldText: "remove this", replacement: "" },
    ] };
    const part = (tool, input, callID) => ({ type: "tool", tool, callID, state: { status: "completed", input, metadata: { exit: 0 } } });
    const turn = [{ info: { id: "a", role: "assistant" }, parts: [
      part("bash", { command: "npm test" }, "test-before"), part("multiedit", input, "edit"),
    ] }];
    const evidence = collectTurnEvidence(turn);
    assert.deepEqual(evidence.fileMutations.map(r => r.filePath).sort(), ["a.ts", "b.ts"]);
    const policy = evaluateTaskPolicy({ iterativeReview: false, requiredVerifications: ["test"] }, evidence);
    assert.equal(policy.verifications[0].status, "unknown");
    const store = new VerificationSnapshotStore_9();
    store.observe("s", "edit", "multiedit", input, "updated", {}, root);
    store.observe("s", "test-after", "bash", { command: "npm test" }, "passed", { exit: 0 }, root);
    assert.deepEqual(store.snapshots("s").get("test-after").files.sort(), ["a.ts", "b.ts"]);
  });

  test("ghost dependency checks preserve each unified/native patch file and manifest", async t => {
    const { root } = projects(t);
    fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "fixture", dependencies: {} }));
    fs.mkdirSync(path.join(root, "child"));
    fs.writeFileSync(path.join(root, "child", "package.json"), JSON.stringify({ dependencies: { allowed: "1.0.0" } }));
    const unified = (name, text) => `--- a/${name}\n+++ b/${name}\n@@ -0,0 +1 @@\n+${text}\n`;
    const native = (name, text) => `*** Add File: ${name}\n+${text}\n`;
    for (const format of [unified, native]) {
      const doc = format("README.md", "# Example");
      const js = format("main.ts", 'import missing from "guardian-missing-package";');
      const child = format("child/main.ts", 'import allowed from "allowed";');
      for (const patch of [doc + js + child, child + js + doc]) {
        const result = await noGhostDepsRule_9.inspect({ sessionID: "s", directory: root,
          messages: [], ruleConfig: {}, currentTurn: [{ info: { id: "a", role: "assistant" }, parts: [
            { type: "tool", state: { input: { patchText: patch } } },
          ] }] });
        assert.equal(result.decision, "block");
        assert.deepEqual(result.findings.map(f => f.pattern), ["guardian-missing-package"]);
      }
    }
  });
});

describe("Rule Engine Improvements", () => {
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
    assert.equal(isHallucinatedOrMalformedPackageInstall_10("npm install React"), true);
    assert.equal(isHallucinatedOrMalformedPackageInstall_10("npm i lodash-security-patch"), true);
    assert.equal(isHallucinatedOrMalformedPackageInstall_10("pnpm add express-official"), true);
    assert.equal(isHallucinatedOrMalformedPackageInstall_10("yarn add chalk-fixed-version"), true);

    // valid installs
    assert.equal(isHallucinatedOrMalformedPackageInstall_10("npm install react react-dom"), false);
    assert.equal(isHallucinatedOrMalformedPackageInstall_10("npm i -D @types/node typescript"), false);

    // evaluatePreflight_10 blocks hallucinated installs
    assert.equal(
      evaluatePreflight_10("bash", { command: "npm install express-security-patch" }),
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
    assert.equal(isLazyCommitMessage_10('git commit -m "fix"'), true);
    assert.equal(isLazyCommitMessage_10('git commit -m "wip"'), true);
    assert.equal(isLazyCommitMessage_10('git commit -m "update"'), true);
    assert.equal(isLazyCommitMessage_10('git commit -m "changes"'), true);
    assert.equal(isLazyCommitMessage_10('git commit -m "hotfix"'), true);
    assert.equal(isLazyCommitMessage_10('git commit -m "feat(core): implement robust error handling"'), false);

    // evaluatePreflight_10 blocks lazy commit
    assert.equal(
      evaluatePreflight_10("bash", { command: 'git commit -m "fix"' }),
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
});

describe("Multi-Project & Audit Regressions", () => {
  function makeTempDir(prefix) {
    return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  }

  function emptyStream() {
    return {
      async *[Symbol.asyncIterator]() {
        // keep open briefly then exit cleanly
      },
    };
  }

  test("sanitizeMessages preserves Message/Part prototypes with parts and redacts reasoning/top-level tool fields", () => {
    class V2Part {
      constructor(data) {
        Object.assign(this, data);
      }
    }
    class V2Message {
      constructor(info, parts) {
        this.info = info;
        this.parts = parts;
      }
    }

    const secret = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";
    const textPart = new V2Part({ type: "text", text: "ok" });
    const reasoningPart = new V2Part({ type: "reasoning", text: `secret=${secret}` });
    const toolPart = new V2Part({ type: "tool", output: `Bearer ${secret}` });
    const msg = new V2Message({ id: "m1", role: "assistant", note: secret }, [
      textPart,
      reasoningPart,
      toolPart,
    ]);

    const sanitized = sanitizeMessages([msg]);
    assert.equal(sanitized.length, 1);
    assert.ok(sanitized[0] instanceof V2Message, "Message prototype must be preserved");
    assert.ok(sanitized[0].parts[0] instanceof V2Part, "Part prototype must be preserved");
    assert.equal(sanitized[0].parts[1].text.includes(secret), false, "reasoning text must be redacted");
    assert.equal(sanitized[0].parts[2].output.includes(secret), false, "top-level tool output must be redacted");
    assert.equal(sanitized[0].info.note.includes(secret), false, "message info fields must be redacted");
  });

  test("SanitizerOptions.safeValues exempts explicitly safe literals across string and object sanitization", () => {
    const safeToken = "sk-proj-safe_public_demo_token_1234567890";
    const realSecret = "sk-proj-real_secret_token_9876543210abcd";
    const opts = resolveSanitizerOptions({
      secrets: {
        enabled: true,
        safeValues: [safeToken],
      },
    });
    assert.ok(opts);
    assert.equal(sanitizeString_11(safeToken, opts).sanitized, safeToken);
    assert.notEqual(sanitizeString_11(realSecret, opts).sanitized, realSecret);

    const kv = sanitizeString_11(`API_KEY=${safeToken}`, opts);
    assert.equal(kv.sanitized, `API_KEY=${safeToken}`);
  });

  test("shell.hook('create.before') resolves event.cwd when sessionID and location.directory are absent", async (t) => {
    const dirA = makeTempDir("guardian-cwd-a-");
    const dirB = makeTempDir("guardian-cwd-b-");
    t.after(() => {
      clearGuardianTelemetryConfig();
      fs.rmSync(dirA, { recursive: true, force: true });
      fs.rmSync(dirB, { recursive: true, force: true });
    });

    // Project A has preflight disabled; Project B has strict preflight enabled
    fs.writeFileSync(
      path.join(dirA, "opencode-guardian.json"),
      JSON.stringify({ enabled: true, preflight: { enabled: false }, telemetry: { level: "off" } })
    );
    fs.writeFileSync(
      path.join(dirB, "opencode-guardian.json"),
      JSON.stringify({ enabled: true, preflight: { enabled: true }, telemetry: { level: "off" } })
    );

    let shellBeforeHandler;
    const dispose = await plugin.setup({
      location: { directory: dirA },
      event: { subscribe: () => emptyStream() },
      session: {
        hook: () => ({ dispose() {} }),
        context: () => ({ dispose() {} }),
        synthetic: async () => {},
      },
      tool: { hook: () => ({ dispose() {} }) },
      shell: {
        hook: async (name, cb) => {
          if (name === "create.before") shellBeforeHandler = cb;
          return { dispose() {} };
        },
      },
    });
    t.after(() => dispose?.());

    assert.equal(typeof shellBeforeHandler, "function");
    await assert.rejects(
      () => shellBeforeHandler({ command: "rm -rf /tmp/nonexistent-target", cwd: dirB }),
      /preflight|destructive/i,
      "shell.create.before must enforce dirB strict preflight using event.cwd"
    );
  });

  test("guardian.interventions.clear RPC honors directory/location context and resolves uncached session directories", async (t) => {
    const dirA = makeTempDir("guardian-rpc-a-");
    const dirB = makeTempDir("guardian-rpc-b-");
    t.after(() => {
      clearGuardianTelemetryConfig();
      fs.rmSync(dirA, { recursive: true, force: true });
      fs.rmSync(dirB, { recursive: true, force: true });
    });

    fs.writeFileSync(
      path.join(dirA, "opencode-guardian.json"),
      JSON.stringify({ enabled: true, preflight: { enabled: true }, telemetry: { level: "off" } })
    );
    fs.writeFileSync(
      path.join(dirB, "opencode-guardian.json"),
      JSON.stringify({ enabled: true, preflight: { enabled: true }, telemetry: { level: "off" } })
    );

    let rpcHandlers;
    let toolBefore;
    const dispose = await plugin.setup({
      location: { directory: dirA },
      event: { subscribe: () => emptyStream() },
      session: {
        hook: () => ({ dispose() {} }),
        context: () => ({ dispose() {} }),
        synthetic: async () => {},
        get: async ({ sessionID }) => ({
          id: sessionID,
          location: { directory: sessionID === "s-b" ? dirB : dirA },
        }),
      },
      tool: {
        hook: (name, cb) => {
          if (name === "execute.before") toolBefore = cb;
          return { dispose() {} };
        },
      },
      rpc: {
        register: async (_def, handlers) => {
          rpcHandlers = handlers;
          return { dispose() {} };
        },
      },
    });
    t.after(() => dispose?.());

    // Trigger a preflight block on session s-a (dirA) and s-b (dirB)
    await assert.rejects(() => toolBefore({ tool: "bash", sessionID: "s-a", input: { command: "rm -rf /" } }));
    await assert.rejects(() => toolBefore({ tool: "bash", sessionID: "s-b", input: { command: "rm -rf /" } }));

    const beforeA = await rpcHandlers.latest({ sessionID: "s-a" });
    const beforeB = await rpcHandlers.latest({ sessionID: "s-b" });
    assert.equal(beforeA.active, true);
    assert.equal(beforeB.active, true);

    // Clear dirB with {} + { location: { directory: dirB } }; s-a must stay active!
    await rpcHandlers[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD]({}, { location: { directory: dirB } });
    const afterA = await rpcHandlers.latest({ sessionID: "s-a" });
    const afterB = await rpcHandlers.latest({ sessionID: "s-b" });
    assert.equal(afterA.active, true, "dirA intervention must not be cleared when clearing dirB");
    assert.equal(afterB.active, false, "dirB intervention must be cleared");
  });

  test("guardianCommandReport applies V2 context.options overrides in doctor, rules, and config", async (t) => {
    const dir = makeTempDir("guardian-cmd-opts-");
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

    const options = {
      preflight: { enabled: true },
      rules: { "safety/destructive-operations": "error" },
    };
    const doctor = await guardianCommandReport("doctor", dir, "0.15.1", options);
    const rules = await guardianCommandReport("rules", dir, "0.15.1", options);
    const config = await guardianCommandReport("config", dir, "0.15.1", options);

    assert.match(doctor.message, /Strict preflight configured: enabled/);
    assert.match(rules.message, /safety\/destructive-operations: error/);
    assert.match(config.message, /Strict preflight: enabled/);
  });

  test("TUI ownsInterventionScope delivers same-directory preflight toast before context.data.session syncs", (t) => {
    const dir = makeTempDir("guardian-tui-scope-");
    const otherDir = makeTempDir("guardian-tui-other-");
    t.after(() => {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(otherDir, { recursive: true, force: true });
    });

    const shown = [];
    const cleanups = [];
    const dispose = tuiPlugin.setup({
      location: { directory: dir },
      ui: {
        slot: () => ({ dispose() {} }),
        toast: { show: (p) => shown.push(p) },
        dialog: { alert: async () => {}, confirm: async () => false },
      },
      lifecycle: { onCleanup: (fn) => cleanups.push(fn) },
      // Minimal/unsynced context.data.session: returns undefined for new session
      data: { session: { get: () => undefined } },
    });
    t.after(() => {
      dispose?.();
      for (const fn of cleanups) fn();
    });

    dispatchGuardianToast(
      { title: "Blocked", message: "destructive", variant: "error", duration: 3000 },
      { directory: dir, sessionID: "new-unsynced-session" }
    );
    dispatchGuardianToast(
      { title: "Other", message: "other project", variant: "error", duration: 3000 },
      { directory: otherDir, sessionID: "other-session" }
    );

    assert.equal(shown.length, 1);
    assert.equal(shown[0].title, "Blocked");
  });

  test("enabled: false cleans up telemetryConfigRegistry and default maxBytes is 512 KiB", async (t) => {
    const dir = makeTempDir("guardian-disabled-reg-");
    t.after(() => {
      clearGuardianTelemetryConfig();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    fs.writeFileSync(
      path.join(dir, "opencode-guardian.json"),
      JSON.stringify({ enabled: false, telemetry: { level: "off", maxBytes: 12345 } })
    );

    await plugin.setup({
      location: { directory: dir },
      event: { subscribe: () => emptyStream() },
      session: { context: () => ({ dispose() {} }), synthetic: async () => {} },
    });

    const settings = resolveTelemetrySettings(dir);
    assert.equal(settings.maxBytes, DEFAULT_GUARDIAN_LOG_BYTES);
    assert.equal(DEFAULT_GUARDIAN_LOG_BYTES, 512 * 1024);
    assert.equal(settings.level, "violations");
  });

  test("GUARDIAN_INTERVENTION_RPC_DEFINITION exposes RPC id and directory-scoped clear schema", () => {
    assert.equal(GUARDIAN_INTERVENTION_RPC_DEFINITION.id, GUARDIAN_INTERVENTION_RPC_ID);
    assert.equal(
      GUARDIAN_INTERVENTION_RPC_DEFINITION.methods[GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD].input.properties.directory.type,
      "string"
    );
  });

  test("R4 Wave 3 (R4-036, R4-040, R4-044): per-file stub dedup, bounded >2 MiB code masking, and doctor critical preflight reporting", async (t) => {
    const { noStubsRule } = await import("../dist/rules/no-stubs.js");
    const { maskCodeLiterals } = await import("../dist/code-context.js");
    const { guardianCommandReport } = await import("../dist/commands.js");

    // R4-040: same stub pattern across two different files must produce findings for BOTH files
    const stubTurn = [
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          { type: "tool", tool: "write", state: { status: "completed", input: { path: "src/a.ts", content: "export function a() { throw new NotImplementedError('todo'); }" } } },
          { type: "tool", tool: "write", state: { status: "completed", input: { path: "src/b.ts", content: "export function b() { throw new NotImplementedError('todo'); }" } } },
        ],
      },
    ];
    const stubRes = noStubsRule.inspect({
      sessionID: "s-r4-040",
      directory: process.cwd(),
      currentTurn: stubTurn,
      history: stubTurn,
      ruleConfig: {},
    });
    assert.equal(stubRes.decision, "block");
    assert.equal(stubRes.findings.length, 2, "R4-040: identical stub patterns in two distinct files must both be reported");
    assert.deepEqual(stubRes.findings.map((f) => f.filePath).sort(), ["src/a.ts", "src/b.ts"]);

    // R4-036: >2 MiB source must still scan bounded prefix rather than silently returning ""
    const hugeCode = "export function f() { throw new NotImplementedError(); }\n" + " ".repeat(2 * 1024 * 1024 + 100);
    const masked = maskCodeLiterals(hugeCode, false, "src/huge.ts");
    assert.ok(masked.includes("NotImplementedError"), "R4-036: >2 MiB source must scan bounded prefix instead of returning empty string");

    // R4-044: /guardian-doctor must accurately report Critical preflight mode, not Autonomous (Strict)
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-r4-044-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
      enabled: true,
      preflight: { enabled: true, mode: "critical" },
    }));
    const doc = await guardianCommandReport("doctor", dir, "0.17.9");
    assert.match(doc.message, /Autonomous \(Critical Preflight\)/, `R4-044: doctor must report Critical Preflight, got:\n${doc.message}`);
    assert.ok(!doc.message.includes("Autonomous (Strict)"), "R4-044: doctor must not misreport critical mode as Autonomous (Strict)");
  });

  test("Re-audit closure: multiple stubs in same file, circuit-breaker probe redirection/subcommands, and disabled doctor report", async (t) => {
    const { noStubsRule } = await import("../dist/rules/no-stubs.js");
    const { circuitBreakerRule } = await import("../dist/rules/circuit-breaker.js");
    const { guardianCommandReport } = await import("../dist/commands.js");

    // Multiple stubs of the same pattern in ONE file must both be reported
    const sameFileStubRes = noStubsRule.inspect({
      sessionID: "s-multi-stub",
      directory: process.cwd(),
      currentTurn: [{
        info: { id: "a1", role: "assistant" },
        parts: [{
          type: "tool",
          tool: "write",
          state: {
            status: "completed",
            input: {
              path: "src/service.ts",
              content: "export function a() { throw new NotImplementedError('first'); }\nexport function b() { throw new NotImplementedError('second'); }\n",
            },
          },
        }],
      }],
      history: [],
      ruleConfig: {},
    });
    assert.equal(sameFileStubRes.findings.length, 2, "distinct stubs in the same file must all be reported");

    // Circuit breaker must skip subcommand probes (`npm test --help`) and probes with `2>&1`
    const probeTurn = [
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test" }, output: "FAIL x", metadata: { exit: 1 } } },
          { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test --help" }, output: "usage", metadata: { exit: 0 } } },
          { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test" }, output: "FAIL x", metadata: { exit: 1 } } },
          { type: "tool", tool: "bash", state: { status: "completed", input: { command: "pytest --version 2>&1" }, output: "pytest 8", metadata: { exit: 0 } } },
          { type: "tool", tool: "bash", state: { status: "completed", input: { command: "npm test" }, output: "FAIL x", metadata: { exit: 1 } } },
        ],
      },
    ];
    const cbRes = circuitBreakerRule.inspect({
      sessionID: "s-cb-probe",
      directory: process.cwd(),
      currentTurn: probeTurn,
      history: probeTurn,
      ruleConfig: {},
    });
    assert.equal(cbRes.decision, "block", "interleaved --help and --version 2>&1 probes must not reset circuit-breaker streak");

    // Doctor & config when enabled: false must report Disabled and NOT emit preflight mismatch warning
    const disabledDir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-disabled-doc-"));
    t.after(() => fs.rmSync(disabledDir, { recursive: true, force: true }));
    fs.writeFileSync(path.join(disabledDir, "opencode-guardian.json"), JSON.stringify({
      enabled: false,
      preflight: { enabled: true, mode: "strict" },
    }));
    const disabledDoc = await guardianCommandReport("doctor", disabledDir, "0.17.9");
    assert.match(disabledDoc.message, /Protection mode: Disabled/);
    assert.match(disabledDoc.message, /Preflight mode: disabled/);
    assert.ok(!disabledDoc.message.includes("Attention: configured preflight"), "disabled Guardian must not emit preflight mismatch attention warning");
    const disabledCfg = await guardianCommandReport("config", disabledDir, "0.17.9");
    assert.match(disabledCfg.message, /Protection mode: Disabled/);
    assert.match(disabledCfg.message, /Preflight mode: disabled/);

    // Pass-2 re-audit: noStubsRule must scan new_str, CodeContent, ReplacementContent, and TargetFile
    for (const input of [
      { path: "src/a.ts", new_str: "throw new NotImplementedError();" },
      { TargetFile: "src/b.ts", CodeContent: "export function run() {}" },
      { TargetFile: "src/c.ts", ReplacementContent: "throw new NotImplementedError();" },
    ]) {
      const res = noStubsRule.inspect({
        sessionID: "s-stub-keys",
        directory: process.cwd(),
        currentTurn: [{ info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "edit", state: { status: "completed", input } }] }],
        history: [],
        ruleConfig: {},
      });
      assert.equal(res.decision, "block", `noStubsRule must inspect ${JSON.stringify(Object.keys(input))}`);
    }

    // Pass-2 re-audit: partial-line edit stub disk recheck must NOT falsely verify when stub remains on disk
    const recheckDir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-stub-recheck-"));
    t.after(() => fs.rmSync(recheckDir, { recursive: true, force: true }));
    fs.mkdirSync(path.join(recheckDir, "src"), { recursive: true });
    fs.writeFileSync(path.join(recheckDir, "src", "a.ts"), "export function f() { throw new NotImplementedError(); }\nexport const x = 2;\n");
    const { GuardEngine } = await import("../dist/engine.js");
    const recheckEngine = new GuardEngine({ enabled: true, remediationBudget: 1 });
    const turn1 = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Implement f" }] },
      { info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "edit", state: { status: "completed", input: { path: "src/a.ts", old_string: "return 1;", new_string: "throw new NotImplementedError();" } } }, { type: "text", text: "Done." }] },
    ];
    const r1 = await recheckEngine.inspect("s-partial-stub", recheckDir, turn1);
    assert.equal(r1.decision, "block");
    const turn2 = [
      ...turn1,
      { info: { id: "rem1", role: "user" }, parts: [{ type: "text", text: r1.combinedRemediationPrompt, synthetic: true, metadata: { "opencode-guardian": true } }] },
      { info: { id: "a2", role: "assistant" }, parts: [{ type: "tool", tool: "edit", state: { status: "completed", input: { path: "src/a.ts", old_string: "x = 1", new_string: "x = 2" } } }, { type: "text", text: "Updated." }] },
    ];
    const r2 = await recheckEngine.inspect("s-partial-stub", recheckDir, turn2);
    assert.notEqual(r2.remediationStatus, "verified", "partial-line stub still present on disk must never verify remediation");

    // Pass-3 re-audit: all remaining code rules inspect new_str/CodeContent/TargetFile, and no-silent-failure uses per-file patch paths
    const { noTruncationRule } = await import("../dist/rules/no-truncation.js");
    const { noCheatRule } = await import("../dist/rules/no-cheat.js");
    const { noSilentFailureRule } = await import("../dist/rules/no-silent-failure.js");
    const { noShortcutsRule } = await import("../dist/rules/no-shortcuts.js");
    fs.writeFileSync(path.join(recheckDir, "package.json"), JSON.stringify({ name: "tmp-pass3", dependencies: {} }));
    const mkCtx = (input, ruleConfig = {}) => ({
      sessionID: "s-pass3-keys",
      directory: recheckDir,
      currentTurn: [{ info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "str_replace_editor", state: { status: "completed", input } }] }],
      history: [],
      ruleConfig,
    });
    assert.equal(noTruncationRule.inspect(mkCtx({ TargetFile: "src/a.ts", new_str: "// ... existing code unchanged ..." })).decision, "block");
    assert.equal(noCheatRule.inspect(mkCtx({ TargetFile: "src/a.test.ts", new_str: 'test.skip("x", () => {})' })).decision, "block");
    assert.equal(noSilentFailureRule.inspect(mkCtx({ TargetFile: "src/a.ts", new_str: "try { a(); } catch (e) {}" }, { blockEmptyHandlers: true })).decision, "block");
    assert.equal(noShortcutsRule.inspect(mkCtx({ TargetFile: "src/a.ts", new_str: "// TODO: implement auth" })).decision, "block");
    assert.equal(noGhostDepsRule.inspect(mkCtx({ TargetFile: "src/a.ts", new_str: 'import x from "nonexistent-ghost-pkg";' })).decision, "block");
    // Patch with JS/TS private class field `#f` must preserve filePath so `#` is not treated as a Python comment
    assert.equal(
      noSilentFailureRule.inspect(
        mkCtx(
          { patchText: "--- a/src/a.ts\n+++ b/src/a.ts\n@@ -1,1 +1,2 @@\n class A {\n+  #f = 1; run() { try { x(); } catch (e) {} }\n" },
          { blockEmptyHandlers: true }
        )
      ).decision,
      "block",
      "noSilentFailureRule must preserve patch filePath so JS/TS #privateField does not mask catch (e) {}"
    );
  });
});
