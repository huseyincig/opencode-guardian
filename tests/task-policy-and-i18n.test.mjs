import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { collectTurnEvidence } from "../dist/evidence.js";
import Guardian, { OpencodeGuardian } from "../dist/index.js";
import { SUPPORTED_SIGNAL_LOCALES, classifyInternationalAgentReport, extractInternationalSignals } from "../dist/locale-intents.js";
import { taskCompletionRule } from "../dist/rules/task-completion.js";
import { extractTaskContract, parseExplicitTaskDirective, taskGuidance } from "../dist/task-contract.js";
import { evaluateTaskPolicy } from "../dist/task-policy.js";

describe("Task Policy Evaluation", () => {
  function messages(user, parts) {
    return [
      { info: { id: "user", role: "user" }, parts: [{ type: "text", text: user }] },
      { info: { id: "agent", role: "assistant" }, parts },
    ];
  }

  const write = { type: "tool", tool: "write", state: {
    status: "completed", input: { filePath: "src/index.ts", content: "export const ok = true;" },
    metadata: { exit: 0 },
  } };
  const successfulRead = { type: "tool", tool: "read", state: {
    status: "completed", input: { filePath: "src/index.ts" },
    output: "export const ok = true;", metadata: { exit: 0 },
  } };
  const goodTests = { type: "tool", tool: "bash", state: {
    status: "completed", input: { command: "npm test" },
    output: "150 passed", metadata: { exit: 0 },
  } };
  const failedTests = { type: "tool", tool: "bash", state: {
    status: "completed", input: { command: "npm test" },
    output: "1 failed", metadata: { exit: 1 },
  } };

  function evaluate(user, parts) {
    const history = messages(user, parts);
    return evaluateTaskPolicy(extractTaskContract(history), collectTurnEvidence(history));
  }

  test("the same normalized policy works for Turkish, Spanish, Chinese and Arabic tasks", () => {
    const prompts = [
      "Her hata bulduğunda düzelt ve incelemeyi baştan başlat.",
      "Cada vez que encuentres un error, corrígelo y vuelve a revisar todo desde el principio hasta que no queden errores.",
      "每发现一个错误就修复，然后从头重新检查，直到没有错误。",
      "كلما وجدت خطأ أصلحه ثم أعد المراجعة من البداية حتى لا تبقى أخطاء.",
    ];
    for (const prompt of prompts) {
      const missed = evaluate(prompt, [write]);
      assert.equal(missed.review, "missing", prompt);
      assert.equal(missed.reviewProvesFullCoverage, false);
      const reviewed = evaluate(prompt, [write, successfulRead]);
      assert.equal(reviewed.review, "observed", prompt);
      assert.equal(reviewed.reviewProvesFullCoverage, false);
    }
  });

  test("policy requires an actual source check when that is what the user requested", () => {
    const sourceLoop = "Fix every bug and restart the full source review until no bugs remain.";
    assert.equal(evaluate(sourceLoop, [write, goodTests]).review, "missing");
    assert.equal(evaluate(sourceLoop, [write, goodTests, successfulRead]).review, "observed");
  });

  test("policy accepts a fresh successful test-only loop without inventing full source coverage", () => {
    const testLoop = "Fix failures and rerun tests until clean.";
    const result = evaluate(testLoop, [write, goodTests]);
    assert.equal(result.review, "observed");
    assert.equal(result.reviewProvesFullCoverage, false);
  });

  test("policy differentiates failed, stale and unknown verification evidence", () => {
    const request = "Fix the implementation and run tests.";
    assert.equal(evaluate(request, [write, failedTests]).verifications[0].status, "failed");
    assert.equal(evaluate(request, [goodTests, write]).verifications[0].status, "unknown");
    assert.equal(evaluate(request, [write]).verifications[0].status, "unknown");
    assert.equal(evaluate(request, [write, goodTests]).verifications[0].status, "passed");
  });

  test("an unknown verification outcome is not silently accepted as success", () => {
    const task = "Run tests.";
    const outcomeUnknown = { ...goodTests, state: { ...goodTests.state, metadata: {} } };
    const result = evaluate(task, [outcomeUnknown]);
    assert.equal(result.verifications[0].status, "unknown");
  });
});

describe("Structured Task Extraction", () => {
  const PREFIX = '@guardian-task {"mode":"iterative-review","review":"source","verify":["test"]}';

  function contract(text) {
    return extractTaskContract([{
      info: { id: "human", role: "user" },
      parts: [{ type: "text", text }],
    }]);
  }

  test("optional typed directive makes an otherwise unsupported language deterministic", () => {
    const greek = `${PREFIX}\nΒρες και διόρθωσε τα λάθη. Ξεκίνα την ανασκόπηση από την αρχή μετά από κάθε διόρθωση.`;
    const task = contract(greek);
    assert.equal(task.signalLocale, "structured");
    assert.equal(task.iterativeReview, true);
    assert.equal(task.requiresSourceReview, true);
    assert.deepEqual(task.requiredVerifications, ["test"]);
    assert.match(taskGuidance(task), /another review pass/);
    const evidence = collectTurnEvidence([
      { info: { id: "u", role: "user" }, parts: [{ type: "text", text: greek }] },
      { info: { id: "a", role: "assistant" }, parts: [
        { type: "tool", tool: "write", state: {
          status: "completed", input: { filePath: "src/code.ts", content: "export const ok = 1;" },
          metadata: { exit: 0 },
        } },
      ] },
    ]);
    const decision = evaluateTaskPolicy(task, evidence);
    assert.equal(decision.review, "missing");
    assert.equal(decision.verifications[0].status, "unknown");
  });

  test("typed directive supports a deliberate one-pass instruction without an inferred loop", () => {
    const task = contract(
      '@guardian-task {"mode":"one-pass","review":"checks","verify":["lint","test"]}\n' +
      "Review and repeat until clean (this line is a quoted example)."
    );
    assert.equal(task.iterativeReview, false);
    assert.deepEqual(task.requiredVerifications, ["lint", "test"]);
  });

  test("a recognized explicit prohibition in the body overrides a conflicting directive", () => {
    for (const text of [
      `${PREFIX}\nDo not repeat the review. Do not run tests.`,
      `${PREFIX}\nİncelemeyi tekrar başlatma, testleri çalıştırma.`,
      `${PREFIX}\n不要重复检查。不要运行测试。`,
      `${PREFIX}\n不要重复检查。Do not run tests.`,
    ]) {
      const task = contract(text);
      assert.equal(task.iterativeReview, false, text);
      assert.deepEqual(task.requiredVerifications, [], text);
    }
  });

  test("malformed and unexpected-key directives cannot silently enable policy", () => {
    const invalid = [
      '@guardian-task {"mode":"iterative-review","review":"source","verify":',
      '@guardian-task {"mode":"iterative-review","review":"source","verify":[],"publish":true}',
      '@guardian-task {"mode":"infinite","review":"source","verify":[]}',
      '@guardian-task {"mode":"iterative-review","review":"source","verify":["release"]}',
      '@guardian-task {"mode":"iterative-review","review":"source","verify":"test"}',
      '@guardian-task ' + 'x'.repeat(900),
      '\n@guardian-task {"mode":"iterative-review","review":"source","verify":[]}',
    ];
    for (const input of invalid) {
      assert.equal(parseExplicitTaskDirective(input), undefined, input.slice(0, 90));
    }
  });

  test("duplicate verification kinds in structured directives are deduplicated", () => {
    const task = contract('@guardian-task {"mode":"iterative-review","review":"checks","verify":["test","test","lint"]}');
    assert.deepEqual(task.requiredVerifications, ["test", "lint"]);
    assert.equal(task.requiresSourceReview, false);
  });
});

describe("Language-Agnostic Policy Invariants", () => {
  // Helper for building message turns
  function makeTurn(userPrompt, assistantParts) {
    return [
      { info: { id: "u-msg", role: "user" }, parts: [{ type: "text", text: userPrompt }] },
      { info: { id: "a-msg", role: "assistant" }, parts: assistantParts },
    ];
  }

  const fileMutation = {
    type: "tool",
    tool: "write_to_file",
    state: {
      status: "completed",
      input: { filePath: "/workspace/src/app.ts", content: "export const x = 1;" },
      metadata: { exit: 0 },
    },
  };

  const failedTestTool = {
    type: "tool",
    tool: "bash",
    state: {
      status: "completed",
      input: { command: "npm test" },
      output: "FAIL: 2 tests failed",
      metadata: { exit: 1 },
    },
  };

  const passedTestTool = {
    type: "tool",
    tool: "bash",
    state: {
      status: "completed",
      input: { command: "npm test" },
      output: "PASS: all 42 tests passed",
      metadata: { exit: 0 },
    },
  };

  const sourceReviewTool = {
    type: "tool",
    tool: "read_file",
    state: {
      status: "completed",
      input: { TargetFile: "/workspace/src/app.ts" },
      output: "1: export const x = 1;\n2: export const y = 2;",
      metadata: { exit: 0 },
    },
  };

  // -----------------------------------------------------------------------------
  // Suite 1: Canonical Task Policy Equivalence across Multi-Script Families
  // -----------------------------------------------------------------------------
  test("Suite 1: Canonical task contract produces identical task policy outcomes regardless of natural language source", () => {
    // Same normalized contract: iterativeReview=true, requiresSourceReview=true, requiredVerifications=["test"]
    const prompts = [
      // Structured machine directive (Language-neutral)
      '@guardian-task {"mode": "iterative-review", "review": "source", "verify": ["test"]}\nTask body',
      // English
      "Fix every bug and restart the full source review until no bugs remain. Run tests.",
      // Turkish
      "Her hata bulduğunda düzelt ve incelemeyi baştan başlat; hata kalmayana kadar devam et. Testleri çalıştır.",
      // Spanish (Latin script)
      "Cada vez que encuentres un error, corrígelo y vuelve a revisar todo el código desde el principio hasta que no queden errores. Ejecuta las pruebas.",
      // German (Germanic)
      "Wenn du einen Fehler findest, behebe ihn und beginne die Quellcode Prüfung von vorn, bis keine Fehler mehr übrig sind. Führe die Tests aus.",
      // Russian (Cyrillic)
      "После каждой найденной ошибки исправь её и начни проверку исходного кода заново, пока ошибок не останется. Запусти тесты.",
      // Arabic (Right-to-left Arabic script)
      "كلما وجدت خطأ أصلحه ثم أعد مراجعة الكود من البداية حتى لا تبقى أخطاء. شغل الاختبارات.",
      // Chinese (CJK script)
      "每发现一个错误就修复，然后从头重新检查源代码，直到没有错误。运行测试。",
    ];

    for (const prompt of prompts) {
      const turn = makeTurn(prompt, [fileMutation]);
      const contract = extractTaskContract(turn);
      assert.ok(contract, `Contract must be extracted for prompt: ${prompt.slice(0, 40)}`);
      assert.equal(contract.iterativeReview, true, `Iterative review must be true for: ${prompt.slice(0, 40)}`);
      assert.equal(contract.requiresSourceReview, true, `Source review must be true for: ${prompt.slice(0, 40)}`);
      assert.deepEqual(contract.requiredVerifications, ["test"], `Test verification must be required for: ${prompt.slice(0, 40)}`);

      const evidence = collectTurnEvidence(turn);
      const policy = evaluateTaskPolicy(contract, evidence);
      assert.equal(policy.review, "missing", `Review must be missing without read tool for: ${prompt.slice(0, 40)}`);
      assert.equal(policy.verifications[0]?.status, "unknown", `Verification must be unknown before test runs`);

      // Now with source review and passing tests
      const turnWithReview = makeTurn(prompt, [fileMutation, sourceReviewTool, passedTestTool]);
      const evidenceWithReview = collectTurnEvidence(turnWithReview);
      const policyWithReview = evaluateTaskPolicy(contract, evidenceWithReview);
      assert.equal(policyWithReview.review, "observed", `Review observed after read tool for: ${prompt.slice(0, 40)}`);
      assert.equal(policyWithReview.verifications[0]?.status, "passed", `Test verification passed for: ${prompt.slice(0, 40)}`);
    }
  });

  // -----------------------------------------------------------------------------
  // Suite 2: Unknown Language Fail-Safe Behavior
  // -----------------------------------------------------------------------------
  test("Suite 2A: Unknown/unsupported language prompt does not invent duties or crash", () => {
    const unknownPrompts = [
      "Jambo rafiki, tafadhali rekebisha hitilafu kwenye mfumo huu.", // Swahili
      "Γεια σας, παρακαλώ ελέγξτε τη λειτουργία της εφαρμογής.", // Greek
      "Halo kawan, mangga pariksa kode ieu.", // Sundanese
      "Vartotojo sąsaja neveikia tinkamai, prašome pataisyti.", // Lithuanian
      "xyzzy plink bloop zorblax flimflam 12345.", // Synthetic gibberish
    ];

    for (const prompt of unknownPrompts) {
      const turn = makeTurn(prompt, [{ type: "text", text: "Working on it." }]);
      const contract = extractTaskContract(turn);
      assert.ok(contract, `Contract object should exist for: ${prompt}`);
      // MUST FAIL SAFE: never invent iterativeReview, never invent required verifications
      assert.equal(contract.iterativeReview, false, `Must NOT invent iterativeReview for unknown language: ${prompt}`);
      assert.deepEqual(contract.requiredVerifications, [], `Must NOT invent verifications for unknown language: ${prompt}`);
      assert.equal(contract.requiresExplicitCompletion, false, `Must NOT require explicit completion: ${prompt}`);
    }
  });

  test("Suite 2B: Assistant blocker report in unsupported language must fail-safe for read-only agents and block for write-capable agents", () => {
    // Structured directive requests review
    const prompt = '@guardian-task {"mode": "iterative-review", "review": "checks", "verify": ["test"]}\nWork';
    // Assistant is BLOCKED in an unsupported language (e.g. Polish, Greek, Czech, Swedish)
    // When a read-only subagent encounters a failed command or states a blocker, Guardian must not loop!
    const polishBlockerTurn = makeTurn(prompt, [
      fileMutation,
      failedTestTool,
      { type: "text", text: "Nie mogę kontynuować pracy. Brak uprawnień do bazy danych i testy nie przechodzą." },
    ]);

    const readOnlyResult = taskCompletionRule.inspect({
      sessionID: "polish-blocker-session",
      directory: process.cwd(),
      messages: polishBlockerTurn,
      currentTurn: polishBlockerTurn,
      isSubagent: true,
      agentCapability: "read-only",
      ruleConfig: {},
      evidence: collectTurnEvidence(polishBlockerTurn),
    });

    // Read-only subagents reporting failure fail-safe to pass without synthetic retry loop
    assert.equal(readOnlyResult.decision, "pass", "Read-only agent blocker with failed tool must fail-safe to pass (no synthetic loop)");

    // Write-capable agents with concrete failed test checks cannot bypass completion gate with an early pass
    const writeCapableResult = taskCompletionRule.inspect({
      sessionID: "polish-blocker-write-session",
      directory: process.cwd(),
      messages: polishBlockerTurn,
      currentTurn: polishBlockerTurn,
      ruleConfig: {},
      evidence: collectTurnEvidence(polishBlockerTurn),
    });
    assert.equal(writeCapableResult.decision, "block", "Write-capable agent with failed test verification must block and remediate");
  });

  // -----------------------------------------------------------------------------
  // Suite 3: Language-Neutral Completion Evidence vs Natural Language Dependency
  // -----------------------------------------------------------------------------
  test("Suite 3A: Completion gate detects missing review from evidence and lifecycle without requiring English/Turkish 'finished' words", () => {
    const prompt = '@guardian-task {"mode": "iterative-review", "review": "source", "verify": []}\nWork';
    // Assistant changed a file, did NOT perform a post-mutation source review, and provided arbitrary output without English/Turkish 'finished'
    const turn = makeTurn(prompt, [
      fileMutation,
      { type: "text", text: "Klaar met de wijzigingen. Hier zijn de details van de update." }, // Dutch (not in CLOSING or REPORT_TERMS)
    ]);

    const result = taskCompletionRule.inspect({
      sessionID: "lifecycle-missing-review",
      directory: process.cwd(),
      messages: turn,
      currentTurn: turn,
      ruleConfig: {},
      evidence: collectTurnEvidence(turn),
    });

    // Missing source review after code change under iterative review contract must be blocked by concrete evidence,
    // regardless of what language the assistant used!
    assert.equal(result.decision, "block", "Missing post-mutation review must be caught even with non-English/Turkish text");
    assert.ok(result.findings.some((f) => f.pattern.includes("iteration ended after a change")), "Must report missing review finding");
  });

  test("Suite 3B: Localized completion claim contradicting a failed test blocks across script families", () => {
    const localizedCompletions = [
      { lang: "German", text: "Aufgabe abgeschlossen. Alle Änderungen wurden durchgeführt." },
      { lang: "Russian", text: "Задача завершена. Все правки внесены." },
      { lang: "Arabic", text: "تم إنجاز المهمة. تم تطبيق التغييرات بنجاح." },
      { lang: "Japanese", text: "作業完了。修正が完了しました。" },
      { lang: "Turkish", text: "İnceleme tamamlandı, iş bitti." },
      { lang: "English", text: "Task completed, all tests verified." },
    ];

    for (const { lang, text } of localizedCompletions) {
      const prompt = '@guardian-task {"mode": "one-pass", "review": "checks", "verify": ["test"]}\nWork';
      const turn = makeTurn(prompt, [
        fileMutation,
        failedTestTool,
        { type: "text", text },
      ]);

      const result = taskCompletionRule.inspect({
        sessionID: `failed-test-${lang}`,
        directory: process.cwd(),
        messages: turn,
        currentTurn: turn,
        ruleConfig: {},
        evidence: collectTurnEvidence(turn),
      });

      assert.equal(result.decision, "block", `Failed test tool evidence with completion claim in ${lang} must be blocked`);
      assert.ok(result.findings.some((f) => f.pattern.includes("test verification not confirmed")), `Must report failed test finding for ${lang}`);
    }
  });


  // -----------------------------------------------------------------------------
  // Suite 4: Read-Only Subagent Zero Remediation in Arbitrary Languages
  // -----------------------------------------------------------------------------
  test("Suite 4: Read-only subagent output in various languages receives 0 synthetic remediation", async () => {
    const multilingualOutputs = [
      { lang: "Turkish", text: "İnceleme tamamlandı. Herhangi bir güvenlik açığı bulunamadı." },
      { lang: "English", text: "Review completed. No vulnerabilities identified." },
      { lang: "Japanese", text: "レビューが完了しました。脆弱性は検出されませんでした。" },
      { lang: "Arabic", text: "اكتملت المراجعة. لم يتم العثور على أي ثغرات أمنية." },
      { lang: "Greek", text: "Η αξιολόγηση ολοκληρώθηκε. Δεν εντοπίστηκαν ευπάθειες." },
      { lang: "Czech", text: "Kontrola byla dokončena. Nebyly nalezeny žádné chyby." },
    ];

    for (const { lang, text } of multilingualOutputs) {
      let syntheticCalls = 0;
      const hooks = new Map();
      const cleanup = await OpencodeGuardian.setup({
        location: { directory: process.cwd() },
        options: { secrets: { enabled: false } },
        event: { subscribe: () => (async function* () {})() },
        tool: {
          hook: async (name, handler) => {
            hooks.set(name, handler);
            return { dispose() {} };
          },
        },
        session: {
          get: async ({ sessionID }) => ({
            id: sessionID,
            parentID: sessionID.startsWith("child-") ? "parent-root" : undefined,
          }),
          context: async () => [
            { id: "u-sub", type: "user", text: "Audit the codebase thoroughly." },
            { id: "a-sub", type: "assistant", agent: "auditor", content: [{ type: "text", text }] },
          ],
          synthetic: async () => { syntheticCalls++; },
          wait: async () => {},
        },
        agent: {
          list: async () => [{
            name: "auditor",
            permission: [
              { permission: "edit", pattern: "*", action: "deny" },
              { permission: "bash", pattern: "*", action: "deny" },
            ],
          }],
        },
      });

      await hooks.get("execute.before")?.({
        tool: "task",
        sessionID: "parent-root",
        callID: `call-${lang}`,
        input: { agent: "auditor", prompt: "audit" },
      });

      const result = {
        output: text,
        metadata: { sessionId: `child-${lang}`, background: false },
      };

      await hooks.get("execute.after")({
        tool: "task",
        sessionID: "parent-root",
        callID: `call-${lang}`,
        input: { agent: "auditor" },
        result,
      });
      await cleanup();

      assert.equal(syntheticCalls, 0, `Read-only auditor in ${lang} must receive 0 synthetic prompts`);
      assert.match(result.output, new RegExp(text), `Output in ${lang} must be preserved intact`);
    }
  });
});

describe("Multilingual Task Constraints", () => {
  const SAMPLES = [
    {
      locale: "es",
      loop: "Cada vez que encuentres un error, corrígelo y vuelve a revisar todo desde el principio hasta que no queden errores.",
      negative: "Cada vez que encuentres un error, corrige el error, pero no repitas la revisión.",
      test: "Ejecuta las pruebas.",
    },
    {
      locale: "pt",
      loop: "Sempre que encontrar um erro, corrija-o e reinicie a revisão desde o início até não haver erros.",
      negative: "Sempre que encontrar um erro, corrija-o, mas não repita a revisão.",
      test: "Execute os testes.",
    },
    {
      locale: "fr",
      loop: "À chaque erreur trouvée, corrige-la et recommence la revue depuis le début jusqu’à la fin.",
      negative: "À chaque erreur trouvée, corrige-la mais ne répète pas la revue.",
      test: "Exécute les tests.",
    },
    {
      locale: "de",
      loop: "Wenn du einen Fehler findest, behebe ihn und beginne die Prüfung von vorn, bis keine Fehler mehr übrig sind.",
      negative: "Immer wenn du einen Fehler findest, behebe ihn, aber wiederhole die Prüfung nicht.",
      test: "Führe die Tests aus.",
    },
    {
      locale: "ru",
      loop: "После каждой найденной ошибки исправь её и начни проверку заново, пока ошибок не останется.",
      negative: "После каждой ошибки исправь её, но не начинай проверку заново.",
      test: "Запусти тесты.",
    },
    {
      locale: "ar",
      loop: "كلما وجدت خطأ أصلحه ثم أعد المراجعة من البداية حتى لا تبقى أخطاء.",
      negative: "كلما وجدت خطأ أصلحه ولكن لا تكرر المراجعة من البداية.",
      test: "شغل الاختبارات.",
    },
    {
      locale: "hi",
      loop: "हर गलती मिलने पर उसे ठीक करो और जब तक कोई गलती न बचे जाँच फिर से शुरू करो।",
      negative: "हर गलती मिलने पर ठीक करो, लेकिन दोबारा मत शुरू करो, जाँच करो।",
      test: "टेस्ट चलाओ।",
    },
    {
      locale: "zh",
      loop: "每发现一个错误就修复，然后从头重新检查，直到没有错误。",
      negative: "每发现一个错误就修复，但不要重复检查。",
      test: "运行测试。",
    },
    {
      locale: "ja",
      loop: "エラーを見つけるたびに修正し、問題がなくなるまで最初から再レビューしてください。",
      negative: "エラーを見つけるたびに修正しますが、繰り返さないでレビューしてください。",
      test: "テストを実行してください。",
    },
    {
      locale: "ko",
      loop: "오류를 찾을 때마다 수정하고 문제가 없을 때까지 처음부터 다시 검토해.",
      negative: "오류를 찾을 때마다 수정하지만 다시 하지 마, 검토는 한 번만 해.",
      test: "테스트 실행.",
    },
    {
      locale: "id",
      loop: "Setiap kali menemukan kesalahan, perbaiki lalu ulangi pemeriksaan dari awal sampai tidak ada kesalahan.",
      negative: "Setiap kali menemukan kesalahan, perbaiki, tapi jangan ulangi pemeriksaan.",
      test: "Jalankan tes.",
    },
  ];

  function contract(text) {
    return extractTaskContract([{ info: { id: "human", role: "user" }, parts: [{ type: "text", text }] }]);
  }

  test("international signal packs have unique stable locale identifiers", () => {
    assert.deepEqual(SUPPORTED_SIGNAL_LOCALES, SAMPLES.map((s) => s.locale));
    assert.equal(new Set(SUPPORTED_SIGNAL_LOCALES).size, SAMPLES.length);
  });

  for (const sample of SAMPLES) {
    test(`${sample.locale}: explicit iterative source review becomes canonical contract`, () => {
      const intent = extractInternationalSignals(sample.loop);
      assert.equal(intent?.locale, sample.locale, JSON.stringify(intent));
      assert.equal(intent?.iterativeReview, true);
      assert.equal(intent?.requiresSourceReview, true);
      assert.deepEqual(intent?.evidence, ["action", "review", "issue", "iteration"]);
      const task = contract(sample.loop);
      assert.equal(task.iterativeReview, true);
      assert.equal(task.requiresSourceReview, true);
      assert.equal(task.signalLocale, sample.locale);
    });

    test(`${sample.locale}: explicit no-repeat instruction does not invent a review loop`, () => {
      const task = contract(sample.negative);
      assert.equal(task.iterativeReview, false, sample.negative);
    });

    test(`${sample.locale}: explicit test request becomes language-neutral test verification`, () => {
      const task = contract(sample.test);
      assert.deepEqual(task.requiredVerifications, ["test"], sample.test);
      assert.equal(task.iterativeReview, false);
    });
  }

  test("unrecognized languages or unclear phrasing fail open without fabricated task requirements", () => {
    for (const text of [
      "Επανέλαβε τον έλεγχο μετά τη διόρθωση.",
      "Revisar?",
      "¿Qué pasaría si revisamos y corregimos errores cada vez?",
      "如果发现错误就修复，然后重新检查会怎么样？",
      "أريد معرفة كيفية مراجعة الأخطاء، لا تنفذ أي شيء.",
    ]) {
      assert.equal(contract(text).iterativeReview, false, text);
    }
  });

  test("international extractor remains deterministic and does not modify user text", () => {
    for (const sample of SAMPLES) {
      const before = sample.loop;
      const first = extractInternationalSignals(before);
      const second = extractInternationalSignals(before);
      assert.deepEqual(first, second);
      assert.equal(sample.loop, before);
    }
  });

  const REPORTS = [
    ["es", "Implementa la función.", "No ejecuta las pruebas.", "Tarea completada.", "No puedo continuar.", "Trabajo en curso."],
    ["pt", "Implemente a função.", "Não execute os testes.", "Tarefa concluída.", "Não consigo continuar.", "Trabalho em andamento."],
    ["fr", "Implémente la fonctionnalité.", "N’exécute pas les tests.", "Tâche terminée.", "Je ne peux pas continuer.", "Travail en cours."],
    ["de", "Implementiere die Funktion.", "Führe die Tests nicht aus.", "Aufgabe abgeschlossen.", "Kann nicht fortfahren.", "In Bearbeitung."],
    ["ru", "Реализуй функцию.", "Не запускай тесты.", "Задача завершена.", "Не могу продолжать.", "В процессе."],
    ["ar", "نفذ الميزة.", "لا تشغل الاختبارات.", "تم إنجاز المهمة.", "لا أستطيع المتابعة.", "قيد التنفيذ."],
    ["hi", "लागू करो।", "टेस्ट मत चलाओ।", "काम पूरा हो गया।", "आगे नहीं बढ़ सकता।", "काम जारी है।"],
    ["zh", "实现功能。", "不要运行测试。", "任务已完成。", "无法继续。", "处理中。"],
    ["ja", "機能を実装してください。", "テストを実行しないでください。", "作業完了。", "続行できません。", "進行中。"],
    ["ko", "기능을 구현해 주세요.", "테스트 실행하지 마.", "작업 완료.", "계속할 수 없습니다.", "진행 중."],
    ["id", "Implementasikan fitur.", "Jangan jalankan tes.", "Tugas selesai.", "Tidak bisa melanjutkan.", "Sedang berlangsung."],
  ];

  for (const [locale, action, forbiddenTest, complete, blocked, inProgress] of REPORTS) {
    test(`${locale}: direct action keeps language-independent latest-instruction guidance`, () => {
      const task = contract(action);
      assert.equal(task.explicitAction, true, action);
      assert.equal(task.signalLocale, locale, action);
      assert.equal(task.iterativeReview, false);
    });

    test(`${locale}: forbidden test is not converted into a required verification`, () => {
      const task = contract(forbiddenTest);
      assert.deepEqual(task.requiredVerifications, [], forbiddenTest);
    });

    test(`${locale}: completion, blocker and in-progress are distinct reporting states`, () => {
      assert.equal(classifyInternationalAgentReport(complete), "completed", complete);
      assert.equal(classifyInternationalAgentReport(blocked), "blocked", blocked);
      assert.equal(classifyInternationalAgentReport(inProgress), "in-progress", inProgress);
    });

    test(`${locale}: failed requested tests contradict a localized completion report`, () => {
      const request = SAMPLES.find((s) => s.locale === locale).test;
      const currentTurn = [
        { info: { id: "human", role: "user" }, parts: [{ type: "text", text: request }] },
        { info: { id: "agent", role: "assistant" }, parts: [
          {
            type: "tool", tool: "bash", state: {
              status: "completed", input: { command: "npm test" },
              output: "Tests failed", metadata: { exit: 1 },
            },
          },
          { type: "text", text: complete },
        ] },
      ];
      const result = taskCompletionRule.inspect({
        sessionID: `status-${locale}`, directory: process.cwd(),
        messages: currentTurn, currentTurn, ruleConfig: {},
        evidence: collectTurnEvidence(currentTurn),
      });
      assert.equal(result.decision, "block", complete);
      assert.ok(result.findings.some((f) => f.confidence === "high"));
    });

    test(`${locale}: explicit blocker does not create an automatic debug loop`, () => {
      const request = SAMPLES.find((s) => s.locale === locale).loop;
      const currentTurn = [
        { info: { id: "human", role: "user" }, parts: [{ type: "text", text: request }] },
        { info: { id: "agent", role: "assistant" }, parts: [
          { type: "tool", tool: "write", state: {
            status: "completed", input: { filePath: "src/example.ts", content: "export const ok = true;" },
          } },
          { type: "text", text: blocked },
        ] },
      ];
      const result = taskCompletionRule.inspect({
        sessionID: `blocker-${locale}`, directory: process.cwd(),
        messages: currentTurn, currentTurn, ruleConfig: {},
        evidence: collectTurnEvidence(currentTurn),
      });
      assert.equal(result.decision, "pass", blocked);
    });
  }

  const HISTORICAL = [
    "Lo habías pausado antes, por eso no lo haré.",
    "Você havia pausado antes, por isso não vou fazer.",
    "Tu l'avais suspendu auparavant, donc je ne le ferai pas.",
    "Du hattest es zuvor pausiert, deshalb werde ich es nicht umsetzen.",
    "Вы ранее приостановили задачу, поэтому я не буду её выполнять.",
    "لقد أوقفت المهمة سابقاً ولذلك لن أنفذها.",
    "आपने पहले इस काम को रोक दिया था, इसलिए मैं इसे नहीं करूँगा।",
    "你之前暂停了这个功能，所以我不会实现它。",
    "以前この機能を保留したので、実装しません。",
    "이전에 이 기능을 중단했으므로 구현하지 않겠습니다.",
    "Fitur ini sebelumnya ditunda, jadi saya tidak akan mengimplementasikannya.",
  ];

  for (const [index, [locale, request, forbiddenTest]] of REPORTS.entries()) {
    test(`${locale}: refusal because of historical suspension contradicts the new explicit task`, async () => {
      const { instructionFidelityRule } = await import("../dist/rules/instruction-fidelity.js");
      const currentTurn = [
        { info: { id: "human", role: "user" }, parts: [{ type: "text", text: request }] },
        { info: { id: "agent", role: "assistant" }, parts: [{ type: "text", text: HISTORICAL[index] }] },
      ];
      const result = instructionFidelityRule.inspect({
        sessionID: `history-${locale}`, directory: process.cwd(),
        messages: currentTurn, currentTurn, ruleConfig: {},
        evidence: collectTurnEvidence(currentTurn),
      });
      assert.equal(result.decision, "block", HISTORICAL[index]);
      assert.equal(result.findings[0].confidence, "high");

      currentTurn[0].parts[0].text = forbiddenTest;
      assert.equal(
        instructionFidelityRule.inspect({
          sessionID: `history-forbidden-${locale}`, directory: process.cwd(),
          messages: currentTurn, currentTurn, ruleConfig: {},
          evidence: collectTurnEvidence(currentTurn),
        }).decision,
        "pass",
        "an explicit prohibition must not be reinterpreted as permission"
      );
    });
  }

  test("multilingual historical refusal blocks even when relevant file work was observed", async () => {
    const { instructionFidelityRule } = await import("../dist/rules/instruction-fidelity.js");
    const currentTurn = [
      { info: { id: "human", role: "user" }, parts: [{ type: "text", text: REPORTS[0][1] }] },
      { info: { id: "agent", role: "assistant" }, parts: [
        { type: "tool", tool: "write", state: {
          status: "completed", input: { filePath: "src/feature.ts", content: "export const ok = true;" },
          metadata: { exit: 0 },
        } },
        { type: "text", text: HISTORICAL[0] },
      ] },
    ];
    const result = instructionFidelityRule.inspect({
      sessionID: "history-advisory", directory: process.cwd(),
      messages: currentTurn, currentTurn, ruleConfig: {},
      evidence: collectTurnEvidence(currentTurn),
    });
    assert.equal(result.decision, "block");
    assert.equal(result.findings[0].confidence, "high");
  });

  test("quoted foreign-language examples cannot silently become the user's task", () => {
    for (const sample of SAMPLES) {
      const quoted = `Explain this sentence: “${sample.loop}”`;
      const task = contract(quoted);
      assert.equal(task.iterativeReview, false, sample.locale);
      assert.deepEqual(task.requiredVerifications, [], sample.locale);
      const codeSample = `Explain the example in this code block:\n\x60\x60\x60text\n${sample.test}\n\x60\x60\x60`;
      assert.deepEqual(contract(codeSample).requiredVerifications, [], sample.locale);
    }
  });

  test("inline commands and blockquoted snippets are not unrequested verification obligations", () => {
    const examples = [
      "Please explain the command \x60npm test\x60 instead of executing it.",
      "> Ejecuta las pruebas.\n\nExplain the quoted instruction.",
      "请解释「运行测试」这句话。",
      "Explain the string “テストを実行してください” without running it.",
    ];
    for (const sample of examples) {
      const task = contract(sample);
      assert.deepEqual(task.requiredVerifications, [], sample);
      assert.equal(task.iterativeReview, false, sample);
    }
  });
});

describe("International Adapter Behavior", () => {
  const ZH = "每发现一个错误就修复，然后从头重新检查，直到没有错误。";
  const CODE = "export const done = true;";

  function previousFix() {
    return { type: "tool", tool: "write", state: {
      status: "completed", input: { filePath: "src/feature.ts", content: CODE },
      metadata: { exit: 0 },
    } };
  }

  test("OpenCode V2 typed prompt/context and idle path preserve Chinese task requirements", async () => {
    const handlers = new Map();
    const issued = [];
    let releaseEvent;
    const context = {
      location: { directory: process.cwd() },
      options: { secrets: { enabled: false } },
      event: {
        subscribe({ signal }) {
          return (async function* () {
            await new Promise((resolve) => { releaseEvent = resolve; });
            yield { type: "session.idle", data: { sessionID: "chinese-task" } };
            await new Promise((resolve) => {
              if (signal.aborted) resolve();
              else signal.addEventListener("abort", resolve, { once: true });
            });
          })();
        },
      },
      session: {
        async hook(name, callback) {
          handlers.set(name, callback);
          return { async dispose() {} };
        },
        async get() { return { location: { directory: process.cwd() } }; },
        async context() {
          return [
            { id: "user-zh", type: "user", text: ZH },
            { id: "agent-zh", type: "assistant", agent: "orchestrator", content: [
              { type: "tool", name: "write", state: previousFix().state },
              { type: "text", text: "任务已完成。" },
            ] },
          ];
        },
        async synthetic(input) { issued.push(input); return {}; },
      },
    };
    const cleanup = await Guardian.setup(context);
    assert.equal(typeof handlers.get("prompt"), "function");
    assert.equal(typeof handlers.get("context"), "function");
    await handlers.get("prompt")({
      sessionID: "chinese-task", messageID: "user-zh",
      prompt: { text: ZH }, delivery: "queue",
    });
    const output = { sessionID: "chinese-task", system: [], tools: {} };
    await handlers.get("context")(output);
    assert.match(output.system[0].text, /another review pass/);
    for (let i = 0; i < 50 && !releaseEvent; i++) {
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    assert.equal(typeof releaseEvent, "function");
    releaseEvent();
    for (let i = 0; i < 50 && issued.length === 0; i++) {
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    assert.equal(issued.length, 1);
    assert.equal(issued[0].delivery, "queue");
    assert.equal(issued[0].resume, true);
    assert.match(issued[0].text, /another substantive review/);
    await cleanup();
  });
});
