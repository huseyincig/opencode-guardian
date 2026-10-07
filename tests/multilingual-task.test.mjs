import test from "node:test";
import assert from "node:assert/strict";
import {
  extractInternationalSignals,
  SUPPORTED_SIGNAL_LOCALES,
  classifyInternationalAgentReport,
} from "../dist/locale-intents.js";
import { taskCompletionRule } from "../dist/rules/task-completion.js";
import { collectTurnEvidence } from "../dist/evidence.js";
import { extractTaskContract } from "../dist/task-contract.js";

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
  ["es", "Implementa la función.", "No ejecuta las pruebas.", "Tarea completada.", "No puedo continuar."],
  ["pt", "Implemente a função.", "Não execute os testes.", "Tarefa concluída.", "Não consigo continuar."],
  ["fr", "Implémente la fonctionnalité.", "N’exécute pas les tests.", "Tâche terminée.", "Je ne peux pas continuer."],
  ["de", "Implementiere die Funktion.", "Führe die Tests nicht aus.", "Aufgabe abgeschlossen.", "Kann nicht fortfahren."],
  ["ru", "Реализуй функцию.", "Не запускай тесты.", "Задача завершена.", "Не могу продолжать."],
  ["ar", "نفذ الميزة.", "لا تشغل الاختبارات.", "تم إنجاز المهمة.", "لا أستطيع المتابعة."],
  ["hi", "लागू करो।", "टेस्ट मत चलाओ।", "काम पूरा हो गया।", "आगे नहीं बढ़ सकता।"],
  ["zh", "实现功能。", "不要运行测试。", "任务已完成。", "无法继续。"],
  ["ja", "機能を実装してください。", "テストを実行しないでください。", "作業完了。", "続行できません。"],
  ["ko", "기능을 구현해 주세요.", "테스트 실행하지 마.", "작업 완료.", "계속할 수 없습니다."],
  ["id", "Implementasikan fitur.", "Jangan jalankan tes.", "Tugas selesai.", "Tidak bisa melanjutkan."],
];

for (const [locale, action, forbiddenTest, complete, blocked] of REPORTS) {
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

  test(`${locale}: completion and blocker are distinct reporting states`, () => {
    assert.equal(classifyInternationalAgentReport(complete), "completed", complete);
    assert.equal(classifyInternationalAgentReport(blocked), "blocked", blocked);
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
