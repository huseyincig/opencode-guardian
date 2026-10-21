import test from "node:test";
import assert from "node:assert/strict";
import { taskCompletionRule } from "../dist/rules/task-completion.js";
import { classifyAgentReport } from "../dist/locale-intents.js";
import { collectTurnEvidence } from "../dist/evidence.js";

test("classifyAgentReport accurately identifies Turkish and English in-progress statements", () => {
  const inProgressPhrases = [
    "işlem devam ediyor, ortamı inceliyorum",
    "İşlemler devam ediyor; test adımlarına geçiyorum.",
    "çalışmaya devam ediyorum, 1. dosya tamamlandı",
    "Çalışma devam ediyor.",
    "devam ediyorum, hata analizi yapıyorum",
    "İşlemler sürüyor.",
    "Şu anda dosyayı inceliyorum ve hazırlıyorum.",
    "Görev Fixer oturumuna devredildi.",
    "İlgili alt ajana aktarıldı.",
    "Ara rapor: ilk aşama tamamlandı, devam edilecek.",
    "Durum güncellemesi: testler hazırlanıyor.",
    "İlerleme raporu: 3/5 adım tamamlandı.",
    "work in progress: investigating failures",
    "in progress: step 1 complete, moving to step 2",
    "Processing dependencies and continuing tests.",
    "Working on it, still analyzing logs.",
  ];

  for (const phrase of inProgressPhrases) {
    const report = classifyAgentReport(phrase);
    assert.equal(report.isInProgress, true, `Should detect in-progress for: "${phrase}"`);
    assert.equal(report.isClosing, false, `Should not be closing for: "${phrase}"`);
    assert.equal(report.state, "in-progress", `State should be in-progress for: "${phrase}"`);
  }
});

test("classifyAgentReport accurately identifies multilingual in-progress statements across all supported non-English/Turkish languages", () => {
  const multilingualPhrases = [
    { lang: "Spanish", text: "Trabajo en curso: revisando los archivos del proyecto." },
    { lang: "Portuguese", text: "Trabalho em andamento: preparando os testes unitários." },
    { lang: "French", text: "Travail en cours: exécution des étapes intermédiaires." },
    { lang: "German", text: "In Bearbeitung: behebe den ersten Fehler." },
    { lang: "Russian", text: "Работа продолжается: изучаю исходный код." },
    { lang: "Arabic", text: "العمل جار: جاري التحقق من التغييرات." },
    { lang: "Hindi", text: "काम जारी है: त्रुटियों का विश्लेषण किया जा रहा है।" },
    { lang: "Chinese", text: "处理中：正在修复发现的问题。" },
    { lang: "Japanese", text: "進行中：テストケースを分析しています。" },
    { lang: "Korean", text: "작업 진행 중: 변경 사항을 적용하고 있습니다." },
    { lang: "Indonesian", text: "Sedang dikerjakan: memeriksa berkas dan konfigurasi." },
  ];

  for (const { lang, text } of multilingualPhrases) {
    const report = classifyAgentReport(text);
    assert.equal(report.isInProgress, true, `Should detect in-progress for ${lang}: "${text}"`);
    assert.equal(report.isClosing, false, `Should not be closing for ${lang}: "${text}"`);
    assert.equal(report.state, "in-progress", `State should be in-progress for ${lang}: "${text}"`);
  }
});

test("subagent reporting 'işlem devam ediyor' with intermediate tool failure does NOT block on completion gate", async () => {
  const turn = [
    {
      info: { id: "u-brief", role: "user" },
      parts: [{ type: "text", text: "Fix the bug and run tests before finishing." }],
    },
    {
      info: { id: "a-prog", role: "assistant", agent: "fixer" },
      parts: [
        {
          type: "tool",
          tool: "bash",
          state: {
            status: "completed",
            input: { command: "npm test" },
            exitCode: 1,
            output: "FAIL: 1 of 5 tests failed",
          },
        },
        {
          type: "text",
          text: "İşlem devam ediyor; başarısız olan testi tespit ettim, düzeltme üzerinde çalışıyorum.",
        },
      ],
    },
  ];

  const result = await taskCompletionRule.inspect({
    sessionID: "subagent-prog-1",
    directory: process.cwd(),
    messages: turn,
    currentTurn: turn,
    isSubagent: true,
    agentCapability: "write-allowed",
    ruleConfig: {},
    evidence: collectTurnEvidence(turn),
  });

  assert.equal(result.decision, "pass", "Subagent reporting ongoing work must pass completion gate");
});

test("subagent reporting intermediate findings without claiming completion does NOT block on completion gate", async () => {
  const turn = [
    {
      info: { id: "u-brief", role: "user" },
      parts: [{ type: "text", text: "Run typecheck and fix any errors." }],
    },
    {
      info: { id: "a-prog", role: "assistant", agent: "fixer" },
      parts: [
        {
          type: "tool",
          tool: "write",
          state: {
            status: "completed",
            input: { filePath: "src/file.ts", content: "export const x = 1;" },
          },
        },
        {
          type: "text",
          text: "Gerekli dosya değişikliğini uyguladım. Şimdi tip denetimini koşturacağım.",
        },
      ],
    },
  ];

  const result = await taskCompletionRule.inspect({
    sessionID: "subagent-prog-2",
    directory: process.cwd(),
    messages: turn,
    currentTurn: turn,
    isSubagent: true,
    agentCapability: "write-allowed",
    ruleConfig: {},
    evidence: collectTurnEvidence(turn),
  });

  assert.equal(result.decision, "pass", "Subagent in intermediate step must pass completion gate");
});

test("root agent delegating to subagent ('devredildi') does NOT block on completion gate", async () => {
  const turn = [
    {
      info: { id: "u-root", role: "user" },
      parts: [{ type: "text", text: "Fix the build and spec validation." }],
    },
    {
      info: { id: "a-root", role: "assistant", agent: "orchestrator" },
      parts: [
        {
          type: "tool",
          tool: "bash",
          state: {
            status: "completed",
            input: { command: "npm run build" },
            exitCode: 1,
            output: "Build error in apps/cli",
          },
        },
        {
          type: "text",
          text: "Onaylı macOS CLI düzeltmesi mevcut Fixer oturumuna devredildi. Tamamlandığında odaklı testleri ve izole aday kanıtlarını uzlaştıracağım.",
        },
      ],
    },
  ];

  const result = await taskCompletionRule.inspect({
    sessionID: "root-delegation-1",
    directory: process.cwd(),
    messages: turn,
    currentTurn: turn,
    isSubagent: false,
    agentCapability: "write-allowed",
    ruleConfig: {},
    evidence: collectTurnEvidence(turn),
  });

  assert.equal(result.decision, "pass", "Root agent delegating to subagent must pass completion gate");
});

test("subagent claiming completion ('iş bitti') with unresolved failure DOES block on completion gate", async () => {
  const turn = [
    {
      info: { id: "u-brief", role: "user" },
      parts: [{ type: "text", text: "Fix the bug and verify tests." }],
    },
    {
      info: { id: "a-done", role: "assistant", agent: "fixer" },
      parts: [
        {
          type: "tool",
          tool: "bash",
          state: {
            status: "completed",
            input: { command: "npm test" },
            exitCode: 1,
            output: "FAIL: 1 test failed",
          },
        },
        {
          type: "text",
          text: "Tüm geliştirmeler tamamlandı, iş bitti.",
        },
      ],
    },
  ];

  const result = await taskCompletionRule.inspect({
    sessionID: "subagent-claim-done",
    directory: process.cwd(),
    messages: turn,
    currentTurn: turn,
    isSubagent: true,
    agentCapability: "write-allowed",
    ruleConfig: {},
    evidence: collectTurnEvidence(turn),
  });

  assert.equal(result.decision, "block", "Subagent claiming completion while tests fail must block");
  assert.ok(result.findings.some((f) => f.ruleId === "task/completion-gate"));
});
