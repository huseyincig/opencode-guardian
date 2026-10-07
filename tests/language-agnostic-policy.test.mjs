import test from "node:test";
import assert from "node:assert/strict";
import { extractTaskContract } from "../dist/task-contract.js";
import { collectTurnEvidence } from "../dist/evidence.js";
import { evaluateTaskPolicy } from "../dist/task-policy.js";
import { taskCompletionRule } from "../dist/rules/task-completion.js";
import { OpencodeGuardian } from "../dist/index.js";

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
    const client = {
      session: {
        get: async () => ({ data: { id: `child-${lang}`, parentID: "parent-root" } }),
        messages: async () => ({
          data: [
            { info: { id: "u-sub", role: "user" }, parts: [{ type: "text", text: "Audit the codebase thoroughly." }] },
            { info: { id: "a-sub", role: "assistant", agent: "auditor" }, parts: [{ type: "text", text }] },
          ],
        }),
        prompt: async () => { syntheticCalls++; return { data: {} }; },
        promptAsync: async () => { syntheticCalls++; return { data: {} }; },
      },
      app: {
        agents: async () => ({
          data: [{
            name: "auditor",
            permission: { edit: "deny", bash: "deny" },
            tools: { read_file: true, grep: true },
          }],
        }),
      },
    };

    const plugin = await OpencodeGuardian.server({ client, directory: process.cwd() });
    await plugin["tool.execute.before"](
      { tool: "task", sessionID: "parent-root", callID: `call-${lang}` },
      { args: { agent: "auditor", prompt: "audit" } }
    );

    const output = {
      output: text,
      metadata: { sessionId: `child-${lang}`, background: false },
    };

    await plugin["tool.execute.after"](
      { tool: "task", sessionID: "parent-root", callID: `call-${lang}`, args: { agent: "auditor" } },
      output
    );
    await plugin.dispose();

    assert.equal(syntheticCalls, 0, `Read-only auditor in ${lang} must receive 0 synthetic prompts`);
    assert.match(output.output, new RegExp(text), `Output in ${lang} must be preserved intact`);
  }
});
