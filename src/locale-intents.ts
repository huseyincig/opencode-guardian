/**
 * Multilingual signals only; never a safety-policy decision by themselves.
 * Tasks, permissions, and verification outcomes are evaluated through the
 * same language-neutral contract/evidence engine regardless of locale.
 *
 * The terms here intentionally target explicit, high-confidence instructions.
 * An unknown dialect, paraphrase, or ambiguous request returns no new duty;
 * the original user request is still passed to the agent unmodified.
 */
export type VerificationKind = "test" | "build" | "typecheck" | "lint" | "audit";

interface LocaleSignals {
  readonly locale: string;
  readonly action: readonly string[];
  readonly review: readonly string[];
  readonly iteration: readonly string[];
  readonly issue: readonly string[];
  readonly source: readonly string[];
  readonly negativeIteration: readonly string[];
  readonly hypothetical: readonly string[];
  readonly tests: readonly string[];
  readonly negativeTests: readonly string[];
  readonly negativeAction: readonly string[];
}

// A trailing * means a prefix match for an inflected verb (not a regex).
// Multiword phrases are matched as complete Unicode word sequences.
const LOCALES: readonly LocaleSignals[] = [
  {
    locale: "es", action: ["corrige*", "corríg*", "arregla*", "repara*", "implementa", "desarrolla*", "haz", "ejecuta*", "realiza*"],
    review: ["revisa*", "revisión", "inspecciona*", "auditoría", "comprueba*"],
    iteration: ["cada vez", "hasta que", "de nuevo", "otra vez", "desde el principio", "vuelve a", "repite*", "reinicia*"],
    issue: ["error*", "fallo*", "problema*", "defecto*", "encuentres", "encontrar"],
    source: ["código", "código fuente", "archivo*", "desde el principio", "desde cero", "toda la revisión"],
    negativeIteration: ["no repitas*", "no vuelvas a", "no reinicies", "sin repetir", "solo una vez"],
    hypothetical: ["qué pasaría si", "deberíamos", "crees que deberíamos", "y si"],
    tests: ["ejecuta las pruebas", "ejecuta los tests", "corre las pruebas", "lanza los tests"],
    negativeTests: ["no ejecutes las pruebas", "no ejecuta las pruebas", "sin ejecutar las pruebas"],
    negativeAction: ["no corrijas", "no arregles", "no implementes"],
  },
  {
    locale: "pt", action: ["corrija*", "corrige*", "conserte*", "repare*", "execute*", "implemente*", "desenvolva*", "faça"],
    review: ["revise*", "revisão", "inspecione*", "auditoria", "verifique*"],
    iteration: ["sempre que", "cada vez", "até que", "novamente", "de novo", "desde o início", "repita*", "reinicie*", "volte a"],
    issue: ["erro*", "falha*", "problema*", "defeito*", "encontrar", "encontre*"],
    source: ["código", "fonte", "arquivos", "desde o início", "do começo", "revisão completa"],
    negativeIteration: ["não repita*", "não reinicie*", "sem repetir", "apenas uma vez", "nao repita*"],
    hypothetical: ["e se", "deveríamos", "será que deveríamos", "o que aconteceria se"],
    tests: ["execute os testes", "rode os testes", "execute as provas", "execute o teste"],
    negativeTests: ["não execute os testes", "não rode os testes", "nao execute os testes"],
    negativeAction: ["não corrija", "não implemente", "nao corrija"],
  },
  {
    locale: "fr", action: ["corrige*", "répare*", "exécute*", "implémente*", "développe*", "effectue*", "fais"],
    review: ["réexamine*", "examine*", "revérifie*", "revue", "audit", "vérifie*"],
    iteration: ["chaque fois", "à chaque", "jusqu'à", "de nouveau", "encore", "depuis le début", "recommence*", "répète*"],
    issue: ["erreur*", "bogue*", "problème*", "défaut*", "trouve*"],
    source: ["code", "source", "fichiers", "depuis le début", "à partir du début", "revue complète"],
    negativeIteration: ["ne répète pas", "ne recommence pas", "sans répéter", "une seule fois"],
    hypothetical: ["et si", "devrions-nous", "que se passerait-il si"],
    tests: ["exécute les tests", "lance les tests", "exécute le test", "lance le test"],
    negativeTests: ["n’exécute pas les tests", "ne lance pas les tests", "ne fais pas les tests"],
    negativeAction: ["ne corrige pas", "n’implémente pas", "ne répare pas"],
  },
  {
    locale: "de", action: ["behebe*", "korrigiere*", "repariere*", "implementiere*", "führe*", "starte*", "mache*"],
    review: ["prüfung", "überprüfung", "prüfe*", "untersuche*", "kontrolliere*", "audit"],
    iteration: ["jedes mal", "immer wenn", "bis keine", "erneut", "wieder", "von vorn", "von vorne", "wiederhole*", "beginne*"],
    issue: ["fehler*", "problem*", "bug*", "findest", "gefunden"],
    source: ["quellcode", "code", "dateien", "von vorn", "von vorne", "gesamte prüfung"],
    negativeIteration: ["nicht wiederholen", "wiederhole nicht", "nicht erneut", "nur einmal", "nicht von vorn", "wiederhole die prüfung nicht"],
    hypothetical: ["was wäre wenn", "sollten wir", "was passiert wenn"],
    tests: ["führe die tests aus", "starte die tests", "tests ausführen", "führe den test aus"],
    negativeTests: ["führe die tests nicht aus", "starte die tests nicht", "keine tests ausführen"],
    negativeAction: ["nicht beheben", "nicht implementieren", "korrigiere nicht"],
  },
  {
    locale: "ru", action: ["исправ*", "почин*", "реализуй", "внедри", "запуст*", "выполн*", "сделай"],
    review: ["проверк*", "проверь", "просмотр*", "изучи*", "ревиз*", "аудит*"],
    iteration: ["каждый раз", "после каждой", "пока не", "снова", "заново", "сначала", "повтори*", "начни*"],
    issue: ["ошиб*", "проблем*", "дефект*", "баг*", "найден*"],
    source: ["исходный код", "код", "файл*", "сначала", "заново", "полную проверку"],
    negativeIteration: ["не повторяй", "не начинай заново", "не проверяй снова", "только один раз", "не начинай проверку заново"],
    hypothetical: ["что если", "стоит ли", "нужно ли нам"],
    tests: ["запусти тесты", "выполни тесты", "запусти тест", "прогони тесты"],
    negativeTests: ["не запускай тесты", "не выполняй тесты", "не надо запускать тесты"],
    negativeAction: ["не исправляй", "не реализуй", "не меняй"],
  },
  {
    locale: "ar", action: ["أصلح*", "اصلح*", "صحح*", "نفذ*", "طبق*", "شغل*", "نفذ*", "قم ب"],
    review: ["المراجعة", "مراجعة", "راجع*", "افحص*", "فحص", "تدقيق"],
    iteration: ["كلما", "في كل مرة", "حتى لا", "مرة أخرى", "من البداية", "أعد*", "اعاد*", "كرر*"],
    issue: ["خطأ*", "خطا*", "الأخطاء", "الاخطاء", "مشكلة*", "تجد"],
    source: ["الكود", "الشفرة", "الملفات", "من البداية", "المراجعة الكاملة"],
    negativeIteration: ["لا تكرر*", "لا تعد*", "مرة واحدة فقط", "دون تكرار"],
    hypothetical: ["ماذا لو", "هل ينبغي", "هل يجب علينا"],
    tests: ["شغل الاختبارات", "نفذ الاختبارات", "قم بتشغيل الاختبارات"],
    negativeTests: ["لا تشغل الاختبارات", "لا تنفذ الاختبارات"],
    negativeAction: ["لا تصلح", "لا تنفذ", "لا تعدل"],
  },
  {
    locale: "hi", action: ["ठीक करो", "सुधारो", "लागू करो", "चलाओ", "करो", "शुरू करो"],
    review: ["जाँच", "जांच", "समीक्षा", "परीक्षण", "जाँच करो", "जांच करो"],
    iteration: ["हर बार", "जब तक", "फिर से", "दोबारा", "शुरू से", "प्रत्येक बार"],
    issue: ["गलती", "त्रुटि", "समस्या", "बग", "मिलने"],
    source: ["कोड", "स्रोत", "फ़ाइल", "फाइल", "शुरू से", "फिर से शुरू", "पूरी जाँच"],
    negativeIteration: ["दोबारा मत", "फिर से मत", "दोहराना मत", "सिर्फ एक बार"],
    hypothetical: ["क्या होगा अगर", "क्या हमें", "क्या ऐसा हो सकता है"],
    tests: ["टेस्ट चलाओ", "टेस्ट चलाएं", "परीक्षण चलाओ"],
    negativeTests: ["टेस्ट मत चलाओ", "टेस्ट नहीं चलाना", "टेस्ट न चलाएं"],
    negativeAction: ["ठीक मत करो", "मत सुधारो", "लागू मत करो"],
  },
  {
    locale: "zh", action: ["修复", "修正", "改好", "实现", "运行", "执行", "处理"],
    review: ["检查", "审查", "审核", "审计", "复查", "排查"],
    iteration: ["每次", "每当", "每发现", "直到", "重新", "再次", "从头", "反复"],
    issue: ["错误", "问题", "漏洞", "缺陷", "发现"],
    source: ["代码", "源码", "文件", "从头", "全部检查", "完整审查"],
    negativeIteration: ["不要重复", "别再", "不要重新", "只检查一次", "不要再次"],
    hypothetical: ["如果会怎么样", "是否应该", "要不要考虑", "会怎么样"],
    tests: ["运行测试", "执行测试", "跑测试"],
    negativeTests: ["不要运行测试", "别运行测试", "不要执行测试"],
    negativeAction: ["不要修复", "别修复", "不要实现", "不要执行"],
  },
  {
    locale: "ja", action: ["修正", "修復", "直して", "実装", "実行", "対応"],
    review: ["レビュー", "確認", "検査", "監査", "再点検", "調査"],
    iteration: ["たびに", "毎回", "まで", "もう一度", "再度", "最初から", "繰り返し"],
    issue: ["エラー", "バグ", "問題", "不具合", "見つけ"],
    source: ["コード", "ソース", "ファイル", "最初から", "全体", "完全"],
    negativeIteration: ["繰り返さない", "繰り返さず", "もう一度しない", "再度しない", "一度だけ"],
    hypothetical: ["もしそうならどうなる", "すべきでしょうか", "どうなる"],
    tests: ["テストを実行", "テストを走らせ", "テスト実行"],
    negativeTests: ["テストを実行しない", "テストは実行しない", "テストを実行しないで"],
    negativeAction: ["修正しない", "実装しない", "修復しない"],
  },
  {
    locale: "ko", action: ["수정", "고쳐", "구현", "해결", "실행", "진행"],
    review: ["검토", "검사", "확인", "점검", "감사"],
    iteration: ["때마다", "매번", "때까지", "다시", "처음부터", "반복"],
    issue: ["오류", "버그", "문제", "결함", "발견"],
    source: ["코드", "소스", "파일", "처음부터", "전체 검토"],
    negativeIteration: ["반복하지 마", "다시 하지 마", "다시 하지 말", "한 번만"],
    hypothetical: ["만약 어떻게", "해야 할까요", "어떻게 될까요"],
    tests: ["테스트 실행", "테스트를 실행", "테스트를 돌려"],
    negativeTests: ["테스트 실행하지 마", "테스트를 실행하지 마", "테스트 실행 금지"],
    negativeAction: ["수정하지 마", "구현하지 마", "수정하지 말"],
  },
  {
    locale: "id", action: ["perbaiki*", "benahi*", "implementasikan*", "jalankan*", "lakukan*"],
    review: ["periksa*", "pemeriksaan", "tinjau*", "audit", "review"],
    iteration: ["setiap kali", "sampai", "hingga", "ulangi*", "kembali", "dari awal", "lagi"],
    issue: ["kesalahan", "masalah", "bug", "menemukan"],
    source: ["kode", "sumber", "berkas", "dari awal", "pemeriksaan menyeluruh"],
    negativeIteration: ["jangan ulangi*", "jangan periksa lagi", "hanya sekali", "tidak perlu mengulang"],
    hypothetical: ["bagaimana jika", "apakah sebaiknya", "haruskah kita"],
    tests: ["jalankan tes", "jalankan pengujian", "lakukan pengujian"],
    negativeTests: ["jangan jalankan tes", "tidak perlu jalankan tes", "jangan lakukan pengujian"],
    negativeAction: ["jangan perbaiki", "jangan implementasikan", "jangan lakukan"],
  },
];

/** Examples, code and quoted commands do not create new task duties. */
export function sanitizeUserInstruction(text: string): string {
  return text
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/\x60[^\x60\n]+\x60/g, " ")
    .replace(/^\s*>[^\n]*$/gm, " ")
    .replace(/"[^"\n]*"/g, " ")
    .replace(/“[^”\n]*”/g, " ")
    .replace(/「[^」\n]*」/g, " ")
    .replace(/『[^』\n]*』/g, " ")
    .replace(/«[^»\n]*»/g, " ");
}

function normalized(text: string): string {
  return text.normalize("NFKC").toLocaleLowerCase().replace(/\u0640/g, "").replace(/[\u064b-\u065f]/g, "").replace(/\s+/g, " ").trim();
}

function isCjk(char: string): boolean {
  return /[\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]/u.test(char);
}

function matches(text: string, rawTerm: string): boolean {
  const term = normalized(rawTerm);
  const prefix = term.endsWith("*");
  const target = prefix ? term.slice(0, -1) : term;
  if (!target) return false;
  let start = 0;
  while (true) {
    const index = text.indexOf(target, start);
    if (index < 0) return false;
    const previous = text[index - 1] ?? "";
    const following = text[index + target.length] ?? "";
    const leftBound = !previous || isCjk(target.charAt(0)) || !/[\p{L}\p{M}\p{N}]/u.test(previous);
    const rightBound = prefix || !following || isCjk(target.charAt(target.length - 1)) || !/[\p{L}\p{M}\p{N}]/u.test(following);
    if (leftBound && rightBound) return true;
    start = index + 1;
  }
}

function has(text: string, terms: readonly string[]): boolean {
  return terms.some((term) => matches(text, term));
}

export interface InternationalTaskSignals {
  locale: string;
  iterativeReview: boolean;
  requiresSourceReview: boolean;
  requiredVerifications: VerificationKind[];
  explicitAction: boolean;
  /** These are indicators, not a verified interpretation of arbitrary prose. */
  evidence: readonly string[];
}

/**
 * The output is locale-neutral; only the extraction of explicit signals is
 * localized. Unknown or conflicted wording does not create a mandatory task.
 */
export function extractInternationalSignals(input: string): InternationalTaskSignals | undefined {
  const text = normalized(sanitizeUserInstruction(input));
  if (!text) return undefined;
  const candidates = LOCALES.map((locale) => {
    const hypothetical = has(text, locale.hypothetical);
    const negated = has(text, locale.negativeIteration);
    const action = has(text, locale.action) &&
      !has(text, locale.negativeAction) &&
      !has(text, locale.negativeTests);
    const review = has(text, locale.review);
    const issue = has(text, locale.issue);
    const iteration = has(text, locale.iteration);
    const tests = has(text, locale.tests) && !has(text, locale.negativeTests);
    const iterativeReview = !hypothetical && !negated && action && review && issue && iteration;
    const requiredVerifications: VerificationKind[] = !hypothetical && tests ? ["test"] : [];
    return {
      locale: locale.locale,
      iterativeReview,
      requiresSourceReview: iterativeReview && has(text, locale.source),
      explicitAction: !hypothetical && (action || tests),
      requiredVerifications,
      evidence: [action && "action", review && "review", issue && "issue", iteration && "iteration", tests && "test"].filter(Boolean) as string[],
      negated,
    };
  }).filter((item) => item.iterativeReview || item.requiredVerifications.length > 0 || item.explicitAction);
  if (candidates.length === 0) return undefined;
  // Multiple conflicting locale interpretations are not a basis for a
  // blocking requirement. Favor a candidate with more concrete signals.
  candidates.sort((a, b) => b.evidence.length - a.evidence.length);
  const first = candidates[0];
  if (!first) return undefined;
  const second = candidates[1];
  if (second && first.evidence.length === second.evidence.length) {
    return undefined;
  }
  const { negated: _negated, ...result } = first;
  return result;
}

export interface InternationalNegations {
  iteration: boolean;
  action: boolean;
  test: boolean;
}

export function extractInternationalNegations(input: string): InternationalNegations {
  const text = normalized(sanitizeUserInstruction(input));
  return {
    iteration: LOCALES.some((locale) => has(text, locale.negativeIteration)),
    action: LOCALES.some((locale) => has(text, locale.negativeAction)),
    test: LOCALES.some((locale) => has(text, locale.negativeTests)),
  };
}

export const SUPPORTED_SIGNAL_LOCALES: readonly string[] = LOCALES.map(({ locale }) => locale);

/** Reporting markers provide context for evidence checks; they are never proof. */
const REPORT_TERMS: readonly {
  locale: string;
  completed: readonly string[];
  blocked: readonly string[];
}[] = [
  { locale: "es", completed: ["tarea completada", "trabajo terminado", "he terminado"], blocked: ["no puedo continuar", "no está terminado", "falta acceso"] },
  { locale: "pt", completed: ["tarefa concluída", "trabalho concluído", "terminei"], blocked: ["não consigo continuar", "tarefa não concluída", "preciso de acesso"] },
  { locale: "fr", completed: ["tâche terminée", "travail terminé", "j'ai terminé"], blocked: ["je ne peux pas continuer", "tâche inachevée", "accès nécessaire"] },
  { locale: "de", completed: ["aufgabe abgeschlossen", "arbeit abgeschlossen", "fertiggestellt"], blocked: ["kann nicht fortfahren", "nicht abgeschlossen", "zugriff erforderlich"] },
  { locale: "ru", completed: ["задача завершена", "работа завершена", "всё готово"], blocked: ["не могу продолжать", "задача не завершена", "нет доступа"] },
  { locale: "ar", completed: ["تم إنجاز المهمة", "المهمة مكتملة", "اكتمل العمل"], blocked: ["لا أستطيع المتابعة", "المهمة غير مكتملة", "أحتاج إلى إذن"] },
  { locale: "hi", completed: ["काम पूरा हो गया", "कार्य पूरा हुआ", "काम समाप्त हुआ"], blocked: ["आगे नहीं बढ़ सकता", "काम पूरा नहीं हुआ", "अनुमति चाहिए"] },
  { locale: "zh", completed: ["任务已完成", "工作已完成", "全部完成"], blocked: ["无法继续", "尚未完成", "需要权限"] },
  { locale: "ja", completed: ["作業完了", "タスク完了", "作業が完了しました"], blocked: ["続行できません", "まだ完了していません", "権限が必要です"] },
  { locale: "ko", completed: ["작업 완료", "작업이 완료되었습니다", "과제 완료"], blocked: ["계속할 수 없습니다", "아직 완료되지 않았습니다", "권한이 필요합니다"] },
  { locale: "id", completed: ["tugas selesai", "pekerjaan selesai", "sudah selesai"], blocked: ["tidak bisa melanjutkan", "tugas belum selesai", "perlu izin"] },
];

export type AgentReportState = "completed" | "blocked" | "unknown";

export function classifyInternationalAgentReport(input: string): AgentReportState {
  const text = normalized(input);
  const blocked = REPORT_TERMS.some((locale) => has(text, locale.blocked));
  if (blocked) return "blocked";
  return REPORT_TERMS.some((locale) => has(text, locale.completed))
    ? "completed"
    : "unknown";
}

/**
 * Narrow historical-refusal signals: both an earlier deferral and a refusal
 * causally attributed to it must appear. These are not general sentiment or
 * cross-language semantic classifiers.
 */
const HISTORICAL_REFUSALS: readonly {
  locale: string;
  historical: readonly string[];
  consequence: readonly string[];
}[] = [
  { locale: "es", historical: ["habías pausado", "antes lo suspendiste", "previamente suspendido"], consequence: ["por eso no lo haré", "así que no lo haré", "por eso no voy a hacerlo"] },
  { locale: "pt", historical: ["havia pausado antes", "anteriormente suspenso", "antes você pausou"], consequence: ["por isso não vou fazer", "portanto não farei", "por isso não vou implementar"] },
  { locale: "fr", historical: ["suspendu auparavant", "mis en pause précédemment", "reporté auparavant"], consequence: ["donc je ne le ferai pas", "donc je ne vais pas le faire"] },
  { locale: "de", historical: ["zuvor pausiert", "früher ausgesetzt", "vorher verschoben"], consequence: ["deshalb werde ich es nicht", "daher mache ich es nicht"] },
  { locale: "ru", historical: ["ранее приостановили", "раньше отложили", "ранее отменили"], consequence: ["поэтому я не буду", "поэтому не стану"] },
  { locale: "ar", historical: ["أوقفت المهمة سابقاً", "أوقفت المهمة سابقا", "تم تأجيلها سابقا"], consequence: ["ولذلك لن أنفذها", "لذلك لن أفعل"] },
  { locale: "hi", historical: ["पहले इस काम को रोक", "पहले स्थगित किया", "पहले रद्द किया"], consequence: ["इसलिए मैं इसे नहीं करूँगा", "इसलिए यह नहीं करूँगा"] },
  { locale: "zh", historical: ["之前暂停", "之前搁置", "以前取消"], consequence: ["所以我不会", "因此我不做", "所以我不再"] },
  { locale: "ja", historical: ["以前この機能を保留", "以前中断", "前に延期"], consequence: ["実装しません", "そのため対応しません"] },
  { locale: "ko", historical: ["이전에 이 기능을 중단", "이전에 보류", "전에 중단"], consequence: ["구현하지 않겠습니다", "따라서 하지 않겠습니다"] },
  { locale: "id", historical: ["sebelumnya ditunda", "sebelumnya dihentikan", "sebelumnya dibatalkan"], consequence: ["jadi saya tidak akan", "oleh karena itu saya tidak akan"] },
];

export function detectInternationalHistoricalRefusal(
  userInstruction: string,
  assistantResponse: string
): string | undefined {
  const user = extractInternationalSignals(userInstruction);
  if (!user?.explicitAction) return undefined;
  const response = normalized(assistantResponse);
  const candidates = HISTORICAL_REFUSALS.filter(
    (locale) => locale.locale === user.locale &&
      has(response, locale.historical) &&
      has(response, locale.consequence)
  );
  return candidates.length === 1 ? candidates[0]?.locale : undefined;
}
