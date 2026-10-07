// A trailing * means a prefix match for an inflected verb (not a regex).
// Multiword phrases are matched as complete Unicode word sequences.
const LOCALES = [
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
export function sanitizeUserInstruction(text) {
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
function normalized(text) {
    return text.normalize("NFKC").toLocaleLowerCase().replace(/\u0640/g, "").replace(/[\u064b-\u065f]/g, "").replace(/\s+/g, " ").trim();
}
function isCjk(char) {
    return /[\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]/u.test(char);
}
function matches(text, rawTerm) {
    const term = normalized(rawTerm);
    const prefix = term.endsWith("*");
    const target = prefix ? term.slice(0, -1) : term;
    if (!target)
        return false;
    let start = 0;
    while (true) {
        const index = text.indexOf(target, start);
        if (index < 0)
            return false;
        const previous = text[index - 1] ?? "";
        const following = text[index + target.length] ?? "";
        const leftBound = !previous || isCjk(target.charAt(0)) || !/[\p{L}\p{M}\p{N}]/u.test(previous);
        const rightBound = prefix || !following || isCjk(target.charAt(target.length - 1)) || !/[\p{L}\p{M}\p{N}]/u.test(following);
        if (leftBound && rightBound)
            return true;
        start = index + 1;
    }
}
function has(text, terms) {
    return terms.some((term) => matches(text, term));
}
/**
 * The output is locale-neutral; only the extraction of explicit signals is
 * localized. Unknown or conflicted wording does not create a mandatory task.
 */
export function extractInternationalSignals(input) {
    const text = normalized(sanitizeUserInstruction(input));
    if (!text)
        return undefined;
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
        const requiredVerifications = !hypothetical && tests ? ["test"] : [];
        return {
            locale: locale.locale,
            iterativeReview,
            requiresSourceReview: iterativeReview && has(text, locale.source),
            explicitAction: !hypothetical && (action || tests),
            requiredVerifications,
            evidence: [action && "action", review && "review", issue && "issue", iteration && "iteration", tests && "test"].filter(Boolean),
            negated,
        };
    }).filter((item) => item.iterativeReview || item.requiredVerifications.length > 0 || item.explicitAction);
    if (candidates.length === 0)
        return undefined;
    // Multiple conflicting locale interpretations are not a basis for a
    // blocking requirement. Favor a candidate with more concrete signals.
    candidates.sort((a, b) => b.evidence.length - a.evidence.length);
    const first = candidates[0];
    if (!first)
        return undefined;
    const second = candidates[1];
    if (second && first.evidence.length === second.evidence.length) {
        return undefined;
    }
    const { negated: _negated, ...result } = first;
    return result;
}
export function extractInternationalNegations(input) {
    const text = normalized(sanitizeUserInstruction(input));
    return {
        iteration: LOCALES.some((locale) => has(text, locale.negativeIteration)),
        action: LOCALES.some((locale) => has(text, locale.negativeAction)),
        test: LOCALES.some((locale) => has(text, locale.negativeTests)),
    };
}
export const SUPPORTED_SIGNAL_LOCALES = LOCALES.map(({ locale }) => locale);
/** Reporting markers provide context for evidence checks; they are never proof. */
const REPORT_TERMS = [
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
export function classifyInternationalAgentReport(input) {
    const text = normalized(input);
    const blocked = REPORT_TERMS.some((locale) => has(text, locale.blocked));
    if (blocked)
        return "blocked";
    return REPORT_TERMS.some((locale) => has(text, locale.completed))
        ? "completed"
        : "unknown";
}
/**
 * Narrow historical-refusal signals: both an earlier deferral and a refusal
 * causally attributed to it must appear. These are not general sentiment or
 * cross-language semantic classifiers.
 */
const HISTORICAL_REFUSALS = [
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
export function detectInternationalHistoricalRefusal(userInstruction, assistantResponse) {
    const user = extractInternationalSignals(userInstruction);
    if (!user?.explicitAction)
        return undefined;
    const response = normalized(assistantResponse);
    const candidates = HISTORICAL_REFUSALS.filter((locale) => locale.locale === user.locale &&
        has(response, locale.historical) &&
        has(response, locale.consequence));
    return candidates.length === 1 ? candidates[0]?.locale : undefined;
}
// -----------------------------------------------------------------------------
// ADVISORY PARSING & COMPATIBILITY REGEXES (English, Turkish, etc.)
// Centralized here so core engine and guard rules have ZERO language-specific phrases.
// -----------------------------------------------------------------------------
const CLOSING_REGEX = /\b(?:completed?|finished|all\s+done|task\s+done|that's\s+it|no\s+(?:more|further)\s+(?:issues?|errors?|bugs?)|nothing\s+(?:else|left)\s+to\s+fix)\b|\b(?:tamamlandı|tamamladım|iş\s+bitti|denetim\s+bitti|inceleme\s+tamamlandı|hata\s+kalmadı|sorun\s+kalmadı|başka\s+hata\s+yok)\b/iu;
const CLEAR_BLOCKER_REGEX = /\b(?:blocked|cannot\s+(?:proceed|continue|verify|run)|unable\s+to\s+(?:proceed|continue|verify|run)|need\s+(?:your\s+)?(?:permission|access|input)|not\s+(?:yet\s+)?(?:complete|done|finished)|unfinished)\b|\b(?:engellendi|ilerleyemiyorum|doğrulayamıyorum|çalıştıramıyorum|tamamlanmadı|izin\s+gerekiyor|erişim\s+gerekiyor|devam\s+edemiyorum)\b/iu;
export function classifyAgentReport(input) {
    const internationalReport = classifyInternationalAgentReport(input);
    const hasClearBlocker = CLEAR_BLOCKER_REGEX.test(input) || internationalReport === "blocked";
    const proseWithoutBlockers = hasClearBlocker ? input.replace(CLEAR_BLOCKER_REGEX, " ") : input;
    const isClosing = CLOSING_REGEX.test(proseWithoutBlockers) || internationalReport === "completed";
    const state = hasClearBlocker && !isClosing
        ? "blocked"
        : isClosing
            ? "completed"
            : "unknown";
    return { state, hasClearBlocker, isClosing };
}
// Task Contract extraction helpers
const ITERATION = /(?:\b(?:repeat|restart|rerun|re-run|again|until|every\s+(?:time|round)|each\s+(?:time|round))\b|\b(?:tekrar|yeniden|baştan|her\s+(?:turda|tura|seferinde|hata|bir\s+hata)|hata\s+kalmayana|bulmayana|sıfır\s+hata)\b)/iu;
const REVIEW = /(?:\b(?:audit|review|inspect|debug|scan|check|test|pass|iteration|issue|bug|error|defect|fix)\b|\b(?:denetim|incele|kontrol|debug|test|tur|hata|sorun|düzelt|bulgu)\b)/iu;
const CONTINUE = /(?:\b(?:until|restart|repeat|rerun|re-run|again|each\s+(?:time|round)|every\s+(?:time|round))\b|\b(?:tekrar|yeniden|baştan|her\s+(?:turda|tura|seferinde|hata)|kalmayana|bulmayana)\b)/iu;
const NEGATED_LOOP = /(?:\b(?:do\s+not|don't|dont|never|without|stop)\s+(?:repeat|restart|rerun|re-run|again)\b|\b(?:tekrarlama|tekrarlamayın|tekrar\s+etme|tekrar\s+başla(?:t)?ma|yeniden\s+başla(?:t)?ma|baştan\s+başla(?:t)?ma)\b)/iu;
const SOURCE_REVIEW = /(?:\b(?:full|entire|whole|from\s+scratch|restart)\b[^.!?]{0,70}\b(?:review|inspect|scan|audit|source|code)\b|(?:\b(?:review|inspect|scan)\b|\b(?:incele|denet|tara)\p{L}*)[^.!?]{0,70}\b(?:again|from\s+the\s+start|baştan|yeniden|tekrar)\b|\b(?:baştan|yeniden|tüm|bütün|satır\s+satır)\b[^.!?]{0,70}\b(?:incele|denet|tara|kod)\w*)/iu;
const ACTION_REQUEST = /\b(?:implement|fix|change|modify|build|develop|resume|continue|write|create|add|update|complete|run|execute|start)\b|\b(?:yap|yapın|uygula|uygulayın|düzelt|düzeltin|geliştir|geliştirin|devam\s+et|başla|başlayın|ekle|ekleyin|oluştur|tamamla|tamamlayın|yaz|yazın|çalıştır|çalıştırın)\b/iu;
const VERIFICATION_REQUESTS = [
    { kind: "test", expression: /(?:\b(?:run|execute|rerun|re-run)\s+(?:the\s+|all\s+)?tests?\b|\b(?:testleri?|testleri\s+)?(?:çalıştır|çalıştırın|koştur|koşturun)\b)/iu },
    { kind: "build", expression: /(?:\b(?:run|execute)\s+(?:the\s+)?build\b|\b(?:build|derleme)(?:i|ı|yi|yı)?\s+(?:çalıştır|çalıştırın|yap|yapın)\b)/iu },
    { kind: "typecheck", expression: /(?:\b(?:run|execute)\s+(?:the\s+)?typecheck\b|\btypecheck\s+(?:çalıştır|çalıştırın|yap|yapın)\b)/iu },
    { kind: "lint", expression: /(?:\b(?:run|execute)\s+(?:the\s+)?lint\b|\blint\s+(?:çalıştır|çalıştırın|yap|yapın)\b)/iu },
    { kind: "audit", expression: /(?:\b(?:run|execute)\s+(?:the\s+)?(?:security\s+)?audit\b|\b(?:npm\s+audit|güvenlik\s+denetimi)\s+(?:çalıştır|çalıştırın|yap|yapın)\b)/iu },
];
export function isExploratoryPrompt(text) {
    return /^\s*(?:should\s+we|would\s+we|could\s+we|what\s+if|do\s+you\s+think\s+we\s+should|sence|acaba|ne\s+olur\s+eğer)\b/iu.test(text);
}
export function deniedVerification(text, kind) {
    const target = kind === "test" ? "tests?" : kind;
    const denied = new RegExp(`\\b(?:do\\s+not|don't|dont|without|never)\\s+(?:run|execute)\\s+(?:the\\s+)?${target}\\b|\\b${kind === "test" ? "testleri?" : kind}\\s+(?:çalıştırma|çalıştırmayın|yapma|yapmayın)\\b`, "iu");
    const negations = extractInternationalNegations(text);
    return denied.test(text) || (kind === "test" && negations.test);
}
export function extractAdvisoryTaskSignals(body) {
    const exploratory = isExploratoryPrompt(body);
    const international = extractInternationalSignals(body);
    const negations = extractInternationalNegations(body);
    const negatedLoop = NEGATED_LOOP.test(body) || negations.iteration;
    const iterativeReview = !exploratory &&
        !negatedLoop &&
        (international?.iterativeReview === true ||
            (ITERATION.test(body) && REVIEW.test(body) && CONTINUE.test(body)));
    const regexVerifications = VERIFICATION_REQUESTS
        .filter(({ kind, expression }) => expression.test(body) && !deniedVerification(body, kind))
        .map(({ kind }) => kind);
    const requestedVerifications = exploratory
        ? []
        : [...new Set([...regexVerifications, ...(international?.requiredVerifications ?? [])])]
            .filter((kind) => !deniedVerification(body, kind));
    return {
        explicitAction: (!exploratory && ACTION_REQUEST.test(body)) || (international?.explicitAction ?? false) || iterativeReview,
        iterativeReview,
        requiresSourceReview: iterativeReview && (SOURCE_REVIEW.test(body) || international?.requiresSourceReview === true),
        requiredVerifications: requestedVerifications,
        negatedLoop,
        exploratory,
        ...(international?.locale ? { signalLocale: international.locale } : {}),
    };
}
// Instruction fidelity helpers
const ACTION_FIDELITY = /\b(?:implement|fix|change|modify|build|develop|resume|continue|write|create|add|update|complete|do|start)\b|\b(?:yap|yapın|uygula|uygulayın|düzelt|düzeltin|geliştir|geliştirin|devam\s+et|başla|başlayın|ekle|ekleyin|oluştur|tamamla|tamamlayın|yaz|yazın)\b/iu;
const NEGATED_ACTION_FIDELITY = /\b(?:do\s+not|don't|dont|never)\s+(?:implement|fix|change|build|develop|resume|continue|write|create|add|update|complete|do|start)\b|\b(?:yapma|yapmayın|uygulama|uygulamayın|düzeltme|düzeltmeyin|geliştirme|geliştirmeyin)\b/iu;
const PREVIOUS_DECISION = /\b(?:previously|earlier|before|last\s+time|already)\b[^.!?]{0,120}\b(?:pause|paused|suspend(?:ed)?|defer(?:red)?|postpone(?:d)?|cancel(?:ed)?|on\s+hold)\b|\b(?:önceden|daha\s+önce|eskiden)\b[^.!?]{0,120}\b(?:askıya\s+al|erteled|durdur|iptal|vazgeç)\w*/iu;
const REFUSAL = /\b(?:so|therefore|hence|thus|because|as\s+a\s+result)\b[^.!?]{0,100}\b(?:won't|will\s+not|cannot|can't|not\s+going\s+to|skip(?:ping)?)\b|\b(?:bu\s+yüzden|dolayısıyla|o\s+nedenle|bu\s+sebeple)\b[^.!?]{0,120}\b(?:yapmıyorum|yapmayacağım|uygulamıyorum|atlıyorum|devam\s+etmiyorum|yapamam)\b/iu;
const REDUNDANT_HANDOFF = /\b(?:would\s+you\s+like\s+me\s+to|do\s+you\s+want\s+me\s+to|should\s+i)\s+(?:proceed|continue|implement|fix|apply|run|finish|complete|start|do)\b|\b(?:devam\s+edeyim|yapayım|uygulayayım|düzelteyim|başlayayım|tamamlayayım)\s+m[ıiuü]\b|\bhangisini\s+(?:tercih\s+edersin|isters?in)\b|\bistersen\b[^.!?]{0,180}\b(?:yaparım|uygularım|düzeltirim|devam\s+ederim|başlarım|kapatırım|tamamlarım|çalıştırırım)\b/iu;
const REAL_BLOCKER_OR_REQUIRED_CHOICE = /\b(?:need|require|requires|required|missing|lack(?:ing)?|without)\b[^.!?]{0,120}\b(?:access|permission|credential|token|key|password|secret|information|details|input|decision|choice)\b|\b(?:cannot|can't|unable\s+to)\s+(?:continue|proceed)\b|\b(?:erişim|izin|yetki|kimlik\s+bilgisi|token|anahtar|parola|bilgi|detay|girdi|karar|tercih)\b[^.!?]{0,120}\b(?:gerekiyor|gerekli|eksik|olmadan|yok)\b/iu;
export function detectInstructionFidelitySignals(instruction, prose, observableWork) {
    const international = detectInternationalHistoricalRefusal(instruction, prose);
    const explicitCurrentAction = ACTION_FIDELITY.test(instruction) &&
        !isExploratoryPrompt(instruction) &&
        !NEGATED_ACTION_FIDELITY.test(instruction);
    const originalPattern = explicitCurrentAction &&
        PREVIOUS_DECISION.test(prose) &&
        REFUSAL.test(prose);
    const redundantHandoff = explicitCurrentAction &&
        !observableWork &&
        REDUNDANT_HANDOFF.test(prose) &&
        !REAL_BLOCKER_OR_REQUIRED_CHOICE.test(prose);
    if (redundantHandoff) {
        return { hasViolation: true, type: "redundant-handoff" };
    }
    if (originalPattern || international) {
        return {
            hasViolation: true,
            type: "historical-refusal",
            ...(international ? { internationalLocale: international } : {}),
        };
    }
    return { hasViolation: false };
}
const UNCERTAINTY_REGEX = /\b(?:probably|likely|possibly|maybe|should|seems?|appears?|i\s+(?:think|suspect|assume)|not\s+verified|unverified|haven't\s+run|have\s+not\s+run|didn't\s+run|did\s+not\s+run|cannot\s+verify|can't\s+verify|couldn't\s+verify|sanırım|muhtemelen|belki|büyük\s+ihtimal(?:le)?|doğrulamadım|doğrulanmadı|çalıştırmadım|kontrol\s+etmedim)\b/iu;
export function isUncertaintyClaim(sentence) {
    return UNCERTAINTY_REGEX.test(sentence);
}
export function getClaimPatterns() {
    return [
        {
            name: "tests passing",
            kind: "test",
            regex: /\b(?:(?:all|the)\s+)?tests?(?:\s+suite)?\s+(?:all\s+)?(?:pass(?:ed|es|ing)?|succeed(?:ed|s)?|are\s+(?:green|passing))\b|\btüm\s+testler\s+(?:geçti|başarılı)\b|\btestler\s+(?:geçti|başarılı)\b/iu,
        },
        {
            name: "build successful",
            kind: "build",
            regex: /\b(?:the\s+)?build\s+(?:pass(?:ed|es)?|is\s+successful|succeed(?:ed|s)?|completed\s+successfully)\b|\bderleme\s+(?:başarılı|geçti)\b/iu,
        },
        {
            name: "typecheck successful",
            kind: "typecheck",
            regex: /\btype\s*-?check(?:ing)?\s+(?:pass(?:ed|es)?|is\s+clean|succeed(?:ed|s)?)\b|\btypecheck\s+(?:başarılı|geçti)\b/iu,
        },
        {
            name: "lint successful",
            kind: "lint",
            regex: /\blint(?:ing)?\s+(?:pass(?:ed|es)?|is\s+clean|succeed(?:ed|s)?)\b|\blint\s+(?:başarılı|geçti)\b/iu,
        },
        {
            name: "audit clean",
            kind: "audit",
            regex: /\b(?:audit\s+(?:is\s+)?clean|no\s+vulnerabilit(?:y|ies)|0\s+vulnerabilit(?:y|ies))\b|\b(?:güvenlik\s+)?açığı\s+yok\b/iu,
        },
        {
            name: "push successful",
            kind: "git-push",
            regex: /\b(?:push(?:ed)?\s+(?:successfully|to\s+(?:github|origin|remote))|successfully\s+pushed)\b|\b(?:github|remote|origin)(?:'a|'e|a|e)?\s+(?:pushlandı|gönderildi)\b/iu,
        },
        {
            name: "working tree clean",
            kind: "git-status",
            regex: /\b(?:working\s+tree|repository|repo)\s+(?:is\s+)?clean\b|\bnothing\s+to\s+commit\b|\bçalışma\s+ağacı\s+temiz\b/iu,
        },
        {
            name: "fix verified",
            mode: "verification",
            regex: /\b(?:the\s+)?(?:bug|issue|problem|regression)\s+(?:is\s+)?(?:fixed|resolved)\b|\b(?:bug|hata|sorun)\s+(?:düzeltildi|çözüldü)\b/iu,
        },
    ];
}
// Destructive operations helpers
export function isAuthorizedGitClean(cleanRequest, command) {
    if (/\b(?:do\s+not|don't|dont|never|avoid|without)\s+(?:(?:run|running|execute|executing|use|using)\s+)?git\s+clean\b/i.test(cleanRequest) ||
        /\b(?:instead\s+of|rather\s+than)\s+(?:(?:running|using)\s+)?git\s+clean\b/i.test(cleanRequest) ||
        /\bgit\s+clean\b[^.!?\n]{0,60}\b(?:yapma|yapmayın|kullanma|kullanmayın|uygulama|uygulamayın|çalıştırma|çalıştırmayın|çalıştırmamalısın|istemiyorum|yerine)\b/iu.test(cleanRequest)) {
        return false;
    }
    const permitted = /\b(?:run|execute|use|apply)\s+(?:the\s+)?git\s+clean\b/i.test(cleanRequest) ||
        /\bgit\s+clean\b[^.!?\n]{0,80}\b(?:yap|yapın|uygula|uygulayın|çalıştır|çalıştırın|kullan|kullanın)\b/iu.test(cleanRequest) ||
        cleanRequest.trim() === command.trim().toLowerCase();
    if (!permitted)
        return false;
    const ignoredFiles = /(?:^|\s)-[a-z]*[xX][a-z]*(?=\s|$)|--(?:exclude-standard|ignored)(?=\s|$)/.test(command);
    return (!ignoredFiles ||
        /(?:^|\s)-[a-z]*[xX][a-z]*(?=\s|$)|\b(?:ignored\s+files?|gitignored\s+files?|yok\s+sayılan\s+dosyalar|ignore\s+edilen\s+dosyalar)\b/iu.test(cleanRequest));
}
export function isImperativeExecutionRequest(request) {
    return /^\s*(?:please\s+)?(?:run|execute|çalıştır|çalıştırın)\b/iu.test(request);
}
export function isDeleteTargetRequested(request) {
    return /\b(?:delete|remove|wipe|sil|silin|sileyim|kaldır|kaldırın)\b/iu.test(request);
}
export function isWholeWorkspaceDeleteRequested(request) {
    return (/\brm\s+-rf\s+\.\/?(?:\s|$)/i.test(request) ||
        /\b(?:delete|remove|wipe|destroy)\s+(?:the\s+)?(?:entire|whole)\s+(?:project|repo|repository|directory|folder|workspace)\b/iu.test(request) ||
        /\b(?:entire|whole)\s+(?:project|repo|repository|directory|folder|workspace)\b[^.!?]*\b(?:delete|remove|wipe|destroy)\b/iu.test(request) ||
        /\b(?:tüm|bütün|komple)\s+(?:projeyi|depoyu|klasörü|dizini|çalışma\s+alanını)\s+(?:sil|silin|sıfırla|sıfırlayın)\b/iu.test(request) ||
        /\b(?:projenin|deponun|klasörün|dizinin)\s+tamamını\s+(?:sil|silin)\b/iu.test(request));
}
export function isExplicitlyAllowedSudo(request) {
    const forbidden = /\b(?:without|no|never|avoid|do\s+not|don\x27t|dont)\s+(?:(?:using|use|running|run)\s+)?sudo\b/i.test(request) ||
        /\bsudo\b[^.!?\n]{0,40}\b(?:kullanma|kullanmayın|yapma|olmadan)\b/iu.test(request);
    return /\bsudo\b/i.test(request) && !forbidden;
}
export function isSqlDestructionRequested(request) {
    return /\b(?:drop|truncate|delete|remove|sil|kaldır)\b/iu.test(request);
}
export const SQL_TARGET_CONTEXT_REGEX = /\b(?:drop|truncate|delete|remove|sil|kaldır|tables?|databases?|schemas?|tablolar?|veritabanı|şema)\b/iu;
// Test cheats helpers
export function isAuthorizedTestEdit(text) {
    if (!text || typeof text !== "string")
        return false;
    return /(?:\b(?:update|rewrite|modify|refactor|fix|change|adjust|delete|remove|skip)\b[^\n.!?]{0,50}\btests?\b|\btests?\b[^\n.!?]{0,50}\b(?:update|rewrite|modify|modification|refactor|fix|change)\b|\b(?:testleri?|testi)\b[^\n.!?]{0,50}\b(?:güncelle|düzelt|yeniden\s+yaz|değiştir|kaldır|sil|atla)\b|\b(?:skip|atla)\b[^\n.!?]{0,50}\b(?:test|testleri)\b)/iu.test(text);
}
export function isTestBypassProhibited(userInstruction) {
    return /(?:do\s+not|don\u0027t|never|without)\s+(?:\w+\s+){0,3}(?:skip|ignore|delete|weaken|remove|only)\b|\b(?:atlama|silme|kaldırma|zayıflatma)\b/iu.test(userInstruction);
}
export function isSpecificTestBypassAuthorized(userInstruction, pattern) {
    if (/skip|xit|xtest|ignore|todo/i.test(pattern)) {
        return /\bskip\b|\batla\b|\bignore\b/i.test(userInstruction);
    }
    if (/focus|only/i.test(pattern))
        return /\bonly\b|\bfocus\b/i.test(userInstruction);
    if (/assertion weakened/i.test(pattern))
        return /\bweaken\b|\bgevşet\b/i.test(userInstruction);
    if (/coverage threshold reduced/i.test(pattern))
        return /(?:lower|reduce|düşür|azalt)[^\n.!?]{0,45}(?:coverage|threshold|kapsam|eşik)/iu.test(userInstruction);
    if (/test file deleted/i.test(pattern))
        return /(?:delete|remove|sil|kaldır)[^\n.!?]{0,45}\btests?\b|\btests?\b[^\n.!?]{0,45}(?:delete|remove|sil|kaldır)/iu.test(userInstruction);
    if (/CI test step removed/i.test(pattern))
        return /(?:remove|delete|kaldır|sil)[^\n.!?]{0,45}\bCI\b/i.test(userInstruction);
    if (/snapshot update/i.test(pattern))
        return /\bsnapshot\b[^\n.!?]{0,45}(?:update|güncelle)/iu.test(userInstruction);
    return false;
}
// Shortcuts helpers
export function isAuthorizedStubOrPlaceholder(text) {
    if (!text || typeof text !== "string")
        return false;
    return /(?:\b(?:add|create|use|put|write|leave)\b[^\n.!?]{0,50}\b(?:stub|mock|placeholder|todo|fixme)\b|\b(?:stub|mock|placeholder|todo|fixme|taslak|yer\s+tutucu)\b[^\n.!?]{0,50}\b(?:ekle|oluştur|yaz|kullan|bırak)\b)/iu.test(text);
}
export function isPlaceholderProhibited(userInstruction) {
    return /(?:do\s+not|don\u0027t|never|without)\s+(?:\w+\s+){0,3}(?:todo|fixme|hack|stub|placeholder|mock)\b|\b(?:todo|fixme|hack|taslak)\s+(?:ekleme|bırakma|yazma)\b/iu.test(userInstruction);
}
export function isCodePlaceholderRequested(userInstruction) {
    return /\b(?:stub|placeholder|todo|fixme|hack|taslak|yer\s*tutucu)\b/iu.test(userInstruction);
}
export function getApologyPatterns() {
    return [
        {
            name: "English",
            regex: /(?<!\p{L})(?:(?:i(?:'m| am)?\s+)?(?:deeply|sincerely|terribly|truly|so)?\s*(?:apologiz\p{L}*|apologis\p{L}*|sorr(?:y|ier))|(?:my|our|sincere|deepest)\s+apolog\p{L}*|apologies\s+for|pardon(?:\s+me)?|forgive\s+me|excuse\s+my\s+mistake|my\s+bad|my\s+fault)(?!\p{L})/iu,
        },
        {
            name: "Turkish",
            regex: /(?<!\p{L})(?:(?:çok\s+|binlerce\s+kez\s+)?özür\s*(?:diler(?:im|iz)?|diliyor(?:um|uz)?|dileyerek)|kusur(?:a|uma)?\s*bakma(?:yın|yınız)?|affeder(?:im|siniz)?|afeder(?:im|siniz)?|bağışla(?:yın)?)(?!\p{L})/iu,
        },
        {
            name: "German",
            regex: /(?<!\p{L})(?:entschuldig\p{L}*|es\s+tut\s+mir\s+leid|verzeih\p{L}*)(?!\p{L})/iu,
        },
        {
            name: "French",
            regex: /(?<!\p{L})(?:désol[ée]\p{L}*|pardon(?:nez-moi)?|excuse[zr]?-moi|veuillez\s+m'excuser|navr[ée]\p{L}*|mille\s+excuses)(?!\p{L})/iu,
        },
        {
            name: "Spanish",
            regex: /(?<!\p{L})(?:disculp\p{L}*|perd[oó]n\p{L}*|lo\s+siento|mil\s+disculpas)(?!\p{L})/iu,
        },
        {
            name: "Italian",
            regex: /(?<!\p{L})(?:scus\p{L}*|spiacente|chiedo\s+scusa|perdon\p{L}*)(?!\p{L})/iu,
        },
        {
            name: "Portuguese",
            regex: /(?<!\p{L})(?:desculp\p{L}*|perd[aã]o|sinto\s+muito|peço\s+desculpas)(?!\p{L})/iu,
        },
        {
            name: "Russian",
            regex: /(?<!\p{L})(?:извини\p{L}*|прости\p{L}*|сожале\p{L}*|прошу\s+прощения)(?!\p{L})/iu,
        },
        {
            name: "Dutch",
            regex: /(?<!\p{L})(?:het\s+spijt\s+me|verontschuldig\p{L}*)(?!\p{L})/iu,
        },
    ];
}
