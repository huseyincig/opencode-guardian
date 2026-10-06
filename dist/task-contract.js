import { extractInternationalNegations, extractInternationalSignals, sanitizeUserInstruction } from "./locale-intents.js";
function userText(message) {
    return message.parts
        .filter((part) => part.type === "text" && typeof part.text === "string")
        .map((part) => part.text ?? "")
        .join("\n");
}
export function currentHumanMessage(messages) {
    return messages.findLast((message) => message.info.role === "user" &&
        !message.parts.some((part) => part.synthetic === true) &&
        !userText(message).trimStart().startsWith("[opencode-guardian remediation]"));
}
const ITERATION = /(?:\b(?:repeat|restart|rerun|re-run|again|until|every\s+(?:time|round)|each\s+(?:time|round))\b|\b(?:tekrar|yeniden|baştan|her\s+(?:turda|tura|seferinde|hata|bir\s+hata)|hata\s+kalmayana|bulmayana|sıfır\s+hata)\b)/iu;
const REVIEW = /(?:\b(?:audit|review|inspect|debug|scan|check|test|pass|iteration|issue|bug|error|defect|fix)\b|\b(?:denetim|incele|kontrol|debug|test|tur|hata|sorun|düzelt|bulgu)\b)/iu;
const CONTINUE = /(?:\b(?:until|restart|repeat|rerun|re-run|again|each\s+(?:time|round)|every\s+(?:time|round))\b|\b(?:tekrar|yeniden|baştan|her\s+(?:turda|tura|seferinde|hata)|kalmayana|bulmayana)\b)/iu;
const NEGATED_LOOP = /(?:\b(?:do\s+not|don't|dont|never|without|stop)\s+(?:repeat|restart|rerun|re-run|again)\b|\b(?:tekrarlama|tekrarlamayın|tekrar\s+etme|tekrar\s+başla(?:t)?ma|yeniden\s+başla(?:t)?ma|baştan\s+başla(?:t)?ma)\b)/iu;
/** Questions about a possible workflow are not instructions to execute it. */
export function isExploratoryPrompt(text) {
    return /^\s*(?:should\s+we|would\s+we|could\s+we|what\s+if|do\s+you\s+think\s+we\s+should|sence|acaba|ne\s+olur\s+eğer)\b/iu.test(text);
}
const SOURCE_REVIEW = /(?:\b(?:full|entire|whole|from\s+scratch|restart)\b[^.!?]{0,70}\b(?:review|inspect|scan|audit|source|code)\b|(?:\b(?:review|inspect|scan)\b|\b(?:incele|denet|tara)\p{L}*)[^.!?]{0,70}\b(?:again|from\s+the\s+start|baştan|yeniden|tekrar)\b|\b(?:baştan|yeniden|tüm|bütün|satır\s+satır)\b[^.!?]{0,70}\b(?:incele|denet|tara|kod)\w*)/iu;
const ACTION_REQUEST = /\b(?:implement|fix|change|modify|build|develop|resume|continue|write|create|add|update|complete|run|execute|start)\b|\b(?:yap|yapın|uygula|uygulayın|düzelt|düzeltin|geliştir|geliştirin|devam\s+et|başla|başlayın|ekle|ekleyin|oluştur|tamamla|tamamlayın|yaz|yazın|çalıştır|çalıştırın)\b/iu;
const VERIFICATION_REQUESTS = [
    { kind: "test", expression: /(?:\b(?:run|execute|rerun|re-run)\s+(?:the\s+|all\s+)?tests?\b|\b(?:testleri?|testleri\s+)?(?:çalıştır|çalıştırın|koştur|koşturun)\b)/iu },
    { kind: "build", expression: /(?:\b(?:run|execute)\s+(?:the\s+)?build\b|\b(?:build|derleme)(?:i|ı|yi|yı)?\s+(?:çalıştır|çalıştırın|yap|yapın)\b)/iu },
    { kind: "typecheck", expression: /(?:\b(?:run|execute)\s+(?:the\s+)?typecheck\b|\btypecheck\s+(?:çalıştır|çalıştırın|yap|yapın)\b)/iu },
    { kind: "lint", expression: /(?:\b(?:run|execute)\s+(?:the\s+)?lint\b|\blint\s+(?:çalıştır|çalıştırın|yap|yapın)\b)/iu },
    { kind: "audit", expression: /(?:\b(?:run|execute)\s+(?:the\s+)?(?:security\s+)?audit\b|\b(?:npm\s+audit|güvenlik\s+denetimi)\s+(?:çalıştır|çalıştırın|yap|yapın)\b)/iu },
];
/** Only an exact first-line directive is accepted; examples in code do not count. */
export function parseExplicitTaskDirective(text) {
    const firstLine = text.split(/\r?\n/, 1)[0]?.trim() ?? "";
    const prefix = "@guardian-task ";
    if (!firstLine.startsWith(prefix) || firstLine.length > 800)
        return undefined;
    try {
        const value = JSON.parse(firstLine.slice(prefix.length));
        if (!value || typeof value !== "object" || Array.isArray(value))
            return undefined;
        const item = value;
        if (Object.keys(item).some((key) => !["mode", "review", "verify"].includes(key))) {
            return undefined;
        }
        if (item.mode !== "iterative-review" && item.mode !== "one-pass")
            return undefined;
        if (item.review !== "source" && item.review !== "checks")
            return undefined;
        if (!Array.isArray(item.verify) || item.verify.length > 5 ||
            item.verify.some((kind) => !["test", "build", "typecheck", "lint", "audit"].includes(kind))) {
            return undefined;
        }
        return {
            mode: item.mode,
            review: item.review,
            verify: [...new Set(item.verify)],
        };
    }
    catch {
        return undefined;
    }
}
function deniedVerification(text, kind) {
    const target = kind === "test" ? "tests?" : kind;
    const denied = new RegExp(`\\b(?:do\\s+not|don't|dont|without|never)\\s+(?:run|execute)\\s+(?:the\\s+)?${target}\\b|\\b${kind === "test" ? "testleri?" : kind}\\s+(?:çalıştırma|çalıştırmayın|yapma|yapmayın)\\b`, "iu");
    return denied.test(text);
}
function explicitVerifications(text) {
    return VERIFICATION_REQUESTS
        .filter(({ kind, expression }) => expression.test(text) && !deniedVerification(text, kind))
        .map(({ kind }) => kind);
}
export function extractTaskContract(messages) {
    const human = currentHumanMessage(messages);
    if (!human)
        return undefined;
    const text = userText(human).trim();
    if (!text)
        return undefined;
    const directive = parseExplicitTaskDirective(text);
    const body = sanitizeUserInstruction(text.startsWith("@guardian-task ")
        ? text.slice(text.indexOf("\n") < 0 ? text.length : text.indexOf("\n") + 1).trim()
        : text);
    const exploratory = isExploratoryPrompt(body);
    const international = extractInternationalSignals(body);
    const negations = extractInternationalNegations(body);
    const negatedLoop = NEGATED_LOOP.test(body) || negations.iteration;
    const iterativeReview = !exploratory &&
        !negatedLoop &&
        (directive
            ? directive.mode === "iterative-review"
            : international?.iterativeReview === true ||
                (ITERATION.test(body) && REVIEW.test(body) && CONTINUE.test(body)));
    const requestedVerifications = exploratory
        ? []
        : directive
            ? directive.verify
            : [...new Set([
                    ...explicitVerifications(body),
                    ...(international?.requiredVerifications ?? []),
                ])];
    // A contradictory natural-language prohibition cannot be overridden by a
    // machine-readable header. Prefer no extra duty to an invented mandate.
    const requiredVerifications = requestedVerifications.filter((kind) => !(kind === "test" && negations.test) &&
        !deniedVerification(body, kind));
    const signalLocale = directive ? "structured" : international?.locale;
    return {
        turnKey: human.info.id ?? "no-human-user",
        explicitAction: Boolean(directive) ||
            ((!exploratory && ACTION_REQUEST.test(body)) ||
                (international?.explicitAction ?? false) || iterativeReview),
        iterativeReview,
        requiresSourceReview: iterativeReview &&
            (directive ? directive.review === "source" :
                SOURCE_REVIEW.test(body) || international?.requiresSourceReview === true),
        requiredVerifications,
        requiresExplicitCompletion: iterativeReview || requiredVerifications.length > 0,
        ...(signalLocale ? { signalLocale } : {}),
    };
}
export function taskGuidance(contract) {
    if (!contract.explicitAction && !contract.requiresExplicitCompletion)
        return undefined;
    const instructions = [
        "[OpenCode Guardian task contract]",
        "Treat the latest explicit human instructions as the active task. Do not override them with earlier user decisions or assumptions.",
    ];
    if (contract.iterativeReview) {
        instructions.push("The user explicitly requested repeated review/debugging. After fixing a finding, perform another review pass of the requested scope; do not claim completion after the first fix. Stop when a subsequent full pass finds no new issues, or report a concrete blocker and remaining work. Do not repeat identical failed actions without progress.");
    }
    if (contract.requiresSourceReview) {
        instructions.push("This request calls for another source inspection after changes; a passing test command alone is not evidence of a new source review.");
    }
    if (contract.requiredVerifications.length > 0) {
        instructions.push(`The user explicitly requested verification: ${contract.requiredVerifications.join(", ")}. Run it after the last relevant change, or state clearly what could not be run and why. Do not claim a passing result without tool evidence.`);
    }
    return instructions.join("\n");
}
export function latestMutationSequence(evidence) {
    return evidence.fileMutations
        .filter((record) => record.status !== "failure")
        .reduce((latest, record) => Math.max(latest, record.sequence), -1);
}
export function hasPostMutationReview(evidence, sourceReviewRequired = false) {
    const lastMutation = latestMutationSequence(evidence);
    if (lastMutation < 0)
        return false;
    return evidence.records.some((record) => {
        if (record.sequence <= lastMutation || record.status !== "success")
            return false;
        if (!sourceReviewRequired && ["test", "build", "typecheck", "lint", "audit"].includes(record.kind)) {
            return true;
        }
        if (record.kind !== "generic" || !record.output?.trim())
            return false;
        const tool = record.toolName.toLowerCase();
        const command = record.command ?? "";
        // Read/view tools commonly use names such as read_file and file.view.
        // A file_search returning only paths is not, by itself, source inspection.
        const directRead = /(?:^|[.:_-])(?:read|view)(?:$|[.:_-])/.test(tool);
        if (directRead)
            return true;
        // Name-only searches, glob/find output and git diff --stat are not
        // evidence of inspecting file contents. Require an actual source snippet.
        const codeMatch = /^(?:(?:[A-Za-z]:)?[^\n:]+:)?\d+:(?!\d+:[ \t]*$)(?:\d+:)?\s*\S/m.test(record.output);
        const searchTool = /(?:^|[.:_-])(?:grep|search)(?:$|[.:_-])/.test(tool);
        // Recognize executed shell commands, not words inside echo arguments or
        // a pipeline into cat/head that might return only filenames or statistics.
        const shellSearch = /(?:^|(?:&&|\|\||;|\n)\s*)\s*(?:rg|grep)(?=\s|$)/m.test(command);
        if (searchTool || shellSearch)
            return codeMatch;
        const directShellRead = /(?:^|(?:&&|\|\||;|\n)\s*)\s*(?:cat|head|tail)(?=\s|$)/m.test(command) ||
            /(?:^|(?:&&|\|\||;|\n)\s*)\s*sed\s+-n(?=\s|$)/m.test(command) ||
            /(?:^|(?:&&|\|\||;|\n)\s*)\s*git\s+show\s+[^\s;&|]+:[^\s;&|]+(?=\s|$|[;&|])/m.test(command);
        if (directShellRead)
            return true;
        return /(?:^|(?:&&|\|\||;|\n)\s*)\s*git\s+(?:diff|show)(?=\s|$)/m.test(command) &&
            /^[+-](?![+-])\s*\S/m.test(record.output);
    });
}
