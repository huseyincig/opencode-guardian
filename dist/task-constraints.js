import { isTrustedMeshMessage } from "./bridge.js";
import { currentHumanMessage } from "./task-contract.js";
import { sanitizeUserInstruction } from "./locale-intents.js";
/** Human text only; generated reminders, mesh messages, and tool output cannot grant authority. */
export function humanInstructionText(message, sessionID) {
    return message?.parts
        .filter((part) => part.type === "text" && typeof part.text === "string" &&
        part.synthetic !== true && part.ignored !== true &&
        !isTrustedMeshMessage(part, sessionID))
        .map((part) => part.text ?? "").join("\n").slice(0, 64_000) ?? "";
}
export function latestHumanInstruction(context) {
    return humanInstructionText(currentHumanMessage(context.currentTurn, context.sessionID), context.sessionID);
}
/** Strip examples/comments while preserving literal inline command targets. */
export function authorizationText(text) {
    return text.slice(0, 64_000)
        .replace(/<lazy_bound_skill\b[\s\S]*?<\/lazy_bound_skill>/gi, " ")
        .replace(/<lazy_skill_suggestions\b[\s\S]*?<\/lazy_skill_suggestions>/gi, " ")
        .replace(/```[\s\S]*?```/g, " ")
        .replace(/^\s*(?:>|#|\/\/)[^\n]*$/gm, " ")
        .replace(/(?:^|[ \t])(?:#|\/\/)[^\n]*$/gm, " ")
        .replace(/\/\*[\s\S]*?\*\//g, " ")
        .replace(/<!--[\s\S]*?-->/g, " ")
        .replace(/(?:"[^"\n]*"|“[^”\n]*”|‘[^’\n]*’)/g, " ")
        .replace(/(^|[\s(])'[^'\n]+'(?=$|[\s).,;!?])/gm, "$1 ")
        .replace(/`([^`\n]+)`/g, "$1");
}
/** Deliberately narrow English/Turkish constraints, not inferred task goals. */
export function hasResearchOnlyConstraint(instruction) {
    const text = sanitizeUserInstruction(instruction.slice(0, 64_000)
        .replace(/(^|[\s(])'[^'\n]+'(?=$|[\s).,;!?])/gm, "$1 "))
        .replace(/^\s*(?:#|\/\/)[^\n]*$/gm, " ")
        .toLocaleLowerCase("en-US");
    // A negated restriction is permission to go beyond research, not a ban.
    const clauses = text.split(/[.!?;\n]+/);
    return clauses.some((clause) => {
        if (/\b(?:do\s+not|don't|never)\s+(?:limit|restrict)\b/.test(clause) ||
            /(?:sınırlı\s+kalma|sınırlama)/u.test(clause))
            return false;
        return /\b(?:(?:research|analysis|analy[sz]e|inspect|investigate)\s+only|only\s+(?:research|analy[sz]e|inspect|investigate)|(?<!\b(?:shows?|showing|found|finds?|had|has|have|with|seeing|sees?|reports?|reporting|made)\s+)no\s+(?:edits|changes)(?!\s+(?:to|in|for|are|were|have|has|had|been|made|needed|necessary|required|detected|found|broke|break|affect|yet)\b)|(?:do\s+not|don't|never)\s+(?:edit|modify|change)\s+(?:(?:any|the)\s+)?files(?!\s+(?:in|under|inside|within|from|at|outside|except|other\s+than)\b)|(?:do\s+not|don't|never)\s+make\s+changes\s+to\s+(?:(?:any|the)\s+)?files(?!\s+(?:in|under|inside|within|from|at|outside|except|other\s+than)\b))\b/.test(clause) ||
            /(?:^|\s)(?:sadece|yalnızca)\s+(?:araştır(?:ma\s+yap)?|incele(?:me\s+yap)?|analiz\s+et)(?:\s|$)/u.test(clause) ||
            /(?:dosyaları|dosyalarda|dosya)\s+(?:değiştirme|düzenleme|değişiklik\s+yapma)(?:\s|$)/u.test(clause);
    });
}
