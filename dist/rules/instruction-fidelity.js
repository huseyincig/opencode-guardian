import { currentHumanMessage, isExploratoryPrompt } from "../task-contract.js";
import { sanitizeProseForInspection } from "../prose.js";
import { detectInternationalHistoricalRefusal } from "../locale-intents.js";
const ACTION = /\b(?:implement|fix|change|modify|build|develop|resume|continue|write|create|add|update|complete|do|start)\b|\b(?:yap|yapın|uygula|uygulayın|düzelt|düzeltin|geliştir|geliştirin|devam\s+et|başla|başlayın|ekle|ekleyin|oluştur|tamamla|tamamlayın|yaz|yazın)\b/iu;
const NEGATED_ACTION = /\b(?:do\s+not|don't|dont|never)\s+(?:implement|fix|change|build|develop|resume|continue|write|create|add|update|complete|do|start)\b|\b(?:yapma|yapmayın|uygulama|uygulamayın|düzeltme|düzeltmeyin|geliştirme|geliştirmeyin)\b/iu;
const PREVIOUS_DECISION = /\b(?:previously|earlier|before|last\s+time|already)\b[^.!?]{0,120}\b(?:pause|paused|suspend(?:ed)?|defer(?:red)?|postpone(?:d)?|cancel(?:ed)?|on\s+hold)\b|\b(?:önceden|daha\s+önce|eskiden)\b[^.!?]{0,120}\b(?:askıya\s+al|erteled|durdur|iptal|vazgeç)\w*/iu;
const REFUSAL = /\b(?:so|therefore|hence|thus|because|as\s+a\s+result)\b[^.!?]{0,100}\b(?:won't|will\s+not|cannot|can't|not\s+going\s+to|skip(?:ping)?)\b|\b(?:bu\s+yüzden|dolayısıyla|o\s+nedenle|bu\s+sebeple)\b[^.!?]{0,120}\b(?:yapmıyorum|yapmayacağım|uygulamıyorum|atlıyorum|devam\s+etmiyorum|yapamam)\b/iu;
const REDUNDANT_HANDOFF = /\b(?:would\s+you\s+like\s+me\s+to|do\s+you\s+want\s+me\s+to|should\s+i)\s+(?:proceed|continue|implement|fix|apply|run|finish|complete|start|do)\b|\b(?:devam\s+edeyim|yapayım|uygulayayım|düzelteyim|başlayayım|tamamlayayım)\s+m[ıiuü]\b|\bhangisini\s+(?:tercih\s+edersin|isters?in)\b|\bistersen\b[^.!?]{0,180}\b(?:yaparım|uygularım|düzeltirim|devam\s+ederim|başlarım|kapatırım|tamamlarım|çalıştırırım)\b/iu;
const REAL_BLOCKER_OR_REQUIRED_CHOICE = /\b(?:need|require|requires|required|missing|lack(?:ing)?|without)\b[^.!?]{0,120}\b(?:access|permission|credential|token|key|password|secret|information|details|input|decision|choice)\b|\b(?:cannot|can't|unable\s+to)\s+(?:continue|proceed)\b|\b(?:erişim|izin|yetki|kimlik\s+bilgisi|token|anahtar|parola|bilgi|detay|girdi|karar|tercih)\b[^.!?]{0,120}\b(?:gerekiyor|gerekli|eksik|olmadan|yok)\b/iu;
/** High-confidence conflicts with the current explicit action only. */
export const instructionFidelityRule = {
    id: "task/instruction-fidelity",
    description: "Detects historical refusals and redundant confirmation handoffs that conflict with the current explicit task.",
    inspect(context) {
        const user = currentHumanMessage(context.currentTurn);
        const instruction = user?.parts
            .filter((part) => part.type === "text" && typeof part.text === "string")
            .map((part) => part.text ?? "")
            .join("\n") ?? "";
        const assistant = context.currentTurn
            .findLast((message) => message.info.role === "assistant")?.parts
            .filter((part) => part.type === "text" && typeof part.text === "string")
            .map((part) => part.text ?? "")
            .join("\n") ?? "";
        const prose = sanitizeProseForInspection(assistant);
        const international = detectInternationalHistoricalRefusal(instruction, prose);
        const explicitCurrentAction = ACTION.test(instruction) &&
            !isExploratoryPrompt(instruction) &&
            !NEGATED_ACTION.test(instruction);
        const originalPattern = explicitCurrentAction &&
            PREVIOUS_DECISION.test(prose) &&
            REFUSAL.test(prose);
        const observableWork = context.evidence?.records.some((record) => record.status === "success") ?? false;
        const redundantHandoff = explicitCurrentAction &&
            !observableWork &&
            REDUNDANT_HANDOFF.test(prose) &&
            !REAL_BLOCKER_OR_REQUIRED_CHOICE.test(prose);
        if (!originalPattern && !international && !redundantHandoff) {
            return { ruleId: this.id, decision: "pass", findings: [] };
        }
        if (redundantHandoff) {
            const finding = {
                ruleId: this.id,
                pattern: "redundant confirmation after explicit action",
                messageSnippet: prose.slice(0, 200),
                description: "The user already gave an explicit action instruction, but the assistant handed the decision back without observable work or a concrete blocker.",
                confidence: "high",
            };
            return {
                ruleId: this.id,
                decision: "block",
                findings: [finding],
                remediationPrompt: "The current user already authorized the requested action. Continue the work instead of asking for redundant confirmation. Ask only when a concrete missing permission, credential, required input, or genuinely unresolved technical choice prevents safe progress.",
            };
        }
        // If the agent actually modified files, a multilingual refusal might
        // refer to a different part of the work. Report it, do not auto-retry.
        const performedAction = context.evidence?.fileMutations.some((record) => record.status === "success") ?? false;
        const advisory = Boolean(international && performedAction && !originalPattern);
        const finding = {
            ruleId: this.id,
            pattern: international
                ? `past decision overrides current instruction (${international})`
                : "past decision overrides current instruction",
            messageSnippet: prose.slice(0, 200),
            description: "The assistant explicitly declined the current requested action on the basis of an earlier user decision. The latest explicit instruction must be considered; an actual conflict should be explained rather than silently changing scope.",
            confidence: advisory ? "medium" : "high",
        };
        return {
            ruleId: this.id,
            decision: advisory ? "pass" : "block",
            findings: [finding],
            ...(advisory ? {} : {
                remediationPrompt: "Re-evaluate the current explicit user request. Do not treat an earlier pause or deferral as a permanent prohibition. Perform the requested work if otherwise permitted; if a genuine conflict prevents it, identify the conflicting instruction precisely and ask the user rather than silently declining.",
            }),
        };
    },
};
