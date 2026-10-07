import { currentHumanMessage } from "../task-contract.js";
import { sanitizeProseForInspection } from "../prose.js";
import { detectInstructionFidelitySignals } from "../locale-intents.js";
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
        const observableWork = context.evidence?.records.some((record) => record.status === "success") ?? false;
        const signals = detectInstructionFidelitySignals(instruction, prose, observableWork);
        if (!signals.hasViolation) {
            return { ruleId: this.id, decision: "pass", findings: [] };
        }
        if (signals.type === "redundant-handoff") {
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
        const advisory = Boolean(signals.internationalLocale && performedAction);
        const finding = {
            ruleId: this.id,
            pattern: signals.internationalLocale
                ? `past decision overrides current instruction (${signals.internationalLocale})`
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
