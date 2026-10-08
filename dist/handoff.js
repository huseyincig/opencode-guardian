/**
 * OpenCode Coordination Handoff Protocol (v1)
 * Enables decoupled, autonomous collaboration between OpenCode Guardian and Smart Questions.
 */
import { createHash } from "node:crypto";
export const OPENCODE_HANDOFF_HEADER = "[OPENCODE_HANDOFF:v1]";
export const COORDINATION_SYMBOL = Symbol.for("opencode.coordination.v1");
/**
 * Format an OpenCode handoff descriptor to the versioned text protocol block.
 */
export function formatOpenCodeHandoff(handoff) {
    return [
        OPENCODE_HANDOFF_HEADER,
        "source=guardian",
        `action=${handoff.action}`,
        `kind=${handoff.kind}`,
        `auto_select=${handoff.autoSelect}`,
        `handoff_id=${handoff.handoffId}`,
    ].join("\n");
}
/**
 * Parse an OpenCode handoff block from remediation or message text.
 */
export function parseOpenCodeHandoff(text) {
    const match = /\[OPENCODE_HANDOFF:v1\]\s*([\s\S]*?)(?:\n\n|\r\n\r\n|$)/.exec(text);
    if (!match || !match[1])
        return null;
    const lines = match[1].split(/\r?\n/);
    const map = new Map();
    for (const line of lines) {
        const eq = line.indexOf("=");
        if (eq > 0) {
            map.set(line.slice(0, eq).trim().toLowerCase(), line.slice(eq + 1).trim());
        }
    }
    const source = map.get("source");
    const action = map.get("action");
    const kind = map.get("kind");
    const autoSelect = map.get("auto_select");
    const handoffId = map.get("handoff_id");
    if (source !== "guardian" || action !== "question_required" || !handoffId) {
        return null;
    }
    if (kind !== "clarification" && kind !== "choice" && kind !== "approval") {
        return null;
    }
    if (autoSelect !== "allowed" && autoSelect !== "forbidden") {
        return null;
    }
    return {
        version: "v1",
        source: "guardian",
        action: "question_required",
        kind,
        autoSelect,
        handoffId,
    };
}
/**
 * Analyze blocking rule results and produce an appropriate question handoff if user input/choice is required.
 * Relies strictly on rules explicitly requesting handoff through `result.handoff`.
 */
export function createHandoffForBlockingResults(results, sessionID, turnKey, sequence = 1) {
    const blockingResults = results.filter((r) => r.decision === "block");
    if (blockingResults.length === 0)
        return null;
    const ruleIds = blockingResults.map((r) => r.ruleId);
    const handoffRequests = blockingResults
        .map((r) => r.handoff)
        .filter((h) => Boolean(h && h.required));
    let kind = null;
    let autoSelect = "allowed";
    if (handoffRequests.length > 0) {
        if (handoffRequests.some((h) => h.kind === "approval" || h.autoSelect === "forbidden")) {
            kind = "approval";
            autoSelect = "forbidden";
        }
        else if (handoffRequests.some((h) => h.kind === "choice")) {
            kind = "choice";
            autoSelect = "allowed";
        }
        else if (handoffRequests.some((h) => h.kind === "clarification")) {
            kind = "clarification";
            autoSelect = "allowed";
        }
    }
    if (!kind)
        return null;
    const handoffHash = createHash("sha256")
        .update(`${sessionID}:${turnKey}:${sequence}:${ruleIds.join(",")}`)
        .digest("hex")
        .slice(0, 10);
    const handoffId = `gq_${handoffHash}`;
    return {
        version: "v1",
        source: "guardian",
        action: "question_required",
        kind,
        autoSelect,
        handoffId,
    };
}
let guardianRegistrationCount = 0;
let previousGuardianCapability;
/**
 * Register Guardian capability in the global OpenCode coordination registry.
 * Returns an idempotent cleanup that restores the prior registration after the
 * last Guardian instance unloads.
 */
export function registerGuardianCapability() {
    const globalObj = globalThis;
    const root = (globalObj[COORDINATION_SYMBOL] ??= {});
    if (guardianRegistrationCount === 0) {
        previousGuardianCapability = root.guardian
            ? { ...root.guardian }
            : undefined;
    }
    guardianRegistrationCount += 1;
    root.guardian = {
        version: 1,
        supportsHandoff: true,
    };
    let disposed = false;
    return () => {
        if (disposed)
            return;
        disposed = true;
        guardianRegistrationCount = Math.max(0, guardianRegistrationCount - 1);
        if (guardianRegistrationCount > 0)
            return;
        const currentRoot = globalObj[COORDINATION_SYMBOL];
        if (!currentRoot) {
            previousGuardianCapability = undefined;
            return;
        }
        if (previousGuardianCapability) {
            currentRoot.guardian = previousGuardianCapability;
        }
        else {
            delete currentRoot.guardian;
        }
        previousGuardianCapability = undefined;
        if (!currentRoot.guardian && !currentRoot.smartQuestions) {
            delete globalObj[COORDINATION_SYMBOL];
        }
    };
}
/**
 * Check if Smart Questions is registered in the in-process capability registry.
 */
export function getSmartQuestionsCapability() {
    const globalObj = globalThis;
    return globalObj[COORDINATION_SYMBOL]?.smartQuestions;
}
