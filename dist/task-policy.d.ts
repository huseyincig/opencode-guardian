import type { EvidenceRecord, TurnEvidence } from "./types.js";
import type { TaskContract } from "./task-contract.js";
type VerificationKind = TaskContract["requiredVerifications"][number];
export interface VerificationDecision {
    kind: VerificationKind;
    status: "passed" | "failed" | "unknown";
    /** The newest post-change record, if one is available. */
    evidence?: EvidenceRecord;
}
export interface TaskPolicyDecision {
    /** No natural-language parsing occurs within this policy evaluator. */
    lastMutationSequence: number;
    review: "not-required" | "no-mutation" | "observed" | "missing";
    /** Observable inspection is not proof of exhaustively auditing a repository. */
    reviewProvesFullCoverage: false;
    verifications: VerificationDecision[];
}
/**
 * Deterministic, language-independent policy evaluation on a canonical task
 * contract and already-normalized tool evidence. This layer neither guesses
 * intent nor interprets the assistant's prose. A Rego/Wasm policy adapter
 * could consume the same structured input without replacing host adapters.
 */
export declare function evaluateTaskPolicy(contract: TaskContract, evidence: TurnEvidence, directory?: string): TaskPolicyDecision;
export {};
