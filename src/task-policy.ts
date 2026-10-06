import type { EvidenceRecord, TurnEvidence } from "./types.js";
import type { TaskContract } from "./task-contract.js";
import { hasPostMutationReview, latestMutationSequence } from "./task-contract.js";

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
export function evaluateTaskPolicy(
  contract: TaskContract,
  evidence: TurnEvidence
): TaskPolicyDecision {
  const lastMutationSequence = latestMutationSequence(evidence);
  const review: TaskPolicyDecision["review"] = !contract.iterativeReview
    ? "not-required"
    : lastMutationSequence < 0
      ? "no-mutation"
      : hasPostMutationReview(evidence, contract.requiresSourceReview)
        ? "observed"
        : "missing";
  const verifications = contract.requiredVerifications.map((kind) => {
    // A verification from the same tool call as a mutation cannot prove
    // whether it ran before or after that mutation. Require a later call.
    const record = evidence.records
      .filter((candidate) =>
        candidate.kind === kind && candidate.sequence > lastMutationSequence
      )
      .sort((left, right) => right.sequence - left.sequence)[0];
    const status: VerificationDecision["status"] =
      record?.status === "success"
        ? "passed"
        : record?.status === "failure"
          ? "failed"
          : "unknown";
    return { kind, status, ...(record ? { evidence: record } : {}) };
  });
  return {
    lastMutationSequence,
    review,
    reviewProvesFullCoverage: false,
    verifications,
  };
}
