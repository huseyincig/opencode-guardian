import { hasPostMutationReview, latestMutationSequence } from "./task-contract.js";
/**
 * Deterministic, language-independent policy evaluation on a canonical task
 * contract and already-normalized tool evidence. This layer neither guesses
 * intent nor interprets the assistant's prose. A Rego/Wasm policy adapter
 * could consume the same structured input without replacing host adapters.
 */
export function evaluateTaskPolicy(contract, evidence) {
    const lastMutationSequence = latestMutationSequence(evidence);
    const review = !contract.iterativeReview
        ? "not-required"
        : lastMutationSequence < 0
            ? "no-mutation"
            : hasPostMutationReview(evidence, contract.requiresSourceReview)
                ? "observed"
                : "missing";
    const verifications = contract.requiredVerifications.map((kind) => {
        const record = evidence.records
            .filter((candidate) => candidate.kind === kind && candidate.sequence >= lastMutationSequence)
            .sort((left, right) => right.sequence - left.sequence)[0];
        const status = record?.status === "success"
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
