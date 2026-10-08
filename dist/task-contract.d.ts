import type { EvidenceRecord, SessionMessage, TurnEvidence } from "./types.js";
export { isExploratoryPrompt } from "./locale-intents.js";
/** Explicit user requirements only. No LLM classification or inferred goals. */
export interface TaskContract {
    turnKey: string;
    explicitAction: boolean;
    iterativeReview: boolean;
    requiresSourceReview: boolean;
    requiredVerifications: Array<"test" | "build" | "typecheck" | "lint" | "audit">;
    requiresExplicitCompletion: boolean;
    /** Optional locale of explicit multilingual signals. Not a universal language detector. */
    signalLocale?: string;
}
export declare function currentHumanMessage(messages: readonly SessionMessage[]): SessionMessage | undefined;
/** Optional, human-authored typed protocol when free-form intent is unclear. */
export interface ExplicitTaskDirective {
    mode: "iterative-review" | "one-pass";
    review: "source" | "checks";
    verify: TaskContract["requiredVerifications"];
}
/** Only an exact first-line directive is accepted; examples in code do not count. */
export declare function parseExplicitTaskDirective(text: string): ExplicitTaskDirective | undefined;
export declare function extractTaskContract(messages: readonly SessionMessage[]): TaskContract | undefined;
export declare function taskGuidance(contract: TaskContract): string | undefined;
export declare function latestMutationSequence(evidence: TurnEvidence): number;
export declare function isSourceReviewEvidence(record: EvidenceRecord): boolean;
export declare function hasPostMutationReview(evidence: TurnEvidence, sourceReviewRequired?: boolean): boolean;
