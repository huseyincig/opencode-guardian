import { type GuardianInterventionInput } from "./toast.js";
export declare const GUARDIAN_VISIBLE_INTERVENTION_KEY = "opencode-guardian-visible";
export declare function formatGuardianTranscriptMessage(input: GuardianInterventionInput): string;
export declare function isGuardianVisibleInterventionMetadata(metadata: unknown): boolean;
