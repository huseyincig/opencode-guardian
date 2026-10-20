import type { SessionMessage, TurnInspectionContext } from "./types.js";
/** Human text only; generated reminders and tool output cannot grant authority. */
export declare function humanInstructionText(message: SessionMessage | undefined): string;
export declare function latestHumanInstruction(context: TurnInspectionContext): string;
/** Strip examples/comments while preserving literal inline command targets. */
export declare function authorizationText(text: string): string;
/** Deliberately narrow English/Turkish constraints, not inferred task goals. */
export declare function hasResearchOnlyConstraint(instruction: string): boolean;
