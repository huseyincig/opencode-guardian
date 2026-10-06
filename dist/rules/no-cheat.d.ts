import type { GuardRule } from "../types.js";
/**
 * High-confidence patterns that directly disable or bypass tests.
 */
export declare const TEST_CHEAT_PATTERNS: {
    regex: RegExp;
    name: string;
    alwaysBlock?: boolean;
}[];
export declare function explicitlyAuthorizedTestEdit(text?: string): boolean;
export declare const noCheatRule: GuardRule;
