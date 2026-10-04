import type { GuardRule } from "../types.js";
export declare const DEFAULT_HEDGING_PATTERNS: string[];
export declare const DEFAULT_CODE_MARKERS: string[];
export declare const DEFAULT_CODE_MARKER_REGEXES: {
    marker: string;
    regex: RegExp;
}[];
export declare const DEFAULT_EXCEPTIONS: string[];
export declare function explicitlyAuthorizedStubOrPlaceholder(text?: string): boolean;
export declare const noShortcutsRule: GuardRule;
