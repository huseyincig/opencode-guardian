import type { GuardRule } from "../types.js";
export declare const SECRET_PATTERNS: {
    regex: RegExp;
    name: string;
}[];
export declare function extractFilePathFromPatch(patch: unknown): string | undefined;
export declare function extractAddedLines(text: unknown): string;
export declare function maskSecret(secret: string): string;
export declare function isExplicitTemplateValue(secretValue: string, capturedPassword?: string): boolean;
/** Documented, local-only example credentials are not real deployment secrets.
 * Never exempt token-shaped strings or remote service credentials by filename. */
export declare function isDocumentedLocalPasswordSample(filePath: string | undefined, value: string, password: string | undefined): boolean;
export interface DetectedSecret {
    name: string;
    secretValue: string;
    masked: string;
}
export declare function findAllSecretsInCode(code: string, filePath?: string, alreadySeen?: Set<string>): DetectedSecret[];
export declare function findSecretInCode(code: string, filePath?: string): DetectedSecret | undefined;
export declare const noSecretsRule: GuardRule;
