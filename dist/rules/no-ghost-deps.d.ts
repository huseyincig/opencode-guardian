import type { GuardRule } from "../types.js";
export declare function clearDeclaredDepsCache(): void;
export declare function isHallucinatedOrSuspiciousPackage(ecosystemOrName: string, name?: string): boolean;
export declare const noGhostDepsRule: GuardRule;
