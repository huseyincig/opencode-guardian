import type { PreflightAssessment } from './types.js';
/**
 * Assesses a shell tool command input for high-risk broad environment dumps.
 */
export declare function assessCommandPreflight(command: unknown): PreflightAssessment;
