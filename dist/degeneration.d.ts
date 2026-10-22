/**
 * opencode-guardian: Degenerative Loop & Token Cycle Detection
 *
 * Detects degenerate model generation cycles (e.g., DeepSeek "full Hmm",
 * Kimi repeating Chinese/Japanese token cascades, runaway punctuation, or
 * repeating code tokens like "None, None, None...") in assistant text and reasoning.
 *
 * Language-agnostic, zero external dependencies, strictly bounded O(1) tail
 * inspection (< 0.02 ms per check).
 */
export interface DegenerativeLoopDetection {
    detected: boolean;
    pattern?: string;
    repetitions?: number;
    span?: number;
    kind?: "periodic-cycle" | "low-entropy";
    sample?: string;
}
export interface DegenerationOptions {
    /** Maximum tail characters to inspect (default: 500). */
    maxTailLength?: number;
    /** Minimum text length to trigger inspection (default: 30). */
    minLength?: number;
}
/**
 * Inspects a text string or reasoning trace for degenerative token or phrase repetitions.
 *
 * @param text The string content to inspect.
 * @param options Optional configuration overrides.
 * @returns Detection result including pattern, repetitions, and span.
 */
export declare function detectDegenerativeLoop(text: unknown, options?: DegenerationOptions): DegenerativeLoopDetection;
