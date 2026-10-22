/**
 * opencode-guardian: Degenerative Loop & Token Cycle Detection
 *
 * Detects degenerate model generation cycles (e.g., DeepSeek "full Hmm",
 * Kimi repeating Chinese/Japanese token cascades, runaway punctuation, or
 * repeating code tokens like "None, None, None...") in assistant text and reasoning.
 *
 * Language-agnostic, zero external dependencies, strictly bounded O(1) tail
 * inspection. Actual latency depends on the host and inspected patterns.
 */
const SEPARATOR_CHARS = new Set([
    "-", "=", "*", "_", "#", "/", "|", "~", "`", " ", "\t", "\n", "\r", ":", "+",
]);
function isSyntaxDivider(str) {
    for (let i = 0; i < str.length; i++) {
        const ch = str[i];
        if (ch === undefined || !SEPARATOR_CHARS.has(ch))
            return false;
    }
    return true;
}
const HAS_LETTER_OR_IDEOGRAM = /\p{L}/u;
/**
 * Inspects a text string or reasoning trace for degenerative token or phrase repetitions.
 *
 * @param text The string content to inspect.
 * @param options Optional configuration overrides.
 * @returns Detection result including pattern, repetitions, and span.
 */
export function detectDegenerativeLoop(text, options) {
    if (typeof text !== "string") {
        return { detected: false };
    }
    const minLength = Math.max(30, Math.min(2048, Math.trunc(options?.minLength ?? 30) || 30));
    if (text.length < minLength) {
        return { detected: false };
    }
    const maxTailLength = Math.max(30, Math.min(2048, Math.trunc(options?.maxTailLength ?? 2048) || 2048));
    // Ignore bounded numeric/hex literals, including incomplete streamed literals.
    // Longer runs remain eligible: a growing output cannot hide forever in a quote.
    const tail = text.slice(-maxTailLength).replace(/(["'])[0-9a-fA-F]{15,128}(?:\1|$)/g, match => " ".repeat(match.length));
    // 1. Suffix offset tolerance (0 to 3 chars for trailing partial tokens / punctuation)
    for (let offset = 0; offset <= 3; offset++) {
        const candidate = offset === 0 ? tail : tail.slice(0, tail.length - offset);
        if (candidate.length < minLength)
            continue;
        // Bound work while supporting whole sentences and multi-code-unit Unicode.
        for (let L = 1; L <= Math.min(512, Math.floor(candidate.length / 4)); L++) {
            if (candidate.length < L * 3)
                continue;
            const pattern = candidate.slice(-L);
            // Exclude pure syntax dividers (markdown tables, comment banners, horizontal rules)
            if (isSyntaxDivider(pattern))
                continue;
            // Count contiguous repetitions backwards
            let k = 0;
            let pos = candidate.length;
            while (pos >= L && candidate.slice(pos - L, pos) === pattern) {
                k++;
                pos -= L;
            }
            const span = k * L;
            const hasWordChar = HAS_LETTER_OR_IDEOGRAM.test(pattern);
            // Threshold rules:
            if (L === 1) {
                if (hasWordChar && k >= 15) {
                    return {
                        detected: true,
                        pattern,
                        repetitions: k,
                        span,
                        kind: "periodic-cycle",
                        sample: pattern.repeat(Math.min(k, 5)),
                    };
                }
                if (!hasWordChar && k >= 30) {
                    return {
                        detected: true,
                        pattern,
                        repetitions: k,
                        span,
                        kind: "periodic-cycle",
                        sample: pattern.repeat(Math.min(k, 5)),
                    };
                }
            }
            else if (L >= 2 && L <= 6) {
                if (hasWordChar && k >= 5 && span >= 25) {
                    return {
                        detected: true,
                        pattern,
                        repetitions: k,
                        span,
                        kind: "periodic-cycle",
                        sample: pattern.repeat(Math.min(k, 4)),
                    };
                }
                // Non-word patterns (e.g. repeated numbers or symbols) require higher threshold
                if (!hasWordChar && k >= 15 && span >= 45) {
                    return {
                        detected: true,
                        pattern,
                        repetitions: k,
                        span,
                        kind: "periodic-cycle",
                        sample: pattern.repeat(Math.min(k, 4)),
                    };
                }
            }
            else if (L >= 7 && L <= 20) {
                if (hasWordChar && k >= 5 && span >= 40) {
                    return {
                        detected: true,
                        pattern,
                        repetitions: k,
                        span,
                        kind: "periodic-cycle",
                        sample: pattern.repeat(Math.min(k, 3)),
                    };
                }
            }
            else if (L >= 21) {
                if (hasWordChar && k >= 4 && span >= 85) {
                    return {
                        detected: true,
                        pattern,
                        repetitions: k,
                        span,
                        kind: "periodic-cycle",
                        sample: pattern.repeat(Math.min(k, 3)),
                    };
                }
            }
        }
    }
    // 2. Secondary Low-Entropy check (non-periodic babble / collapse)
    const nonWsChars = tail.replace(/\s+/g, "");
    if (nonWsChars.length >= 60) {
        const tailChunk = nonWsChars.slice(-60);
        const unique = new Set(tailChunk);
        if (unique.size <= 2 && !isSyntaxDivider(tailChunk)) {
            return {
                detected: true,
                pattern: [...unique].sort().join(""),
                repetitions: tailChunk.length,
                span: tailChunk.length,
                kind: "low-entropy",
                sample: tailChunk.slice(0, 30),
            };
        }
    }
    return { detected: false };
}
