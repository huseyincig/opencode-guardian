/**
 * A bounded lexical view for pattern checks, not a language parser. Offsets and
 * line breaks stay stable. String delimiters remain for call-shape patterns;
 * literal contents (including template bodies) never become executable code.
 */
export function maskCodeLiterals(source, keepComments = false, filePath) {
    if (source.length > 2 * 1024 * 1024)
        return "";
    const output = source.split("");
    const blank = (start, end) => {
        for (let at = start; at < end; at++) {
            if (source[at] !== "\n" && source[at] !== "\r")
                output[at] = " ";
        }
    };
    const javascript = /\.[cm]?[jt]sx?$/i.test(filePath ?? "");
    let i = 0;
    const quoted = (quote) => {
        const triple = quote !== "`" && source.slice(i, i + 3) === quote.repeat(3);
        const width = triple ? 3 : 1;
        const start = i + width;
        i = start;
        while (i < source.length) {
            if (source[i] === "\\") {
                i += 2;
                continue;
            }
            if (source.slice(i, i + width) === quote.repeat(width))
                break;
            i++;
        }
        blank(start, Math.min(i, source.length));
        i += width;
    };
    const scan = (expression = false, nesting = 0) => {
        let braces = 0;
        while (i < source.length) {
            const ch = source[i];
            if (ch === "'" || ch === '"') {
                quoted(ch);
                continue;
            }
            if (ch === "`") {
                i++;
                while (i < source.length) {
                    if (source[i] === "\\") {
                        blank(i, Math.min(i + 2, source.length));
                        i += 2;
                        continue;
                    }
                    if (source[i] === "`") {
                        i++;
                        break;
                    }
                    if (source.startsWith("${", i)) {
                        blank(i, i + 2);
                        i += 2;
                        if (nesting >= 32) {
                            blank(i, source.length);
                            i = source.length;
                            break;
                        }
                        scan(true, nesting + 1);
                    }
                    else {
                        blank(i, i + 1);
                        i++;
                    }
                }
                continue;
            }
            if (source.startsWith("//", i) || !javascript && ch === "#" && source[i + 1] !== "[") {
                const end = source.indexOf("\n", i);
                const until = end < 0 ? source.length : end;
                if (!keepComments)
                    blank(i, until);
                i = until;
                continue;
            }
            if (source.startsWith("/*", i)) {
                const end = source.indexOf("*/", i + 2);
                const until = end < 0 ? source.length : end + 2;
                if (!keepComments)
                    blank(i, until);
                i = until;
                continue;
            }
            // Recognize common JS regex literals in expression-start positions.
            if (ch === "/" && /(?:^|[=(:,!&|?;{}[]|\breturn)\s*$/.test(source.slice(Math.max(0, i - 30), i))) {
                const start = i++;
                let inClass = false;
                while (i < source.length && source[i] !== "\n") {
                    if (source[i] === "\\") {
                        i += 2;
                        continue;
                    }
                    if (source[i] === "[")
                        inClass = true;
                    if (source[i] === "]")
                        inClass = false;
                    if (source[i++] === "/" && !inClass)
                        break;
                }
                blank(start, i);
                continue;
            }
            if (expression && ch === "}") {
                if (braces === 0) {
                    blank(i, i + 1);
                    i++;
                    return;
                }
                braces--;
            }
            else if (expression && ch === "{")
                braces++;
            i++;
        }
    };
    scan();
    return output.join("");
}
/** Literal configured exceptions only exempt the span they cover. */
export function withinConfiguredException(text, index, length, exceptions) {
    const lower = text.toLowerCase();
    return exceptions.some((exception) => {
        const phrase = exception.trim().toLowerCase();
        if (!phrase)
            return false;
        let at = lower.indexOf(phrase);
        while (at >= 0 && at <= index) {
            if (at + phrase.length >= index + length)
                return true;
            at = lower.indexOf(phrase, at + 1);
        }
        return false;
    });
}
