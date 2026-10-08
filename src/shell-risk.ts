/**
 * Conservative shell-pattern inspection, not an interpreter or a permission
 * boundary. Recognize common literal shell rewrites without executing input.
 */
/**
 * Split only on top-level shell separators. Quoted examples and separators
 * inside command substitutions must not become independently executed stages.
 */
export function splitShellStages(command: string): string[][] {
  const groups: string[][] = [];
  let pipeline: string[] = [];
  let segment = "";
  let quote: "'" | '"' | null = null;
  let substitutionDepth = 0;
  const pushStage = () => {
    if (segment.trim()) pipeline.push(segment.trim());
    segment = "";
  };
  const pushPipeline = () => {
    pushStage();
    if (pipeline.length) groups.push(pipeline);
    pipeline = [];
  };

  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (ch === "\\" && quote !== "'") {
      segment += ch + (command[++i] ?? "");
      continue;
    }
    if (ch === "'" && quote !== '"') {
      quote = quote === "'" ? null : "'";
    } else if (ch === '"' && quote !== "'") {
      quote = quote === '"' ? null : '"';
    }
    if (ch === "$" && command[i + 1] === "(" && quote !== "'") {
      substitutionDepth++;
      segment += "$(";
      i++;
      continue;
    }
    if (substitutionDepth && quote !== "'") {
      if (ch === "(") substitutionDepth++;
      if (ch === ")") substitutionDepth--;
    }
    if (!quote && !substitutionDepth) {
      if (ch === "|" && command[i + 1] !== "|") {
        pushStage();
        continue;
      }
      if (ch === ";" || ch === "\n" || ch === "&" || (ch === "|" && command[i + 1] === "|")) {
        pushPipeline();
        if ((ch === "&" || ch === "|") && command[i + 1] === ch) i++;
        continue;
      }
    }
    segment += ch;
  }
  pushPipeline();
  return groups;
}

export function shellCommandVariants(command: string): string[] {
  return splitShellStages(command).flatMap((stages) => stages.flatMap((stage) => {
    const canonical = stage
      // Empty quote pairs and escaped command letters disappear in the shell.
      .replace(/(?<!\\)(?:''|"")/g, "")
      .replace(/\\([A-Za-z])/g, "$1")
      // A literal IFS expansion can separate shell arguments.
      .replace(/\$\{IFS\}|\$IFS(?=[^A-Za-z0-9_]|$)/g, " ")
      // Only resolve a known literal command name, not arbitrary substitutions.
      .replace(/\$\(\s*(?:echo|printf(?:\s+%s)?)\s+(?:(["'])rm\1|rm)\s*\)/gi, "rm");
    // A literal backtick substitution in command position supplies the
    // executable name. This is unlike a passive \`echo \`...\`\` example.
    const expanded = canonical.replace(
      /^(\s*(?:sudo\s+)?)(?:\x60(?:echo\s+|printf(?:\s+%s)?\s+)(?:['"]?rm['"]?)\x60)(?=\s|$)/i,
      "$1rm"
    );
    return [...new Set([stage, canonical, expanded])];
  }));
}

/** Only active $(...) expressions; text inside single quotes is inert. */
export function activeCommandSubstitutions(command: string): string[] {
  const found: string[] = [];
  let quote: "'" | '"' | null = null;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (ch === "\\" && quote !== "'") {
      i++;
      continue;
    }
    if (ch === "'" && quote !== '"') {
      quote = quote === "'" ? null : "'";
      continue;
    }
    if (ch === '"' && quote !== "'") {
      quote = quote === '"' ? null : '"';
      continue;
    }
    if (quote === "'" || ch !== "$" || command[i + 1] !== "(") continue;
    const start = i + 2;
    let depth = 1;
    let nestedQuote: "'" | '"' | null = null;
    let end = start;
    for (; end < command.length; end++) {
      const next = command[end];
      if (next === "\\" && nestedQuote !== "'") {
        end++;
        continue;
      }
      if (next === "'" && nestedQuote !== '"') {
        nestedQuote = nestedQuote === "'" ? null : "'";
        continue;
      }
      if (next === '"' && nestedQuote !== "'") {
        nestedQuote = nestedQuote === '"' ? null : '"';
        continue;
      }
      if (nestedQuote) continue;
      if (next === "(") depth++;
      if (next === ")" && --depth === 0) break;
    }
    if (depth === 0) {
      found.push(command.slice(start, end));
      i = end;
    }
  }
  return found;
}

/** Only active paired backtick substitutions; single-quoted text and escaped
 * delimiters are inert. The returned script is classified, never executed. */
export function activeBacktickSubstitutions(command: string): string[] {
  const scripts: string[] = [];
  let quote: "'" | '"' | null = null;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (ch === "\\" && quote !== "'") {
      i++;
      continue;
    }
    if (ch === "'" && quote !== '"') {
      quote = quote === "'" ? null : "'";
      continue;
    }
    if (ch === '"' && quote !== "'") {
      quote = quote === '"' ? null : '"';
      continue;
    }
    if (ch !== "\x60" || quote === "'") continue;
    let end = i + 1;
    for (; end < command.length; end++) {
      if (command[end] === "\\") {
        end++;
        continue;
      }
      if (command[end] === "\x60") break;
    }
    if (end < command.length) {
      scripts.push(command.slice(i + 1, end));
      i = end;
    }
  }
  return scripts;
}

/** Literal script passed to a shell; dynamic scripts are not decoded here. */
export function literalShellScripts(command: string): string[] {
  const scripts: string[] = [];
  // Match literal shell scripts, including common sudo wrappers and -lc.
  // Opposite quote types and newlines are legal inside an outer quoted script.
  const pattern = /^\s*(?:sudo\s+)?(?:env\s+)?(?:sh|bash|zsh|dash)\s+-[a-z]*c[a-z]*\s+(?:'([^']*)'|"((?:\\.|[^"\\])*)")(?=\s|$)/i;
  for (const stage of splitShellStages(command).flat()) {
    const match = pattern.exec(stage);
    const script = match?.[1] ?? match?.[2];
    if (script !== undefined) scripts.push(script);
  }
  return scripts;
}

function unwrapLiteralWindowsScript(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2) {
    const first = trimmed[0];
    const last = trimmed.at(-1);
    if ((first === '"' || first === "'") && first === last) {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

/** Literal scripts passed through Windows command interpreters. Encoded
 * PowerShell payloads are intentionally not decoded and are treated opaque. */
export function literalWindowsShellScripts(command: string): string[] {
  const scripts: string[] = [];
  for (const stage of splitShellStages(command).flat()) {
    const cmd = /^\s*(?:cmd(?:\.exe)?)\s+\/[ck]\s+([\s\S]+)$/i.exec(stage);
    if (cmd?.[1]) {
      scripts.push(unwrapLiteralWindowsScript(cmd[1]));
      continue;
    }

    const powershell =
      /^\s*(?:powershell|pwsh)(?:\.exe)?\b[\s\S]*?\s-(?:command|c)\s+([\s\S]+)$/i.exec(stage);
    if (powershell?.[1]) {
      scripts.push(unwrapLiteralWindowsScript(powershell[1]));
    }
  }
  return scripts;
}

/** Find's deletion actions do not require the rm binary to run directly. */
export function hasFindDeletion(command: string): boolean {
  return splitShellStages(command).flat().some((stage) =>
    /^\s*(?:sudo\s+)?find\b[^\n;&|]*\s(?:-delete\b|-exec(?:dir)?\s+(?:sudo\s+)?(?:rm|unlink)\b)/i.test(stage)
  );
}

/**
 * Decoding into a shell conceals the executed script. This is a warning
 * signal only: it does not prove that the decoded payload is destructive.
 */
export function isOpaqueShellExecution(command: string): boolean {
  if (
    splitShellStages(command).flat().some((stage) =>
      /^\s*(?:powershell|pwsh)(?:\.exe)?\b[\s\S]*?\s-(?:encodedcommand|enc)\b/i.test(stage)
    )
  ) {
    return true;
  }
  return splitShellStages(command).some((stages) =>
    stages.some((stage, index) =>
      /^\s*(?:sudo\s+)?(?:env\s+)?(?:openssl\s+)?base64\s+(?:-[dD]\b|--decode\b)/i.test(stage) &&
      /^\s*(?:sudo\s+)?(?:env\s+)?(?:sh|bash|zsh|dash)(?=\s|$)/i.test(stages[index + 1] ?? "")
    )
  );
}


/** An unresolved command substitution in executable position is opaque.
 * The strict preflight can reject it without treating ordinary echo output
 * or quoted documentation as a destructive action. */
export function hasDynamicCommandName(command: string, depth = 0): boolean {
  for (const stage of splitShellStages(command).flat()) {
    if (/^\s*(?:sudo\s+)?(?:"|)(?:\x60|\$\(|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)/.test(stage)) {
      return true;
    }
  }
  return depth < 4 && [
    ...literalShellScripts(command),
    ...literalWindowsShellScripts(command),
  ].some((script) => hasDynamicCommandName(script, depth + 1));
}
