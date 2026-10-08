export function extractToolCommand(
  input: Record<string, unknown>
): string {
  return typeof input.command === "string"
    ? input.command
    : typeof input.cmd === "string"
      ? input.cmd
      : typeof input.script === "string"
        ? input.script
        : typeof input.executable === "string" &&
            input.executable.trim() &&
            (input.args === undefined ||
              (Array.isArray(input.args) &&
                input.args.every((arg) => typeof arg === "string")))
          ? [
              input.executable.trim(),
              ...((input.args as string[] | undefined) ?? []),
            ].join(" ")
          : "";
}

/**
 * Returns shell source only when the command appears to mutate file contents.
 * This covers common heredoc/redirection and in-place scripting paths without
 * treating ordinary read-only shell commands as file writes.
 */
export function extractLikelyShellMutation(
  input: Record<string, unknown>
): string {
  const command = extractToolCommand(input);
  if (!command) return "";

  const mutatesFile =
    /(?:^|[;&|]\s*|\n)\s*(?:cat|printf|echo)\b[\s\S]*?(?<!\d)>{1,2}\s*(?!&)(?!\/dev\/null\b)\S+/im.test(
      command
    ) ||
    /\btee(?:\s+-a)?\s+(?!\/dev\/null\b)\S+/i.test(command) ||
    /\bsed\b[^\n;]*\s-i(?:\s|['"]|$)/i.test(command) ||
    /\bperl\b[^\n;]*\s-(?:pi|ip)\b/i.test(command) ||
    /\b(?:python(?:3)?|node)\b[\s\S]*(?:writeFile(?:Sync)?|appendFile(?:Sync)?|write_text|write_bytes|open\s*\([^)]*,\s*["'][wax])/i.test(
      command
    );

  return mutatesFile ? command : "";
}

export interface StructuredEditText {
  text: string;
  filePath?: string;
}

/**
 * Normalizes replacement text embedded in structured edit arrays.
 * Providers use several field aliases; rules should inspect the replacement
 * payload rather than treating the outer edits array as opaque.
 */
export function extractStructuredEditTexts(
  input: Record<string, unknown>,
  defaultFilePath?: string
): StructuredEditText[] {
  if (!Array.isArray(input.edits)) return [];

  const output: StructuredEditText[] = [];
  for (const raw of input.edits) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const edit = raw as Record<string, unknown>;
    const filePath =
      (typeof edit.path === "string" ? edit.path : undefined) ??
      (typeof edit.targetFile === "string" ? edit.targetFile : undefined) ??
      (typeof edit.filePath === "string" ? edit.filePath : undefined) ??
      (typeof edit.file === "string" ? edit.file : undefined) ??
      defaultFilePath;

    for (const key of [
      "content",
      "text",
      "new_text",
      "newText",
      "replacement",
      "new_string",
      "newString",
    ]) {
      const value = edit[key];
      if (typeof value !== "string" || value.length === 0) continue;
      output.push({
        text: value,
        ...(filePath ? { filePath } : {}),
      });
    }
  }
  return output;
}
