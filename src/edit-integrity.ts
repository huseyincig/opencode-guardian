import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { maskCodeLiterals } from "./code-context.js";

export const TRUNCATION_PLACEHOLDERS: RegExp[] = [
  /(?:\/\/|#|\/\*|<!--)\s*\.{3}\s*(?:existing|rest\s+of|remaining|previous|earlier|unchanged|keep\s+existing|other|more|code\s+here)\b/i,
  /(?:\/\/|#|\/\*|<!--)\s*(?:existing|rest\s+of|remaining|previous|earlier|unchanged)\s*(?:code|methods|functions|implementation|content|logic)\s*(?:remains|here|unchanged|as\s+is|continues)?\s*\.{3}/i,
  /(?:\/\/|#|\/\*|<!--)\s*\[?\.\.\.\s*(?:rest|existing|code|truncated)\s*(?:of\s+code)?\s*\.?\]?/i,
  /(?:\/\/|#)\s*\.{3}\s*$/m,
];

export function findTruncationPlaceholder(text: string, filePath?: string): RegExpMatchArray | null {
  if (filePath && /\.(?:md|mdx|rst|txt|json|ya?ml)$/i.test(filePath)) return null;
  if (text.length > 2 * 1024 * 1024) return null;
  const comments = maskCodeLiterals(text, true, filePath);
  for (const pattern of TRUNCATION_PLACEHOLDERS) {
    const match = pattern.exec(comments);
    if (match) return match;
  }
  return null;
}

export interface EditIntegrityEvidence {
  status: "observed" | "unavailable";
  filePath: string;
  beforeHash?: string;
  afterHash?: string;
  beforeBytes?: number;
  afterBytes?: number;
  removedDefinitions?: number;
}

export interface BeforeEditState {
  filePath: string;
  directory: string;
  hash?: string;
  bytes?: number;
  definitions?: Set<string>;
}

function fileState(directory: string, target: string): Omit<BeforeEditState, "filePath" | "directory"> {
  let fd: number | undefined;
  try {
    const root = fs.realpathSync(directory);
    const candidate = path.resolve(root, target);
    const lexical = path.relative(root, candidate);
    if (lexical === ".." || lexical.startsWith(".." + path.sep) || path.isAbsolute(lexical)) return {};
    const real = fs.realpathSync(candidate);
    const relative = path.relative(root, real);
    if (relative === ".." || relative.startsWith(".." + path.sep) || path.isAbsolute(relative)) return {};
    fd = fs.openSync(real, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > 2 * 1024 * 1024) return {};
    const buffer = Buffer.alloc(stat.size + 1);
    const length = fs.readSync(fd, buffer, 0, buffer.length, 0);
    if (length !== stat.size) return {};
    const content = buffer.subarray(0, length);
    const code = maskCodeLiterals(content.toString("utf8"), false, target);
    const definitions = new Set<string>();
    for (const match of code.matchAll(/\b(?:function\s*\*?|class|def|const|let|var)\s+([\p{L}_$][\p{L}\p{N}_$]{0,127})/gu)) {
      if (match[1]) definitions.add(match[1]);
      if (definitions.size > 1024) return {};
    }
    return { hash: createHash("sha256").update(content).digest("hex"), bytes: length, definitions };
  } catch { return {}; }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}

export function captureBeforeEdit(tool: string, input: Record<string, unknown>, directory: string): BeforeEditState | undefined {
  const action = tool.toLowerCase().replace(/^mcp__[a-z0-9_]+__/, "").split(/[.:/]/).at(-1) ?? "";
  if (!/^(?:write|write_file|write_to_file|create_file|save_file|replace_file_content|file_write|file_mutate|edit|edit_file)$/.test(action)) return undefined;
  if (!Object.hasOwn(input, "content") || typeof input.content !== "string" ||
      typeof input.old_string === "string" || typeof input.oldString === "string") return undefined;
  const target = input.path ?? input.filePath ?? input.file ?? input.targetFile;
  if (typeof target !== "string" || !target.trim()) return undefined;
  return { filePath: target, directory, ...fileState(directory, target) };
}

export function finishEditObservation(before: BeforeEditState): EditIntegrityEvidence {
  const after = fileState(before.directory, before.filePath);
  if (!before.hash || !after.hash || !before.definitions || !after.definitions) {
    return { status: "unavailable", filePath: before.filePath };
  }
  return {
    status: "observed", filePath: before.filePath, beforeHash: before.hash, afterHash: after.hash,
    beforeBytes: before.bytes ?? 0, afterBytes: after.bytes ?? 0,
    removedDefinitions: [...before.definitions].filter(name => !after.definitions?.has(name)).length,
  };
}
