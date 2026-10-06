import fs from "node:fs";
import path from "node:path";
import { builtinModules } from "node:module";
import type {
  GuardRule,
  RuleFinding,
  RuleResult,
  TurnInspectionContext,
} from "../types.js";
import { extractLikelyShellMutation } from "../tool-input.js";

const NODE_BUILTINS = new Set(
  builtinModules
    .filter((name) => !name.startsWith("node:"))
    .map((name) => name.split("/")[0])
);

const PYTHON_STDLIB = new Set([
  "__future__", "_thread", "abc", "argparse", "array", "ast", "asyncio",
  "atexit", "base64", "bdb", "binascii", "bisect", "builtins", "bz2",
  "calendar", "cmath", "cmd", "code", "codecs", "collections", "colorsys",
  "compileall", "concurrent", "configparser", "contextlib", "contextvars",
  "copy", "copyreg", "csv", "ctypes", "curses", "dataclasses", "datetime",
  "dbm", "decimal", "difflib", "dis", "doctest", "email", "encodings",
  "ensurepip", "enum", "errno", "faulthandler", "fcntl", "filecmp",
  "fileinput", "fnmatch", "fractions", "ftplib", "functools", "gc",
  "genericpath", "getopt", "getpass", "gettext", "glob", "graphlib", "grp",
  "gzip", "hashlib", "heapq", "hmac", "html", "http", "imaplib", "importlib",
  "inspect", "io", "ipaddress", "itertools", "json", "keyword", "linecache",
  "locale", "logging", "lzma", "mailbox", "marshal", "math", "mimetypes",
  "mmap", "modulefinder", "multiprocessing", "netrc", "numbers", "operator",
  "optparse", "os", "pathlib", "pdb", "pickle", "pickletools", "pkgutil",
  "platform", "plistlib", "poplib", "posixpath", "pprint", "profile", "pstats",
  "pty", "pwd", "py_compile", "pydoc", "queue", "quopri", "random", "re",
  "readline", "reprlib", "resource", "runpy", "sched", "secrets", "select",
  "selectors", "shelve", "shlex", "shutil", "signal", "site", "smtplib",
  "socket", "socketserver", "sqlite3", "ssl", "stat", "statistics", "string",
  "stringprep", "struct", "subprocess", "sys", "sysconfig", "syslog",
  "tarfile", "tempfile", "termios", "textwrap", "threading", "time", "timeit",
  "tkinter", "token", "tokenize", "tomllib", "trace", "traceback",
  "tracemalloc", "tty", "types", "typing", "unicodedata", "unittest",
  "urllib", "uuid", "venv", "warnings", "wave", "weakref", "webbrowser",
  "winreg", "wsgiref", "xml", "xmlrpc", "zipapp", "zipfile", "zipimport",
  "zlib", "zoneinfo",
]);

const PYTHON_IMPORT_TO_PACKAGE: Record<string, string> = {
  yaml: "pyyaml",
  PIL: "pillow",
  cv2: "opencv-python",
  sklearn: "scikit-learn",
  bs4: "beautifulsoup4",
  Crypto: "pycryptodome",
  dateutil: "python-dateutil",
  dotenv: "python-dotenv",
  jwt: "pyjwt",
  attr: "attrs",
};

const AMBIGUOUS_PYTHON_NAMESPACES = new Set([
  "google",
  "azure",
  "zope",
  "pkg_resources",
]);

const DEPS_CACHE = new Map<
  string,
  { timestamp: number; deps: Set<string> | null; manifestPath: string; revision: string; files: string[] }
>();
const CACHE_TTL_MS = 5000;

/** Cache only while the actual manifest files have not changed. */
function filesRevision(files: string[]): string {
  return files.map((file) => {
    try {
      const stat = fs.statSync(file, { bigint: true });
      return `${file}:${stat.ino}:${stat.size}:${stat.mtimeNs}:${stat.ctimeNs}`;
    } catch {
      return `${file}:missing`;
    }
  }).join("|");
}

export function clearDeclaredDepsCache(): void {
  DEPS_CACHE.clear();
}

function normalizePackageName(value: string): string {
  return value.trim().toLowerCase().replace(/[_.]+/g, "-");
}

function nearestFile(
  directory: string,
  names: string[],
  dynamicName?: RegExp
): { path: string; root: string } | null {
  let current = path.resolve(directory);
  while (true) {
    for (const name of names) {
      const candidate = path.join(current, name);
      if (fs.existsSync(candidate)) return { path: candidate, root: current };
    }

    if (dynamicName) {
      try {
        const matching = fs
          .readdirSync(current)
          .filter((name) => dynamicName.test(name))
          .sort()[0];
        dynamicName.lastIndex = 0;
        if (matching) {
          return { path: path.join(current, matching), root: current };
        }
      } catch {
        // Fail open when a directory cannot be inspected.
      }
    }

    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

function dependenciesFromPackage(pkg: Record<string, unknown>): Set<string> {
  const deps = new Set<string>();
  for (const section of [
    pkg.dependencies,
    pkg.devDependencies,
    pkg.peerDependencies,
    pkg.optionalDependencies,
  ]) {
    if (!section || typeof section !== "object" || Array.isArray(section)) continue;
    for (const key of Object.keys(section as Record<string, unknown>)) {
      deps.add(key);
    }
  }
  return deps;
}

function loadNodeDependencies(directory: string): Set<string> | null {
  const resolvedDir = path.resolve(directory);
  const cacheKey = `node:${resolvedDir}`;
  const manifest = nearestFile(resolvedDir, ["package.json"]);
  if (!manifest) return null;

  const files = [manifest.path];
  const revision = filesRevision(files);
  const cached = DEPS_CACHE.get(cacheKey);
  const now = Date.now();
  if (cached && cached.manifestPath === manifest.path && cached.revision === revision &&
      now - cached.timestamp < CACHE_TTL_MS) return cached.deps;

  try {
    const pkg = JSON.parse(fs.readFileSync(manifest.path, "utf8"));
    const result = pkg && typeof pkg === "object" && !Array.isArray(pkg)
      ? dependenciesFromPackage(pkg as Record<string, unknown>) : null;
    DEPS_CACHE.set(cacheKey, { timestamp: now, deps: result, manifestPath: manifest.path, revision, files });
    return result;
  } catch {
    DEPS_CACHE.delete(cacheKey);
    return null;
  }
}

function parseRequirementName(line: string): string {
  let trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) return "";

  const editable = /^(?:-e|--editable)(?:\s+|=)/i.exec(trimmed);
  if (editable) trimmed = trimmed.slice(editable[0].length).trim();
  if (!trimmed || trimmed.startsWith("-")) return "";

  if (/^(?:(?:git|hg|svn|bzr)\+|(?:https?|file|ssh):\/\/)/i.test(trimmed)) {
    // Legacy pip VCS requirements may declare the actual distribution with
    // #egg=package. A URL without a usable name must not invent a dependency
    // called "git", "file", "ssh", etc.
    const fragment = trimmed.split("#", 2)[1] ?? "";
    const egg = /(?:^|&)egg=([A-Za-z0-9_.-]+)(?=[&\s]|$)/i.exec(fragment)?.[1];
    return egg ? normalizePackageName(egg) : "";
  }

  if (editable) return "";
  const requirement = trimmed.split("#", 1)[0] ?? "";
  const match = /^([A-Za-z0-9_.-]+)/.exec(requirement.trim());
  const name = match?.[1];
  return name ? normalizePackageName(name) : "";
}

function parseRequirementsFile(
  filePath: string,
  root: string,
  seen = new Set<string>()
): Set<string> {
  const deps = new Set<string>();
  const resolved = path.resolve(filePath);
  const rootPrefix = `${path.resolve(root)}${path.sep}`;

  if (
    seen.has(resolved) ||
    (resolved !== path.resolve(root) && !resolved.startsWith(rootPrefix))
  ) {
    return deps;
  }
  seen.add(resolved);

  let text = "";
  try {
    text = fs.readFileSync(resolved, "utf8");
  } catch {
    return deps;
  }

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    const include =
      /^(?:-r|--requirement)\s+(.+)$/i.exec(line)?.[1]?.trim();
    if (include) {
      const nested = path.resolve(path.dirname(resolved), include);
      for (const dep of parseRequirementsFile(nested, root, seen)) {
        deps.add(dep);
      }
      continue;
    }

    const name = parseRequirementName(line);
    if (name) deps.add(name);
  }

  return deps;
}

/**
 * Parse a TOML string array without confusing brackets in quoted PEP 508
 * extras (for example fastapi[all]) with the array's closing bracket.
 * An incomplete array provides no authoritative dependency evidence.
 */
function readTomlDependencyArray(text: string, start: number): string[] {
  const entries: string[] = [];
  let quote: "'" | '"' | null = null;
  let value = "";

  for (let index = start; index < text.length; index++) {
    const char = text[index];
    if (quote) {
      if (quote === '"' && char === "\\" && index + 1 < text.length) {
        value += text[++index];
      } else if (char === quote) {
        entries.push(value);
        value = "";
        quote = null;
      } else {
        value += char;
      }
      continue;
    }

    if (char === '"' || char === "'") {
      quote = char;
    } else if (char === "#") {
      while (index < text.length && text[index] !== "\n") index++;
    } else if (char === "]") {
      return entries;
    }
  }

  return [];
}

function parsePythonManifest(text: string, fileName: string): Set<string> {
  const deps = new Set<string>();

  if (fileName.startsWith("requirements")) {
    for (const line of text.split(/\r?\n/)) {
      const name = parseRequirementName(line);
      if (name) deps.add(name);
    }
    return deps;
  }

  // PEP 621 / uv style arrays, including extras such as "fastapi[all]".
  for (const arrayMatch of text.matchAll(
    /(?:^|\n)\s*(?:dependencies|dev-dependencies)\s*=\s*\[/g
  )) {
    const start = (arrayMatch.index ?? 0) + arrayMatch[0].length;
    for (const requirement of readTomlDependencyArray(text, start)) {
      const name = parseRequirementName(requirement);
      if (name) deps.add(name);
    }
  }

  // Poetry dependency tables and PEP 621 optional-dependency groups.
  let table: "poetry" | "optional" | null = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (/^\[tool\.poetry\.(?:group\.[^.]+\.)?dependencies\]$/.test(line)) {
      table = "poetry";
      continue;
    }
    if (/^\[project\.optional-dependencies\]$/.test(line)) {
      table = "optional";
      continue;
    }
    if (/^\[.*\]$/.test(line)) {
      table = null;
      continue;
    }

    if (table === "poetry") {
      const key = /^["']?([A-Za-z0-9_.-]+)["']?\s*=/.exec(line)?.[1];
      if (key && key.toLowerCase() !== "python") {
        deps.add(normalizePackageName(key));
      }
      continue;
    }

    if (table === "optional") {
      for (const quoteMatch of line.matchAll(/["']([^"']+)["']/g)) {
        const name = parseRequirementName(quoteMatch[1] ?? "");
        if (name) deps.add(name);
      }
    }
  }

  return deps;
}

function loadPythonDependencies(
  directory: string
): { deps: Set<string>; root: string } | null {
  const resolvedDir = path.resolve(directory);
  const manifest = nearestFile(
    resolvedDir,
    ["pyproject.toml", "requirements.txt", "requirements-dev.txt", "requirements.in"],
    /^requirements(?:[-_.][A-Za-z0-9_-]+)?\.txt$/i
  );
  if (!manifest) return null;

  const cacheKey = `python:${manifest.root}`;
  const cached = DEPS_CACHE.get(cacheKey);
  const now = Date.now();
  if (cached?.deps && cached.manifestPath === manifest.path &&
      cached.revision === filesRevision(cached.files) &&
      now - cached.timestamp < CACHE_TTL_MS) {
    return { deps: cached.deps, root: manifest.root };
  }

  try {
    const deps = new Set<string>();
    const pyproject = path.join(manifest.root, "pyproject.toml");
    const files = [manifest.root, pyproject];
    if (fs.existsSync(pyproject)) {
      for (const dep of parsePythonManifest(
        fs.readFileSync(pyproject, "utf8"), "pyproject.toml"
      )) deps.add(dep);
    }

    const requirementFiles = fs.readdirSync(manifest.root)
      .filter((name) =>
        /^requirements(?:[-_.][A-Za-z0-9_-]+)?\.txt$/i.test(name) ||
        name === "requirements.in"
      ).sort();
    const seen = new Set<string>();
    for (const name of requirementFiles) {
      for (const dep of parseRequirementsFile(
        path.join(manifest.root, name), manifest.root, seen
      )) deps.add(dep);
    }
    files.push(...seen);
    DEPS_CACHE.set(cacheKey, {
      timestamp: now, deps, manifestPath: manifest.path,
      revision: filesRevision(files), files,
    });
    return { deps, root: manifest.root };
  } catch {
    DEPS_CACHE.delete(cacheKey);
    return null;
  }
}

function loadGoManifest(
  directory: string
): { modules: Set<string>; ownModule: string; root: string } | null {
  const manifest = nearestFile(directory, ["go.mod"]);
  if (!manifest) return null;

  try {
    const text = fs.readFileSync(manifest.path, "utf8");
    const ownModule = /^\s*module\s+([^\s]+)\s*$/m.exec(text)?.[1] ?? "";
    const modules = new Set<string>();

    for (const match of text.matchAll(/^\s*require\s+([^\s()]+)\s+v?[^\s]+/gm)) {
      const moduleName = match[1];
      if (moduleName) modules.add(moduleName);
    }
    // go.mod commonly has separate direct and indirect require blocks.
    // Inspect every block, not only the first one.
    for (const block of text.matchAll(/(?:^|\n)\s*require\s*\(([\s\S]*?)\)/g)) {
      const body = block[1];
      if (body === undefined) continue;
      for (const line of body.split(/\r?\n/)) {
        const mod = /^\s*([^\s/][^\s]*)\s+v?[^\s]+/.exec(line)?.[1];
        if (mod) modules.add(mod);
      }
    }

    return { modules, ownModule, root: manifest.root };
  } catch {
    return null;
  }
}

function loadRustDependencies(
  directory: string
): { deps: Set<string>; root: string } | null {
  const manifest = nearestFile(directory, ["Cargo.toml"]);
  if (!manifest) return null;

  try {
    const text = fs.readFileSync(manifest.path, "utf8");
    const deps = new Set<string>();
    let inDeps = false;

    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (
        /^\[(?:(?:dependencies|dev-dependencies|build-dependencies|workspace\.dependencies)|target\..+\.(?:dependencies|dev-dependencies|build-dependencies))\]$/.test(
          line
        )
      ) {
        inDeps = true;
        continue;
      }
      if (/^\[.*\]$/.test(line)) {
        inDeps = false;
        continue;
      }
      if (!inDeps || !line || line.startsWith("#")) continue;
      const key = /^["']?([A-Za-z0-9_-]+)["']?\s*=/.exec(line)?.[1];
      if (key) deps.add(key.replace(/-/g, "_"));
    }

    return { deps, root: manifest.root };
  } catch {
    return null;
  }
}

function getNodePackageName(importPath: string): string {
  if (importPath.startsWith("node:")) return "";
  if (
    importPath.startsWith(".") ||
    importPath.startsWith("/") ||
    importPath.startsWith("~")
  ) {
    return "";
  }
  if (importPath.startsWith("@")) {
    return importPath.split("/").slice(0, 2).join("/");
  }
  return importPath.split("/")[0] ?? "";
}

const JS_IMPORT_REGEXES = [
  /\bimport\s+(?:[\w*$\s{},]+from\s+)?["']([^"']+)["']/g,
  /\bexport\s+[\w*$\s{},]+from\s+["']([^"']+)["']/g,
  /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
  /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
];

function buildJsCodeMask(code: string): Uint8Array {
  const mask = new Uint8Array(code.length);
  mask.fill(1);
  let i = 0;

  while (i < code.length) {
    const ch = code[i];
    const next = code[i + 1];

    if (ch === "/" && next === "/") {
      const start = i;
      i += 2;
      while (i < code.length && code[i] !== "\n") i++;
      mask.fill(0, start, i);
      continue;
    }

    if (ch === "/" && next === "*") {
      const start = i;
      i += 2;
      while (
        i < code.length &&
        !(code[i] === "*" && code[i + 1] === "/")
      ) {
        i++;
      }
      i = Math.min(code.length, i + 2);
      mask.fill(0, start, i);
      continue;
    }

    if (ch === "'" || ch === '"' || ch === "`") {
      const quote = ch;
      const start = i;
      i++;
      while (i < code.length) {
        if (code[i] === "\\") {
          i += 2;
          continue;
        }
        if (code[i] === quote) {
          i++;
          break;
        }
        i++;
      }
      mask.fill(0, start, Math.min(i, code.length));
      continue;
    }

    i++;
  }
  return mask;
}

function extractJsImports(code: string): string[] {
  const imports: string[] = [];
  const mask = buildJsCodeMask(code);

  for (const regex of JS_IMPORT_REGEXES) {
    regex.lastIndex = 0;
    let match = regex.exec(code);
    while (match !== null) {
      if (mask[match.index] === 1 && match[1]) imports.push(match[1]);
      match = regex.exec(code);
    }
  }

  return imports;
}

function maskPythonNonCode(code: string): string {
  const chars = [...code];
  let i = 0;

  const blank = (start: number, end: number) => {
    for (let j = start; j < end; j++) {
      if (chars[j] !== "\n" && chars[j] !== "\r") chars[j] = " ";
    }
  };

  while (i < chars.length) {
    const ch = chars[i];

    if (ch === "#") {
      const start = i;
      while (i < chars.length && chars[i] !== "\n") i++;
      blank(start, i);
      continue;
    }

    if (ch === "'" || ch === '"') {
      const quote = ch;
      const triple =
        chars[i + 1] === quote && chars[i + 2] === quote;
      const start = i;
      i += triple ? 3 : 1;

      while (i < chars.length) {
        if (chars[i] === "\\") {
          i += 2;
          continue;
        }

        if (
          triple &&
          chars[i] === quote &&
          chars[i + 1] === quote &&
          chars[i + 2] === quote
        ) {
          i += 3;
          break;
        }

        if (!triple && chars[i] === quote) {
          i++;
          break;
        }

        i++;
      }

      blank(start, Math.min(i, chars.length));
      continue;
    }

    i++;
  }

  return chars.join("");
}

function extractPythonImports(code: string): string[] {
  const imports: string[] = [];
  const executable = maskPythonNonCode(code);

  for (const rawLine of executable.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;

    const from = /^from\s+([A-Za-z_][\w.]*)\s+import\b/.exec(line)?.[1];
    if (from && !from.startsWith(".")) {
      const moduleName = from.split(".")[0];
      if (moduleName) imports.push(moduleName);
      continue;
    }

    const direct = /^import\s+(.+)$/.exec(line)?.[1];
    if (!direct) continue;
    for (const item of direct.split(",")) {
      const importHead = item.trim().split(/\s+as\s+/i)[0] ?? "";
      const name = importHead.split(".")[0] ?? "";
      if (name && /^[A-Za-z_]\w*$/.test(name)) imports.push(name);
    }
  }
  return imports;
}

function extractGoImports(code: string): string[] {
  const imports: string[] = [];
  for (const match of code.matchAll(/\bimport\s+"([^"]+)"/g)) {
    const importPath = match[1];
    if (importPath) imports.push(importPath);
  }
  for (const block of code.matchAll(/\bimport\s*\(([\s\S]*?)\)/g)) {
    const body = block[1];
    if (body === undefined) continue;
    for (const match of body.matchAll(/"([^"]+)"/g)) {
      const importPath = match[1];
      if (importPath) imports.push(importPath);
    }
  }
  return imports;
}

function extractRustCrates(code: string): string[] {
  const crates = new Set<string>();
  for (const match of code.matchAll(/\bextern\s+crate\s+([A-Za-z_][\w]*)\s*;/g)) {
    const crate = match[1];
    if (crate) crates.add(crate);
  }
  for (const match of code.matchAll(/(?:^|\n)\s*use\s+([A-Za-z_][\w]*)::/g)) {
    const crate = match[1];
    if (crate) crates.add(crate);
  }
  return [...crates];
}

function localPythonModuleExists(root: string, moduleName: string): boolean {
  if ([
    path.join(root, `${moduleName}.py`),
    path.join(root, moduleName, "__init__.py"),
    path.join(root, "src", `${moduleName}.py`),
    path.join(root, "src", moduleName, "__init__.py"),
  ].some((candidate) => fs.existsSync(candidate))) {
    return true;
  }

  // PEP 420 namespace packages are importable without __init__.py.
  return [path.join(root, moduleName), path.join(root, "src", moduleName)]
    .some((candidate) => {
      try {
        return fs.statSync(candidate).isDirectory();
      } catch {
        return false;
      }
    });
}

function localRustModuleExists(root: string, crateName: string): boolean {
  return [
    path.join(root, "src", `${crateName}.rs`),
    path.join(root, "src", crateName, "mod.rs"),
  ].some((candidate) => fs.existsSync(candidate));
}

function extractAddedLines(text: unknown): string {
  if (typeof text !== "string") return "";
  return text
    .split("\n")
    .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
    .map((line) => line.slice(1))
    .join("\n");
}

function extractFilePathFromPatch(patch: unknown): string | undefined {
  if (typeof patch !== "string") return undefined;
  const match = patch.match(/\+\+\+\s+(?:b\/)?([^\s\t\n]+)/);
  return match && match[1] !== "/dev/null" ? match[1] : undefined;
}

function resolveTargetFile(
  input: Record<string, unknown>
): string | undefined {
  const patch = input.patchText ?? input.patch;
  return (
    (input.path as string) ??
    (input.targetFile as string) ??
    (input.filePath as string) ??
    (input.file as string) ??
    extractFilePathFromPatch(patch)
  );
}

function targetDirectory(
  targetFile: string | undefined,
  sessionDirectory: string
): string {
  if (!targetFile) return sessionDirectory;
  const absolute = path.isAbsolute(targetFile)
    ? targetFile
    : path.resolve(sessionDirectory, targetFile);
  return path.dirname(absolute);
}

function extensionOf(targetFile?: string): string {
  return targetFile ? path.extname(targetFile).toLowerCase() : "";
}

export const noGhostDepsRule: GuardRule = {
  id: "manifest/no-ghost-deps",
  description:
    "Detects undeclared imports against the nearest Node, Python, Go, or Rust dependency manifest.",
  inspect: (context: TurnInspectionContext): RuleResult => {
    const findings: RuleFinding[] = [];
    const blocking: RuleFinding[] = [];
    const seen = new Set<string>();
    const blockPythonGhostDeps =
      context.ruleConfig.blockPythonGhostDeps === true;

    const addFinding = (
      ecosystem: string,
      packageName: string,
      importPath: string,
      source: string,
      manifestName: string,
      shouldBlock = true
    ) => {
      const key = `${ecosystem}:${packageName}`;
      if (seen.has(key)) return;
      seen.add(key);
      const finding: RuleFinding = {
        ruleId: "manifest/no-ghost-deps",
        pattern: packageName,
        messageSnippet: importPath,
        description: `Undeclared ${ecosystem} dependency "${packageName}" imported in ${source} but missing from ${manifestName}`,
        confidence: shouldBlock ? "high" : "medium",
      };
      findings.push(finding);
      if (shouldBlock) blocking.push(finding);
    };

    const checkCode = (
      code: string,
      source: string,
      targetFile: string | undefined
    ) => {
      const ext = extensionOf(targetFile);
      const dir = targetDirectory(targetFile, context.directory);

      if ([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"].includes(ext) || !ext) {
        const declared = loadNodeDependencies(dir);
        if (declared) {
          for (const importPath of extractJsImports(code)) {
            const pkg = getNodePackageName(importPath);
            if (
              !pkg ||
              NODE_BUILTINS.has(pkg) ||
              declared.has(pkg)
            ) {
              continue;
            }
            addFinding("Node", pkg, importPath, source, "package.json");
          }
        }
        if (ext) return;
      }

      if (ext === ".py") {
        const manifest = loadPythonDependencies(dir);
        if (!manifest) return;

        for (const moduleName of extractPythonImports(code)) {
          if (PYTHON_STDLIB.has(moduleName)) continue;
          if (localPythonModuleExists(manifest.root, moduleName)) continue;

          if (AMBIGUOUS_PYTHON_NAMESPACES.has(moduleName)) continue;

          const mapped =
            PYTHON_IMPORT_TO_PACKAGE[moduleName] ?? moduleName;
          const pkg = normalizePackageName(mapped);
          const declaredByName =
            manifest.deps.has(pkg) ||
            manifest.deps.has(normalizePackageName(moduleName));
          if (declaredByName) continue;

          addFinding(
            "Python",
            pkg,
            moduleName,
            source,
            "pyproject/requirements",
            blockPythonGhostDeps
          );
        }
        return;
      }

      if (ext === ".go") {
        const manifest = loadGoManifest(dir);
        if (!manifest) return;

        for (const importPath of extractGoImports(code)) {
          const first = importPath.split("/")[0] ?? "";
          if (!first.includes(".")) continue;
          if (
            manifest.ownModule &&
            (importPath === manifest.ownModule ||
              importPath.startsWith(`${manifest.ownModule}/`))
          ) {
            continue;
          }
          if (
            [...manifest.modules].some(
              (mod) => importPath === mod || importPath.startsWith(`${mod}/`)
            )
          ) {
            continue;
          }

          addFinding("Go", importPath, importPath, source, "go.mod");
        }
        return;
      }

      if (ext === ".rs") {
        const manifest = loadRustDependencies(dir);
        if (!manifest) return;

        const localMods = new Set(
          [...code.matchAll(/(?:^|\n)\s*mod\s+([A-Za-z_][\w]*)\s*;/g)].map(
            (match) => match[1]
          )
        );

        for (const crateName of extractRustCrates(code)) {
          if (
            ["std", "core", "alloc", "crate", "self", "super"].includes(
              crateName
            )
          ) {
            continue;
          }
          if (localMods.has(crateName)) continue;
          if (localRustModuleExists(manifest.root, crateName)) continue;
          if (manifest.deps.has(crateName.replace(/-/g, "_"))) continue;

          addFinding("Rust", crateName, crateName, source, "Cargo.toml");
        }
      }
    };

    for (const msg of context.currentTurn) {
      if (msg.info.role !== "assistant") continue;

      for (const part of msg.parts) {
        if (part.type !== "tool" || !part.state?.input) continue;
        const input = part.state.input as Record<string, unknown>;
        const targetFile = resolveTargetFile(input);

        if (typeof input.content === "string") {
          checkCode(input.content, "file content", targetFile);
        }
        if (typeof input.new_string === "string") {
          checkCode(input.new_string, "file edit", targetFile);
        }
        if (typeof input.newString === "string") {
          checkCode(input.newString, "file edit", targetFile);
        }

        const patchText = extractAddedLines(input.patchText ?? input.patch);
        if (patchText) checkCode(patchText, "patch added lines", targetFile);

        const shellMutation = extractLikelyShellMutation(input);
        if (shellMutation) {
          // Shell content cannot be reliably assigned to a language without a
          // target path, so retain Node fallback only for path-less mutations.
          checkCode(shellMutation, "shell file mutation", targetFile);
        }
      }
    }

    if (findings.length === 0) {
      return {
        ruleId: "manifest/no-ghost-deps",
        decision: "pass",
        findings: [],
      };
    }

    if (blocking.length === 0) {
      return {
        ruleId: "manifest/no-ghost-deps",
        decision: "pass",
        findings,
      };
    }

    const list = blocking
      .map(
        (finding) =>
          `  - "${finding.pattern}" (import: ${finding.messageSnippet})`
      )
      .join("\n");

    return {
      ruleId: "manifest/no-ghost-deps",
      decision: "block",
      findings,
      remediationPrompt:
        `Ghost/undeclared dependency detected in this turn:\n${list}\n\n` +
        `Declare the dependency in the nearest owning manifest, or use the standard library / a local module / an already-declared dependency instead.`,
    };
  },
};
