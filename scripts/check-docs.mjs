#!/usr/bin/env node
// Validate repository Markdown navigation and the checked-in SVG infographic.
// No network calls or development dependencies are required.
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const documents = [join(root, "README.md")];

function visit(folder) {
  for (const item of readdirSync(folder, { withFileTypes: true })) {
    const full = join(folder, item.name);
    if (item.isDirectory()) visit(full);
    else if (item.isFile() && item.name.endsWith(".md")) documents.push(full);
  }
}
visit(join(root, "docs"));

let references = 0;
const errors = [];
for (const document of documents) {
  const source = readFileSync(document, "utf8");
  // Ignore fenced examples; references inside those blocks are not navigation.
  const body = source.replace(/^([ \t]*)(?:`{3,}|~{3,})[^\n]*\n[\s\S]*?^\1(?:`{3,}|~{3,})[ \t]*$/gm, "");
  for (const match of body.matchAll(/!?\[[^\]]*\]\(([^)\s]+)(?:\s+["'][^"']*["'])?\)/g)) {
    const destination = match[1];
    if (/^(?:[a-z][a-z\d+.-]*:|\/\/|#)/i.test(destination)) continue;
    const filePart = destination.split("#", 1)[0].split("?", 1)[0];
    if (!filePart) continue;
    let decoded;
    try {
      decoded = decodeURIComponent(filePart);
    } catch {
      errors.push(relative(root, document) + ": invalid link encoding " + destination);
      continue;
    }
    const target = resolve(dirname(document), decoded);
    if (target !== root && !target.startsWith(root + sep)) {
      errors.push(relative(root, document) + ": link escapes repository " + destination);
    } else if (!existsSync(target)) {
      errors.push(relative(root, document) + ": missing " + destination);
    } else if (!statSync(target).isFile() && !statSync(target).isDirectory()) {
      errors.push(relative(root, document) + ": inaccessible " + destination);
    }
    references++;
  }
}

const asset = join(root, "docs", "assets", "verification-overview.svg");
if (!existsSync(asset)) {
  errors.push("docs/assets/verification-overview.svg: missing");
} else {
  const svg = readFileSync(asset, "utf8");
  if (!/<svg\b[^>]*role="img"/.test(svg) ||
      !/<title\b/.test(svg) || !/<desc\b/.test(svg) ||
      !/<\/svg>\s*$/.test(svg)) {
    errors.push("docs/assets/verification-overview.svg: accessibility metadata or SVG root missing");
  }
  if (/<script\b|onload\s*=|href\s*=\s*["']https?:/i.test(svg)) {
    errors.push("docs/assets/verification-overview.svg: embedded executable or remote resource");
  }
}

if (errors.length) {
  for (const error of errors) console.error("[docs] " + error);
  process.exitCode = 1;
} else {
  console.log("[docs] Verified " + documents.length + " Markdown files, " +
    references + " local links, and one accessible SVG.");
}
