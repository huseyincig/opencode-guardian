#!/usr/bin/env node
/** Keep the dev dependency audit visible and fail on any new advisory. */
import { spawnSync } from "node:child_process";
import path from "node:path";

const audit = spawnSync("npm", ["audit", "--json"], {
  cwd: path.resolve(import.meta.dirname, ".."),
  encoding: "utf8",
  maxBuffer: 16 * 1024 * 1024,
});
if (audit.error) {
  console.error("Could not run npm audit:", audit.error);
  process.exit(1);
}
let report;
try {
  report = JSON.parse(audit.stdout);
} catch {
  console.error("Could not parse npm audit output:", audit.stdout.slice(0, 500), audit.stderr.slice(0, 500));
  process.exit(1);
}
if (audit.status !== 0 && audit.status !== 1) {
  console.error("npm audit did not finish normally:", audit.stderr.slice(0, 500));
  process.exit(1);
}
if (!report.vulnerabilities || !report.metadata?.vulnerabilities) {
  console.error("npm audit returned an incomplete report");
  process.exit(1);
}
const knownUpstreamChain = new Set([
  "@npmcli/arborist", "@npmcli/config", "@npmcli/map-workspaces",
  "@npmcli/metavuln-calculator", "@npmcli/package-json", "@npmcli/run-script",
  "@opencode/ai", "@opencode/client", "@opencode/plugin",
  "@opencode/protocol", "@opencode/schema", "@opencode/util", "@opentui/solid",
  "@sigstore/sign", "@sigstore/tuf", "@tufjs/models",
  "babel-plugin-module-resolver", "cacache", "effect", "gaxios", "gcp-metadata",
  "glob", "http-cache-semantics", "ignore-walk", "make-fetch-happen",
  "minimatch", "npm-packlist", "npm-registry-fetch", "pacote", "rimraf",
  "seroval", "seroval-plugins", "sigstore", "solid-js", "tuf-js",
  "undici", "zod",
]);

const knownUpstreamAdvisories = new Set([
  1243609, // seroval (moderate, via @opencode/plugin -> @opentui/solid -> solid-js)
  1243611, // seroval (moderate)
  1244013, // glob (moderate, via @opencode/plugin -> npm/cacache)
  1244623, // minimatch (moderate, via @opencode/plugin -> npm/glob)
]);

const issues = Object.entries(report.vulnerabilities);
const unexpected = issues.filter(([name]) => !knownUpstreamChain.has(name));
const unexpectedAdvisories = [];
for (const [pkg, info] of issues) {
  for (const via of info.via ?? []) {
    if (via && typeof via === "object" && typeof via.source === "number") {
      if (!knownUpstreamAdvisories.has(via.source)) {
        unexpectedAdvisories.push(`${via.source} (${pkg}: ${via.severity})`);
      }
    }
  }
}
const counts = report.metadata.vulnerabilities;
const valid =
  unexpected.length === 0 &&
  unexpectedAdvisories.length === 0 &&
  counts.critical === 0 &&
  counts.high === 0;

console.log(`Full development-dependency audit: ${issues.length} vulnerable packages (${counts.high} high, ${counts.moderate} moderate, ${counts.low} low, ${counts.critical} critical).`);
if (issues.length) {
  console.warn("Known upstream development-only SDK dependency chains tracked.");
  console.warn(`Tracked packages: ${issues.map(([name]) => name).join(", ")}`);
}
if (!valid) {
  console.error("New or unexpected audit vulnerabilities detected. Investigate before merging.");
  if (unexpected.length) console.error("Unexpected packages:", unexpected.map(([name]) => name).join(", "));
  if (unexpectedAdvisories.length) console.error("Unexpected advisories:", unexpectedAdvisories.join(", "));
  if (counts.high > 0) console.error("High vulnerabilities found:", counts.high);
  if (counts.critical > 0) console.error("Critical vulnerabilities found:", counts.critical);
  process.exit(1);
}
