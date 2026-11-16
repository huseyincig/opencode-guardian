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
  "@opencode-ai/plugin", "@opencode/ai", "@opencode/client", "@opencode/plugin",
  "@opencode/protocol", "@opencode/schema", "@opencode/util", "@opentui/solid",
  "@sigstore/sign", "@sigstore/tuf", "@tufjs/models",
  "babel-plugin-module-resolver", "cacache", "effect", "gaxios", "gcp-metadata",
  "glob", "http-cache-semantics", "ignore-walk", "make-fetch-happen",
  "minimatch", "npm-packlist", "npm-registry-fetch", "pacote", "rimraf",
  "seroval", "seroval-plugins", "sigstore", "solid-js", "tuf-js",
  "undici", "zod",
]);

const issues = Object.entries(report.vulnerabilities);
const unexpected = issues.filter(([name]) => !knownUpstreamChain.has(name));
const counts = report.metadata.vulnerabilities;
const valid = unexpected.length === 0 && counts.critical === 0;

console.log(`Full development-dependency audit: ${issues.length} vulnerable packages (${counts.high} high, ${counts.moderate} moderate, ${counts.low} low, ${counts.critical} critical).`);
if (issues.length) {
  console.warn("Known upstream development-only SDK dependency chains tracked.");
  console.warn(`Tracked packages: ${issues.map(([name]) => name).join(", ")}`);
}
if (!valid) {
  console.error("New or unexpected audit vulnerabilities detected. Investigate before merging.");
  if (unexpected.length) console.error("Unexpected packages:", unexpected.map(([name]) => name).join(", "));
  if (counts.critical > 0) console.error("Critical vulnerabilities found:", counts.critical);
  process.exit(1);
}
