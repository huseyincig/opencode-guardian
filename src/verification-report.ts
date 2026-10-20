import type { OutcomeReason, TestSummary } from "./types.js";

const MAX_OUTPUT = 1024 * 1024;
const validCount = (n: number): boolean => Number.isSafeInteger(n) && n >= 0 && n <= 1_000_000_000;

function summary(format: TestSummary["format"], counts: Partial<Omit<TestSummary, "format">>): TestSummary | undefined {
  const result: TestSummary = { format, total: 0, passed: 0, failed: 0, skipped: 0, cancelled: 0, todo: 0, ...counts };
  const sum = result.passed + result.failed + result.skipped + result.cancelled + result.todo;
  if (!Object.values(result).filter((v): v is number => typeof v === "number").every(validCount) || sum !== result.total) return undefined;
  return result;
}

/** Only complete, anchored aggregate summaries in bounded tool output. */
export function parseTestSummary(output: string): TestSummary | undefined {
  if (output.length > MAX_OUTPUT) return undefined;
  // oxlint-disable-next-line no-control-regex -- ANSI terminal escape sequences.
  const text = output.replace(/\x1b\[[0-9;]*m/g, "").replace(/\r/g, "");
  const nodeStarts = [...text.matchAll(/^(?:#|ℹ)\s+tests\s+(\d+)\s*$/gm)];
  const node = nodeStarts.at(-1);
  if (node) {
    const tail = text.slice(node.index, node.index + 1024);
    const read = (key: string): number | undefined => {
      const m = new RegExp(`^(?:#|ℹ)\\s+${key}\\s+(\\d+)\\s*$`, "m").exec(tail);
      return m ? Number(m[1]) : undefined;
    };
    const passed = read("pass"), failed = read("fail");
    if (passed === undefined || failed === undefined) return undefined;
    return summary("node", { total: Number(node[1]), passed, failed,
      skipped: read("skipped") ?? 0, cancelled: read("cancelled") ?? 0, todo: read("todo") ?? 0 });
  }
  for (const line of text.split("\n").reverse()) {
    const jest = /^Tests:\s+(.+)$/.exec(line.trim());
    const vitest = /^Tests\s+(.+?)\s+\((\d+)\)\s*$/.exec(line.trim());
    const pytest = /^=+\s*(.+?)\s+in\s+[\d.]+(?:s|\s+seconds?)\s*=*$/.exec(line.trim());
    const format = jest ? "jest" : vitest ? "vitest" : pytest ? "pytest" : undefined;
    const body = jest?.[1] ?? vitest?.[1] ?? pytest?.[1];
    if (!format || !body) continue;
    const counts: Partial<Omit<TestSummary, "format">> = {};
    const groups = body.split(/\s*[,|]\s*/);
    let total = vitest ? Number(vitest[2]) : undefined;
    let recognized = true;
    for (const group of groups) {
      if (format === "pytest" && /^\d+\s+(?:warnings?|deselected)$/.test(group.trim())) continue;
      const m = /^(\d+)\s+(passed|failed|skipped|todo|xfailed|xpassed|errors?|total)$/.exec(group.trim());
      if (!m) { recognized = false; break; }
      const value = Number(m[1]);
      const label = m[2];
      if (label === "total") { total = value; continue; }
      const key = label === "xfailed" ? "skipped" : label === "xpassed" ? "passed" :
        label === "error" || label === "errors" ? "failed" : label as "passed" | "failed" | "skipped" | "todo";
      counts[key] = (counts[key] ?? 0) + value;
    }
    if (!recognized) continue;
    if (format === "pytest") total = Object.values(counts).reduce((sum, n) => sum + n, 0);
    if (total !== undefined) return summary(format, { ...counts, total });
  }
  return undefined;
}

/** A failed host result is never promoted by a passing text summary. */
export function testOutcomeReason(command: string, exitCode: number | undefined,
  counts?: TestSummary): OutcomeReason | undefined {
  if (exitCode === 124) return "timeout";
  const pytest = /\b(?:pytest|py\.test)\b/.test(command);
  if (pytest && exitCode === 5) return "no-tests";
  if (exitCode !== undefined && exitCode !== 0) return "execution-failure";
  if (!counts) return undefined;
  if (counts.total === 0) return "no-tests";
  if (counts.failed || counts.cancelled) return "summary-conflict";
  if (counts.passed === 0) return "skipped-only";
  return undefined;
}
