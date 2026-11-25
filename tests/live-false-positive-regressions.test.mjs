import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { collectTurnEvidence } from "../dist/evidence.js";
import { extractTaskContract } from "../dist/task-contract.js";
import { deniedVerification } from "../dist/locale-intents.js";
import { noUnverifiedClaimsRule } from "../dist/rules/no-unverified-claims.js";
import { noStubsRule } from "../dist/rules/no-stubs.js";
import { noShortcutsRule } from "../dist/rules/no-shortcuts.js";
import { taskCompletionRule } from "../dist/rules/task-completion.js";
import {
  clearMeshIntervention,
  forgetMeshSession,
  getLatestMeshIntervention,
} from "../dist/bridge.js";
import Guardian from "../dist/index.js";

function createAsyncEventStream() {
  const queue = [];
  let waiting = null;
  let closed = false;
  return {
    push(event) {
      if (closed) return;
      if (waiting) {
        const resolve = waiting;
        waiting = null;
        resolve({ value: event, done: false });
      } else {
        queue.push(event);
      }
    },
    close() {
      closed = true;
      if (waiting) {
        const resolve = waiting;
        waiting = null;
        resolve({ value: undefined, done: true });
      }
    },
    iterable: {
      [Symbol.asyncIterator]() {
        return {
          next() {
            if (queue.length > 0) return Promise.resolve({ value: queue.shift(), done: false });
            if (closed) return Promise.resolve({ value: undefined, done: true });
            return new Promise((resolve) => { waiting = resolve; });
          },
        };
      },
    },
  };
}

describe("0.18.2 live false-positive and policy regressions", () => {
  test("evidence collector unwraps flock/timeout/sh -c and recognizes node --import --test, oxlint, biome, and plain tsc", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-ev-wrap-"));
    try {
      const cmd =
        "flock /tmp/dist.lock sh -c 'npx tsc && node --import ./tests/support/isolate-env.mjs --test tests/unit/a.test.mjs'";
      const ev = collectTurnEvidence(
        [
          {
            info: { id: "a1", role: "assistant" },
            parts: [
              {
                type: "tool",
                tool: "shell",
                state: {
                  status: "completed",
                  input: { command: cmd },
                  output: "ℹ tests 12\nℹ suites 0\nℹ pass 12\nℹ fail 0\nℹ cancelled 0\nℹ skipped 0\nℹ todo 0\n",
                  metadata: { exit: 0 },
                },
              },
              {
                type: "tool",
                tool: "shell",
                state: {
                  status: "completed",
                  input: { command: "npx oxlint src/a.ts tests/a.test.mjs --deny-warnings" },
                  output: "Found 0 warnings and 0 errors.\nFinished in 7ms on 2 files.",
                  metadata: { exit: 0 },
                },
              },
            ],
          },
        ],
        dir
      );

      assert.equal(ev.records.find((r) => r.kind === "test")?.status, "success");
      assert.equal(ev.records.find((r) => r.kind === "typecheck")?.status, "success");
      assert.equal(ev.records.find((r) => r.kind === "lint")?.status, "success");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("evidence collector trusts complete anchored node test summary and oxlint clean summary even when piped to tail without echo spoofing", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-ev-pipe-"));
    try {
      const cmd =
        "flock /tmp/dist.lock sh -c 'npx tsc && node --import ./tests/support/isolate-env.mjs --test tests/unit/a.test.mjs' 2>&1 | tail -12; npx oxlint src/a.ts --deny-warnings 2>&1 | tail -3";
      const output = [
        "✔ case 1 (1.2ms)",
        "ℹ tests 179",
        "ℹ suites 0",
        "ℹ pass 179",
        "ℹ fail 0",
        "ℹ cancelled 0",
        "ℹ skipped 0",
        "ℹ todo 0",
        "Found 0 warnings and 0 errors.",
        "Finished in 8ms on 1 files.",
      ].join("\n");
      const ev = collectTurnEvidence(
        [
          {
            info: { id: "a1", role: "assistant" },
            parts: [
              {
                type: "tool",
                tool: "shell",
                state: {
                  status: "completed",
                  input: { command: cmd },
                  output,
                  metadata: { exit: 0 },
                },
              },
            ],
          },
        ],
        dir
      );
      assert.equal(ev.records.find((r) => r.kind === "test")?.status, "success");
      assert.equal(ev.records.find((r) => r.kind === "lint")?.status, "success");

      // Spoofing via echo after pipe must STILL remain unknown!
      const spoofed = collectTurnEvidence(
        [
          {
            info: { id: "a2", role: "assistant" },
            parts: [
              {
                type: "tool",
                tool: "shell",
                state: {
                  status: "completed",
                  input: { command: "npm test | tail -n 5; echo 'ℹ tests 1'" },
                  output,
                  metadata: { exit: 0 },
                },
              },
            ],
          },
        ],
        dir
      );
      assert.equal(spoofed.records.find((r) => r.kind === "test")?.status, "unknown");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("deniedVerification and extractTaskContract recognize backticked and plain 'Do NOT run npm ...' prohibitions", () => {
    assert.equal(deniedVerification("Do NOT run `npm run check`; do not commit.", "test"), true);
    assert.equal(deniedVerification("Do NOT run `npm run check`; do not commit.", "lint"), true);
    assert.equal(deniedVerification("Do NOT run `npm test`; just fix the typo.", "test"), true);
    assert.equal(deniedVerification("not run npm run build in this task", "build"), true);
    assert.equal(deniedVerification("npm test çalıştırma, sadece kodu düzelt", "test"), true);

    const contract = extractTaskContract([
      {
        info: { id: "u1", role: "user" },
        parts: [{ type: "text", text: "Fix M163. Do NOT run `npm run check`; do not commit." }],
      },
    ]);
    assert.ok(contract?.prohibitedVerifications?.includes("test"));
    assert.ok(contract?.prohibitedVerifications?.includes("lint"));
    assert.ok(contract?.prohibitedVerifications?.includes("typecheck"));
    assert.ok(contract?.prohibitedVerifications?.includes("build"));
  });

  test("no-unverified-claims respects prohibited npm verification for fix statements while still catching fabricated test-pass lies", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-prohibit-claim-"));
    try {
      const honestTurn = [
        {
          info: { id: "u1", role: "user" },
          parts: [{ type: "text", text: "Fix the bug in src/app.ts. Do NOT run `npm run check`." }],
        },
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            {
              type: "tool",
              tool: "edit",
              state: {
                status: "completed",
                input: { path: "src/app.ts", oldString: "a", newString: "b" },
                output: "ok",
              },
            },
            {
              type: "text",
              text: "The bug is fixed in src/app.ts. I did not run `npm run check` as requested.",
            },
          ],
        },
      ];
      const honestRes = noUnverifiedClaimsRule.inspect({
        sessionID: "s-prohibit-1",
        directory: dir,
        currentTurn: honestTurn,
        history: honestTurn,
        evidence: collectTurnEvidence(honestTurn, dir),
        ruleConfig: {},
        isSubagent: false,
      });
      assert.equal(
        honestRes.findings.length,
        0,
        `expected 0 findings when npm verification is prohibited, got: ${JSON.stringify(honestRes.findings)}`
      );

      // Fabricated explicit pass claim for a prohibited check must STILL be caught!
      const lyingTurn = [
        {
          info: { id: "u1", role: "user" },
          parts: [{ type: "text", text: "Fix the bug. Do NOT run `npm test`." }],
        },
        {
          info: { id: "a1", role: "assistant" },
          parts: [{ type: "text", text: "The bug is fixed and all tests passed." }],
        },
      ];
      const lyingRes = noUnverifiedClaimsRule.inspect({
        sessionID: "s-prohibit-2",
        directory: dir,
        currentTurn: lyingTurn,
        history: lyingTurn,
        evidence: collectTurnEvidence(lyingTurn, dir),
        ruleConfig: {},
        isSubagent: false,
      });
      assert.ok(
        lyingRes.findings.some((f) => f.pattern === "tests passing"),
        "fabricated 'all tests passed' claim must still be flagged even when tests were prohibited"
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("task-contract does not treat technical 'until' clauses as iterativeReview", () => {
    const prompt =
      "Add behavioral regression tests: a legacy task with `paths: []` denies writes until `hi_task update` adds paths. Fix only if a test exposes a real gap.";
    const contract = extractTaskContract([
      {
        info: { id: "u1", role: "user" },
        parts: [{ type: "text", text: prompt }],
      },
    ]);
    assert.equal(contract?.iterativeReview, false, "technical 'denies writes until ...' must not trigger iterativeReview");

    const realLoop = extractTaskContract([
      {
        info: { id: "u2", role: "user" },
        parts: [{ type: "text", text: "Review the codebase and fix bugs until no errors remain." }],
      },
    ]);
    assert.equal(realLoop?.iterativeReview, true, "genuine 'until no errors remain' must still trigger iterativeReview");

    const turn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: prompt }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "write",
            state: { status: "completed", input: { path: "tests/unit/gate.test.mjs", content: "export const ok = true;\n" }, output: "ok" },
          },
          { type: "text", text: "Done. Added the regression tests." },
        ],
      },
    ];
    const gateRes = taskCompletionRule.inspect({
      sessionID: "s-until",
      directory: process.cwd(),
      currentTurn: turn,
      history: turn,
      evidence: collectTurnEvidence(turn, process.cwd()),
      ruleConfig: {},
      isSubagent: true,
      agentCapability: "write-allowed",
    });
    assert.equal(gateRes.decision, "pass");
  });

  test("integrity/no-stubs allows empty mock/test-double functions inside test files while still blocking production stubs", () => {
    const testFileTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Add unit test" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "write",
            state: {
              status: "completed",
              input: {
                path: "tests/unit/harden-final-mesh-bounds.test.mjs",
                content: "const host = { async interrupt() {}, hook() {} };\nconst dispose = () => {};\n",
              },
              output: "ok",
            },
          },
        ],
      },
    ];
    const testRes = noStubsRule.inspect({
      sessionID: "s-stub-test",
      directory: process.cwd(),
      currentTurn: testFileTurn,
      history: testFileTurn,
      ruleConfig: {},
      isSubagent: false,
    });
    assert.equal(testRes.decision, "pass");
    assert.equal(testRes.findings.length, 0, "empty mock functions in tests/** must not be flagged as stubs");

    const prodFileTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Implement handler" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "write",
            state: {
              status: "completed",
              input: {
                path: "src/handler.ts",
                content: "export function handleRequest() {}\n",
              },
              output: "ok",
            },
          },
        ],
      },
    ];
    const prodRes = noStubsRule.inspect({
      sessionID: "s-stub-prod",
      directory: process.cwd(),
      currentTurn: prodFileTurn,
      history: prodFileTurn,
      ruleConfig: {},
      isSubagent: false,
    });
    assert.equal(prodRes.decision, "block", "empty implementation in src/** must still be blocked");
  });

  test("quality/no-shortcuts does not flag removed temporary debug notes while still flagging active temporary fixes", () => {
    const removedTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Debug and fix" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "text",
            text: "A temporary debug log (since removed) showed the effective scope is catalog.",
          },
        ],
      },
    ];
    const removedRes = noShortcutsRule.inspect({
      sessionID: "s-short-removed",
      directory: process.cwd(),
      currentTurn: removedTurn,
      history: removedTurn,
      ruleConfig: {},
      isSubagent: false,
    });
    assert.equal(removedRes.findings.length, 0, "past removed temporary debug note must not trigger no-shortcuts");

    const activeTurn = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix auth" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [{ type: "text", text: "I added a temporary fix for now." }],
      },
    ];
    const activeRes = noShortcutsRule.inspect({
      sessionID: "s-short-active",
      directory: process.cwd(),
      currentTurn: activeTurn,
      history: activeTurn,
      ruleConfig: {},
      isSubagent: false,
    });
    assert.equal(activeRes.decision, "block", "active 'temporary fix' must still block");
  });

  test("V2 runtime keeps active post-remediation mesh intervention when remediation ends unverified", async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-unverified-mesh-"));
    const sessionID = "ses_unverified_mesh_v2_test";
    const stream = createAsyncEventStream();
    t.after(() => {
      stream.close();
      forgetMeshSession(sessionID);
      fs.rmSync(dir, { recursive: true, force: true });
    });

    let currentMessages = [
      { id: "u1", type: "user", text: "Implement compute()" },
      {
        id: "a1",
        type: "assistant",
        agent: "coder",
        content: [
          {
            type: "tool",
            id: "c1",
            name: "write",
            state: { status: "completed", input: { filePath: path.join(dir, "src", "calc.ts"), content: "export function compute() {}\n" }, output: "ok" },
          },
          { type: "text", text: "Added compute." },
        ],
      },
    ];
    let syntheticsSent = [];

    const ctx = {
      location: { directory: dir },
      options: {
        enabled: true,
        remediationBudget: 1,
        secrets: { enabled: false },
        rules: {
          "integrity/no-stubs": "error",
          "quality/no-shortcuts": "off",
          "integrity/no-unverified-claims": "off",
          "integrity/no-silent-failure": "off",
          "task/completion-gate": "off",
        },
      },
      event: {
        subscribe: () => stream.iterable,
      },
      session: {
        get: async () => ({ id: sessionID, parentID: "ses_parent_root", agent: "coder", location: { directory: dir } }),
        context: async () => currentMessages,
        synthetic: async (input) => {
          syntheticsSent.push(input);
          return { id: `syn-${syntheticsSent.length}` };
        },
        hook: async () => ({ dispose() {} }),
      },
      agent: {
        list: async () => [{
          id: "coder",
          name: "coder",
          permissions: [
            { resource: "*", action: "edit", effect: "allow" },
            { resource: "*", action: "shell", effect: "allow" },
          ],
        }],
        get: async () => ({
          id: "coder",
          name: "coder",
          permissions: [
            { resource: "*", action: "edit", effect: "allow" },
            { resource: "*", action: "shell", effect: "allow" },
          ],
        }),
      },
      tool: { hook: async () => ({ dispose() {} }) },
      shell: { hook: async () => ({ dispose() {} }) },
      rpc: { register: async () => ({ dispose() {} }) },
    };

    const dispose = await Guardian.setup(ctx);
    t.after(async () => {
      if (typeof dispose === "function") await dispose();
    });

    // Turn 1: triggers remediation on production stub
    stream.push({
      type: "session.execution.succeeded",
      location: { directory: dir },
      data: { sessionID },
    });
    for (let i = 0; i < 40 && syntheticsSent.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(syntheticsSent.length, 1, "turn 1 must emit remediation prompt");

    // Simulate stale/cleared intervention before turn 2 finishes unverified
    clearMeshIntervention(sessionID, "opencode-guardian");

    // Turn 2: responds with prose only without touching src/calc.ts -> remediation-unverified
    currentMessages = [
      ...currentMessages,
      { id: "u2", type: "synthetic", text: syntheticsSent[0].text, metadata: syntheticsSent[0].metadata },
      { id: "a2", type: "assistant", agent: "coder", content: [{ type: "text", text: "Reviewed and left as-is." }] },
    ];
    stream.push({
      type: "session.execution.succeeded",
      location: { directory: dir },
      data: { sessionID },
    });
    await new Promise((r) => setTimeout(r, 150));

    const active = getLatestMeshIntervention(sessionID);
    assert.ok(active && active.active, "remediation-unverified must record an active mesh intervention");
    assert.equal(active.kind, "post-remediation");
    assert.ok(active.ruleIds.includes("integrity/no-stubs"));
  });
});
