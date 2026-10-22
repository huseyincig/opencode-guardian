import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, {
  detectDegenerativeLoop,
  circuitBreakerRule,
} from "../dist/index.js";

// ============================================================================
// 1. Core Algorithmic Unit Tests (detectDegenerativeLoop)
// ============================================================================

test("detectDegenerativeLoop detects English 'Hmm... ' reasoning loop", () => {
  const text = "Let me think about this step:\n" + "Hmm... ".repeat(12);
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, true);
  assert.equal(result.kind, "periodic-cycle");
  assert.ok(result.repetitions >= 5);
  assert.ok(result.span >= 35);
  assert.match(result.pattern, /Hmm/);
});

test("detectDegenerativeLoop tolerates trailing partial tokens (offset tolerance)", () => {
  // Model generated 12 repeats of "Hmm... " followed by a partial "Hm"
  const text = "Thinking trace:\n" + "Hmm... ".repeat(12) + "Hm";
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, true);
  assert.equal(result.kind, "periodic-cycle");
  assert.ok(result.repetitions >= 5);
});

test("detectDegenerativeLoop detects English phrase loop ('wait, ')", () => {
  const text = "Checking context: " + "wait, wait, wait, ".repeat(8);
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, true);
  assert.equal(result.kind, "periodic-cycle");
  assert.ok(result.repetitions >= 5);
});

test("detectDegenerativeLoop detects Chinese single ideogram loop ('等等等...')", () => {
  const text = "思考过程：\n" + "等".repeat(25);
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, true);
  assert.equal(result.kind, "periodic-cycle");
  assert.equal(result.pattern, "等");
  assert.ok(result.repetitions >= 15);
});

test("detectDegenerativeLoop detects Chinese phrase loop ('我想想')", () => {
  const text = "让我分析一下问题：\n" + "我想想".repeat(10);
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, true);
  assert.equal(result.kind, "periodic-cycle");
  assert.equal(result.pattern, "我想想");
  assert.ok(result.repetitions >= 5);
});

test("detectDegenerativeLoop detects Chinese punctuated phrase ('等等，')", () => {
  const text = "分析如下：" + "等等，等等，".repeat(8);
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, true);
  assert.equal(result.kind, "periodic-cycle");
  assert.ok(result.repetitions >= 5);
});

test("detectDegenerativeLoop detects Japanese phrase loop ('確認中...')", () => {
  const text = "状況の確認：\n" + "確認中...確認中...".repeat(6);
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, true);
  assert.equal(result.kind, "periodic-cycle");
  assert.ok(result.repetitions >= 5);
});

test("detectDegenerativeLoop detects Japanese single kana loop ('あああ...')", () => {
  const text = "あ".repeat(32);
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, true);
  assert.equal(result.kind, "periodic-cycle");
  assert.equal(result.pattern, "あ");
  assert.ok(result.repetitions >= 15);
});

test("detectDegenerativeLoop detects Turkish phrase repeat loop ('bekle, ')", () => {
  const text = "Düşünelim:\n" + "bekle, bekle, ".repeat(8);
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, true);
  assert.equal(result.kind, "periodic-cycle");
  assert.ok(result.repetitions >= 5);
});

test("detectDegenerativeLoop detects code token loop ('None, ')", () => {
  const text = "const values = [" + "None, None, ".repeat(10) + "None];";
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, true);
  assert.equal(result.kind, "periodic-cycle");
  assert.ok(result.repetitions >= 5);
});

test("detectDegenerativeLoop detects code statement loop ('break; ')", () => {
  const text = "while (running) {\n" + "  break; break;\n".repeat(8) + "}";
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, true);
  assert.equal(result.kind, "periodic-cycle");
  assert.ok(result.repetitions >= 5);
});

test("detectDegenerativeLoop detects secondary low-entropy babble collapse", () => {
  // Alternating 2 characters non-periodically over 70 characters
  const text = "Analysis starting:\n" + "abababbabbabaabaababbabababaabbababaabbabaabbabbababababaabaab";
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, true);
  assert.ok(result.kind === "low-entropy" || result.kind === "periodic-cycle");
});

// ============================================================================
// 2. Negative Legitimate Tests (Zero False Positives)
// ============================================================================

test("detectDegenerativeLoop does NOT flag Markdown table rows or dividers", () => {
  const text =
    "| Column A | Column B | Column C | Column D |\n" +
    "|---|---|---|---|---|---|---|---|---|---|\n" +
    "| 1 | 2 | 3 | 4 |\n";
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, false);
});

test("detectDegenerativeLoop does NOT flag banner comment horizontal dividers", () => {
  const text =
    "// ================================================================================\n" +
    "// Service Implementation Header\n" +
    "// ================================================================================\n";
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, false);
});

test("detectDegenerativeLoop does NOT flag hash or asterisk dividers", () => {
  const text =
    "################################################################################\n" +
    "/* ************************************************************************** */\n" +
    "--------------------------------------------------------------------------------\n";
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, false);
});

test("detectDegenerativeLoop does NOT flag small array fixtures with repeated items", () => {
  const text =
    "const fixture = ['item', 'item', 'item', 'item'];\n" +
    "assert.equal(fixture.length, 4);\n";
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, false);
});

test("detectDegenerativeLoop does NOT flag zero matrix array initializers", () => {
  const text =
    "const zeros = [0, 0, 0, 0, 0, 0, 0, 0];\n" +
    "return { status: 200, data: zeros };\n";
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, false);
});

test("detectDegenerativeLoop does NOT flag normal prose", () => {
  const text =
    "We investigated the failure and found that the configuration file was missing.\n" +
    "It was a very very large log file, but after parsing the entries everything worked.";
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, false);
});

test("detectDegenerativeLoop does NOT flag short text (< 30 chars)", () => {
  const text = "Hmm... Hmm... Hmm...";
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, false);
});

test("detectDegenerativeLoop does NOT flag normal code loops", () => {
  const text =
    "for (let i = 0; i < 10; i++) {\n" +
    "  for (let j = 0; j < 10; j++) {\n" +
    "    matrix[i][j] = i * j;\n" +
    "  }\n" +
    "}\n";
  const result = detectDegenerativeLoop(text);
  assert.equal(result.detected, false);
});

// ============================================================================
// 3. Rule Integration Tests (circuitBreakerRule)
// ============================================================================

test("circuitBreakerRule trips when assistant turn contains degenerative reasoning", () => {
  const context = {
    sessionID: "test-session",
    directory: "/tmp",
    ruleConfig: {},
    messages: [],
    currentTurn: [
      {
        info: { id: "u1", role: "user" },
        parts: [{ type: "text", text: "Refactor the database queries." }],
      },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "reasoning",
            text: "Let me check the query logic:\n" + "Hmm... ".repeat(15),
          },
        ],
      },
    ],
  };

  const result = circuitBreakerRule.inspect(context);
  assert.equal(result.decision, "block");
  assert.equal(result.ruleId, "runtime/circuit-breaker");
  assert.ok(result.findings.some((f) => f.pattern === "Degenerative loop"));
  assert.match(
    result.remediationPrompt ?? "",
    /Circuit breaker tripped! Degenerative reasoning\/text loop detected/
  );
  assert.match(
    result.remediationPrompt ?? "",
    /Stop the repetitive token or phrase generation cycle immediately/
  );
});

test("circuitBreakerRule passes when assistant turn contains normal clean response", () => {
  const context = {
    sessionID: "test-clean-session",
    directory: "/tmp",
    ruleConfig: {},
    messages: [],
    currentTurn: [
      {
        info: { id: "u1", role: "user" },
        parts: [{ type: "text", text: "What is 2 + 2?" }],
      },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "text",
            text: "2 + 2 equals 4. Let me know if you need any other math help!",
          },
        ],
      },
    ],
  };

  const result = circuitBreakerRule.inspect(context);
  assert.equal(result.decision, "pass");
  assert.equal(result.findings.length, 0);
});

// ============================================================================
// 4. Live In-Flight Streaming Abort Integration Test
// ============================================================================

test("V1 in-flight message.part.updated aborts streaming session on degenerative loop", async (t) => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "guardian-abort-streaming-")
  );
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));

  let abortCalls = 0;
  let abortedSessionID = "";
  const mockClient = {
    session: {
      async abort({ path: p }) {
        abortCalls++;
        abortedSessionID = p.id;
        return { data: { success: true } };
      },
      async get() {
        return { data: { id: "stream-session" } };
      },
      async messages() {
        return { data: [] };
      },
    },
  };

  const hooks = await Guardian.server({
    directory,
    client: mockClient,
  });

  t.after(() => hooks.dispose());
  await hooks.event({ event: { type: "message.updated", properties: {
    info: { id: "assistant-stream", sessionID: "stream-session", role: "assistant", time: { created: 1 } },
  } } });
  // 1. Send normal initial text stream (no abort)
  await hooks.event({
    event: {
      type: "message.part.updated",
      properties: {
        part: {
          id: "part-1",
          messageID: "assistant-stream",
          sessionID: "stream-session",
          type: "reasoning",
          text: "Analyzing the repository structure and test suite...",
        },
      },
    },
  });
  assert.equal(abortCalls, 0, "Normal streaming must not trigger abort");

  // 2. Stream collapses into repetitive "Hmm... " loop
  await hooks.event({
    event: {
      type: "message.part.updated",
      properties: {
        part: {
          id: "part-1",
          messageID: "assistant-stream",
          sessionID: "stream-session",
          type: "reasoning",
          text:
            "Analyzing the repository structure and test suite...\n" +
            "Hmm... ".repeat(15),
        },
      },
    },
  });

  assert.equal(abortCalls, 1, "Degenerative loop must trigger client.session.abort");
  assert.equal(abortedSessionID, "stream-session");

  // 3. Further updates to the already-aborted part must not trigger duplicate aborts
  await hooks.event({
    event: {
      type: "message.part.updated",
      properties: {
        part: {
          id: "part-1",
          messageID: "assistant-stream",
          sessionID: "stream-session",
          type: "reasoning",
          text:
            "Analyzing the repository structure and test suite...\n" +
            "Hmm... ".repeat(25),
        },
      },
    },
  });
  assert.equal(abortCalls, 1, "Duplicate abort calls must be suppressed");

  await hooks.dispose();
});

test("V2 native reasoning deltas interrupt streaming session on degenerative loop", async (t) => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "guardian-abort-v2-")
  );
  fs.writeFileSync(
    path.join(directory, "opencode-guardian.json"),
    JSON.stringify({ enabled: true, secrets: { enabled: false } })
  );
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));

  let interruptCalls = 0;
  let interruptedSessionID = "";

  const host = {
    location: { directory },
    event: {
      subscribe({ signal }) {
        return (async function* () {
          yield { type: "session.reasoning.delta", data: {
            sessionID: "v2-session-1", assistantMessageID: "assistant-v2", ordinal: 0,
            delta: "Refactoring components cleanly...\n",
          } };
          yield { type: "session.reasoning.delta", data: {
            sessionID: "v2-session-1", assistantMessageID: "assistant-v2", ordinal: 0,
            delta: "我想想".repeat(15),
          } };

          await new Promise((resolve) => {
            if (signal.aborted) resolve();
            else signal.addEventListener("abort", resolve, { once: true });
          });
        })();
      },
    },
    session: {
      async context() {
        return [];
      },
      async synthetic() {},
      async interrupt({ sessionID }) {
        interruptCalls++;
        interruptedSessionID = sessionID;
      },
    },
  };

  const cleanup = await Guardian.setup(host);

  // Allow event loop to process
  const until = Date.now() + 1500;
  while (interruptCalls === 0 && Date.now() < until) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }

  assert.equal(interruptCalls, 1, "V2 degenerative loop must call session.interrupt");
  assert.equal(interruptedSessionID, "v2-session-1");

  if (typeof cleanup === "function") {
    await cleanup();
  }
});

