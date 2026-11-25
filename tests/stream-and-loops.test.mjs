import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, { circuitBreakerRule, detectDegenerativeLoop, normalizeV2Messages, readGuardianActivity, readGuardianStatus } from "../dist/index.js";

describe("Degenerative Loop Detection", () => {
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
});

describe("StreamLoopWatcher Hardening", () => {
  const loop = "我想想".repeat(70);
  function fixture(t, rules = "error") {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-stream-fixes-"));
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
      rules: { "runtime/circuit-breaker": rules }, secrets: { enabled: false }, updateNotice: { enabled: false },
    }));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    return directory;
  }

  async function v2(t, setting = "error", interrupt = async () => {}, sessionDirectory) {
    const directory = fixture(t, setting);
    let calls = 0, wake;
    const queue = [];
    const cleanup = await Guardian.setup({ location: { directory },
      session: {
        async context() { return []; }, async synthetic() {},
        async get() { return { location: { directory: sessionDirectory ?? directory } }; },
        async interrupt(input) { calls++; return interrupt(input); },
      },
      event: { subscribe({ signal }) { return (async function* () {
        const stop = () => wake?.();
        signal.addEventListener("abort", stop, { once: true });
        try { while (!signal.aborted) {
          if (!queue.length) await new Promise(resolve => { wake = resolve; });
          const entry = queue.shift();
          if (entry) { yield entry.event; entry.resolve(); }
        } } finally { signal.removeEventListener("abort", stop); }
      })(); } },
    });
    t.after(cleanup);
    const send = async event => {
      await new Promise(resolve => { queue.push({ event, resolve }); wake?.(); });
      await new Promise(resolve => setImmediate(resolve));
    };
    const delta = (value, type = "text", ordinal = 0, assistantMessageID = "a") => send({
      type: `session.${type}.delta`, data: { sessionID: "s", assistantMessageID, ordinal, delta: value },
    });
    return { directory, cleanup, send, delta, get calls() { return calls; } };
  }

  test("native V2 text and reasoning deltas interrupt without waiting for idle", async t => {
    for (const kind of ["text", "reasoning"]) {
      const h = await v2(t);
      for (let n = 0; n < 8; n++) await h.delta("我想想".repeat(12), kind, 0);
      assert.equal(h.calls, 1, kind);
      assert.equal(readGuardianStatus(h.directory).blocked, 0, "a stop request is not a preflight prevention");
      assert.ok(readGuardianActivity(h.directory, 30).some(e => e.kind === "stream-interrupt-requested"));
    }
  });

  test("V2 honors string and object warn/off settings", async t => {
    for (const setting of ["off", { severity: "off" }, "warn", { severity: "warn" }]) {
      const b = await v2(t, setting); await b.delta(loop);
      assert.equal(b.calls, 0, JSON.stringify(setting));
      if (setting === "warn" || setting.severity === "warn") {
        assert.equal(readGuardianStatus(b.directory).warnings, 1);
      }
    }
  });

  test("V2 retries a rejected interrupt but deduplicates successful admission", async t => {
    let attempts = 0;
    const h = await v2(t, "error", async () => { if (++attempts === 1) throw new Error("fixture transport failure"); });
    await h.delta(loop); await h.delta(loop); await h.delta(loop);
    assert.equal(h.calls, 2);
    assert.equal(readGuardianStatus(h.directory).errors, 1);
  });

  test("V2 uses the active project's rule setting for native deltas", async t => {
    const other = fixture(t, "off");
    const h = await v2(t, "error", async () => {}, other);
    await h.delta(loop);
    assert.equal(h.calls, 0);
  });

  test("V2 reasoning survives normalization and reaches the post-turn rule", () => {
    const messages = normalizeV2Messages([{ id: "a", type: "assistant", content: [{ type: "reasoning", text: loop }] }], "s");
    assert.equal(messages[0].parts[0]?.type, "reasoning");
    assert.equal(circuitBreakerRule.inspect({ sessionID: "s", directory: "/tmp", messages,
      currentTurn: messages, ruleConfig: {} }).decision, "block");
  });

  test("quoted numeric/hex fixtures pass even at their streaming prefixes", () => {
    for (const char of ["0", "a"]) for (const quote of ['"', "'"]) {
      for (const suffix of ["", quote, quote + ";\n"]) {
        assert.equal(detectDegenerativeLoop(`const fixture = ${quote}${char.repeat(64)}${suffix}`).detected, false);
      }
    }
  });

  test("long periodic sentences and astral Unicode cycles are detected", () => {
    for (const unit of [
      "I need to check the implementation before deciding what to change. ",
      "この実装を変更する前に、処理の流れとテストの結果をもう一度確認する必要があります。",
      "𠀀𠀁𠀂",
    ]) assert.equal(detectDegenerativeLoop(unit.repeat(100)).detected, true, unit);
  });

  test("V2 lifecycle events invalidate a detection while its project lookup is pending", async t => {
    const directory = fixture(t);
    let release, lookupStarted;
    const started = new Promise(resolve => { lookupStarted = resolve; });
    const lookup = new Promise(resolve => { release = resolve; });
    let interruptCalls = 0, wake;
    const queue = [];
    const cleanup = await Guardian.setup({ location: { directory }, session: {
      async get() { lookupStarted(); await lookup; return { location: { directory } }; },
      async context() { return []; }, async synthetic() {}, async interrupt() { interruptCalls++; },
    }, event: { subscribe({ signal }) { return (async function* () {
      signal.addEventListener("abort", () => wake?.(), { once: true });
      while (!signal.aborted) {
        if (!queue.length) await new Promise(resolve => { wake = resolve; });
        const item = queue.shift(); if (item) yield item;
      }
    })(); } } });
    t.after(cleanup);
    queue.push({ type: "session.text.delta", data: { sessionID: "s", assistantMessageID: "old", ordinal: 0, delta: loop } }); wake?.();
    await started;
    queue.push({ type: "session.execution.succeeded", data: { sessionID: "s" } },
      { type: "session.text.delta", data: { sessionID: "s", assistantMessageID: "new", ordinal: 0, delta: "New response without repetition." } }); wake?.();
    await new Promise(resolve => setImmediate(resolve));
    release(); await new Promise(resolve => setImmediate(resolve));
    assert.equal(interruptCalls, 0, "the stop belongs to the completed old response");
  });

  test("V2 stop requests explicitly disable host resumption", async t => {
    let input;
    const h = await v2(t, "error", async value => { input = value; });
    await h.delta(loop);
    assert.deepEqual(input, { sessionID: "s", resume: false });
  });

  test("V2 ignores completed parts and session deletion resets watcher ownership", async t => {
    const h = await v2(t);
    await h.send({ type: "session.reasoning.ended", data: { sessionID: "s", assistantMessageID: "a", ordinal: 0 } });
    await h.delta(loop, "reasoning");
    assert.equal(h.calls, 0);
    await h.delta(loop); assert.equal(h.calls, 1);
    await h.send({ type: "session.deleted", data: { sessionID: "s" } });
    await h.delta(loop); assert.equal(h.calls, 2);
  });
});

describe("Stream Interruption Verification", () => {
  const loop = "我想想".repeat(70);

  async function harness(t) {
    process.env.OPENCODE_GUARDIAN_STREAM_VERIFY_MS = "150";
    t.after(() => { delete process.env.OPENCODE_GUARDIAN_STREAM_VERIFY_MS; });
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-stream-verify-"));
    fs.writeFileSync(path.join(directory, "opencode-guardian.json"), JSON.stringify({
      secrets: { enabled: false }, updateNotice: { enabled: false },
    }));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    let calls = 0, wake;
    const queue = [];
    const cleanup = await Guardian.setup({
      location: { directory },
      session: {
        async context() { return []; },
        async synthetic() {},
        async get() { return { location: { directory } }; },
        async interrupt() { calls++; },
      },
      event: { subscribe({ signal }) { return (async function* () {
        const stop = () => wake?.();
        signal.addEventListener("abort", stop, { once: true });
        try { while (!signal.aborted) {
          if (!queue.length) await new Promise(resolve => { wake = resolve; });
          const entry = queue.shift();
          if (entry) { yield entry.event; entry.resolve(); }
        } } finally { signal.removeEventListener("abort", stop); }
      })(); } },
    });
    t.after(cleanup);
    const send = async event => {
      await new Promise(resolve => { queue.push({ event, resolve }); wake?.(); });
      await new Promise(resolve => setImmediate(resolve));
    };
    const delta = value => send({
      type: "session.text.delta",
      data: { sessionID: "s", assistantMessageID: "a", ordinal: 0, delta: value },
    });
    const kinds = () => readGuardianActivity(directory, 50).map(e => e.kind);
    const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
    return { directory, send, delta, kinds, sleep, get calls() { return calls; } };
  }

  test("stream stop is verified once the host reports the execution interrupted", async t => {
    const h = await harness(t);
    await h.delta(loop);
    assert.equal(h.calls, 1);
    await h.send({ type: "session.execution.interrupted", data: { sessionID: "s" } });
    assert.ok(h.kinds().includes("stream-interrupt-verified"));
    const status = readGuardianStatus(h.directory);
    assert.equal(status.streamStops, 1);
    assert.equal(status.streamVerified, 1);
    assert.equal(status.streamIneffective, 0);
    await h.sleep(250);
    assert.ok(!h.kinds().includes("stream-interrupt-ineffective"));
  });

  test("stream stop is ineffective when deltas keep flowing, and the loop may be interrupted again", async t => {
    const h = await harness(t);
    await h.delta(loop);
    assert.equal(h.calls, 1);
    await h.delta("我想想".repeat(12));
    await h.sleep(300);
    assert.ok(h.kinds().includes("stream-interrupt-ineffective"));
    assert.ok(!h.kinds().includes("stream-interrupt-verified"));
    const status = readGuardianStatus(h.directory);
    assert.equal(status.streamStops, 1);
    assert.equal(status.streamIneffective, 1);
    await h.delta(loop);
    assert.equal(h.calls, 2, "an ineffective stop must allow another interrupt attempt");
  });

  test("stream stop stays unverified when the host sends neither a terminal event nor more deltas", async t => {
    const h = await harness(t);
    await h.delta(loop);
    await h.sleep(300);
    const kinds = h.kinds();
    assert.ok(kinds.includes("stream-interrupt-requested"));
    assert.ok(!kinds.includes("stream-interrupt-verified"));
    assert.ok(!kinds.includes("stream-interrupt-ineffective"));
    assert.equal(readGuardianStatus(h.directory).streamStops, 1);
  });
});
