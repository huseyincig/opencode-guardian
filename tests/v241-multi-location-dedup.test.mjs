import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, {
  clearGuardianTelemetryConfig,
  readGuardianStatus,
} from "../dist/index.js";

function createSharedGlobalBus() {
  const subscribers = new Set();
  return {
    subscribe({ signal }) {
      const queue = [];
      let wake = null;
      const sub = {
        push(ev) {
          queue.push(ev);
          wake?.();
        },
      };
      subscribers.add(sub);
      const onAbort = () => {
        subscribers.delete(sub);
        wake?.();
      };
      signal.addEventListener("abort", onAbort, { once: true });
      return (async function* () {
        try {
          while (!signal.aborted) {
            if (!queue.length) {
              await new Promise((resolve) => {
                wake = resolve;
              });
            }
            while (queue.length && !signal.aborted) {
              yield queue.shift();
            }
          }
        } finally {
          subscribers.delete(sub);
        }
      })();
    },
    async broadcast(ev, settleMs = 60) {
      for (const sub of Array.from(subscribers)) {
        sub.push(ev);
      }
      await new Promise((r) => setTimeout(r, settleMs));
    },
  };
}

function makeHost({ dir, bus, sessionsById, synthetics, interrupts = [] }) {
  return {
    location: { directory: dir },
    event: {
      subscribe: (opts) => bus.subscribe(opts),
    },
    session: {
      async get({ sessionID }) {
        const meta = sessionsById.get(sessionID);
        return {
          id: sessionID,
          parentID: meta?.parentID,
          location: { directory: meta?.directory ?? dir },
        };
      },
      async context({ sessionID }) {
        return sessionsById.get(sessionID)?.messages ?? [];
      },
      async synthetic(req) {
        synthetics.push({ ...req, viaDirectory: dir });
        return { id: `syn-${synthetics.length}` };
      },
      async interrupt({ sessionID }) {
        interrupts.push({ sessionID, viaDirectory: dir });
      },
      async wait() {
        return { status: "idle" };
      },
      async hook() {
        return { dispose() {} };
      },
    },
    tool: {
      async hook() {
        return { dispose() {} };
      },
    },
    shell: {
      async hook() {
        return { dispose() {} };
      },
    },
  };
}

test("1. Multi-location server: 3 Guardian instances on shared global event bus remediate a session EXACTLY ONCE", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-multiloc-"));
  const globalCfgDir = path.join(root, "global-opencode");
  const dirHi = path.join(root, "opencode-hi");
  const dirGuardian = path.join(root, "opencode-guardian");
  const dirRoot = path.join(root, "root-home");
  for (const d of [globalCfgDir, dirHi, dirGuardian, dirRoot]) {
    fs.mkdirSync(d, { recursive: true });
  }
  // Global install (same as real ~/.config/opencode/opencode.json with opencode-guardian@latest)
  fs.writeFileSync(
    path.join(globalCfgDir, "opencode.json"),
    JSON.stringify({ plugin: ["opencode-guardian@latest"] })
  );
  for (const d of [dirHi, dirGuardian, dirRoot]) {
    fs.writeFileSync(
      path.join(d, "opencode-guardian.json"),
      JSON.stringify({ enabled: true, updateNotice: { enabled: false }, telemetry: { level: "violations" } })
    );
  }

  const prevConfigDir = process.env.OPENCODE_CONFIG_DIR;
  process.env.OPENCODE_CONFIG_DIR = globalCfgDir;
  t.after(() => {
    if (prevConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
    else process.env.OPENCODE_CONFIG_DIR = prevConfigDir;
    clearGuardianTelemetryConfig();
    fs.rmSync(root, { recursive: true, force: true });
  });

  const bus = createSharedGlobalBus();
  const synthetics = [];
  const sessionsById = new Map([
    [
      "ses-hi-root",
      {
        directory: dirHi,
        messages: [
          { id: "u1", type: "user", text: "Fix the failing unit test." },
          {
            id: "a1",
            type: "assistant",
            agent: "hi-manager",
            content: [{ type: "text", text: "The test failure is unrelated to this change and pre-existing." }],
          },
        ],
      },
    ],
  ]);

  const cleanups = [];
  t.after(async () => {
    for (const c of cleanups.reverse()) await c?.();
  });

  // Boot 3 locations inside the same server process (mimics real opencode.exe serve --service)
  cleanups.push(await Guardian.setup(makeHost({ dir: dirHi, bus, sessionsById, synthetics })));
  cleanups.push(await Guardian.setup(makeHost({ dir: dirGuardian, bus, sessionsById, synthetics })));
  cleanups.push(await Guardian.setup(makeHost({ dir: dirRoot, bus, sessionsById, synthetics })));

  // Broadcast ONE session.execution.succeeded to ALL 3 instances (with event.location)
  await bus.broadcast({
    type: "session.execution.succeeded",
    location: { directory: dirHi },
    data: { sessionID: "ses-hi-root" },
  });

  assert.equal(
    synthetics.length,
    1,
    `expected exactly 1 remediation across 3 server locations, got ${synthetics.length}`
  );
  assert.equal(
    synthetics[0].viaDirectory,
    dirHi,
    "the owning location instance must perform the remediation"
  );
  assert.equal(readGuardianStatus(dirHi).remediations, 1, "telemetry must record exactly 1 remediation");
});

test("2. Overlapping reload instances for the SAME directory remediate EXACTLY ONCE and hand off cleanly on dispose", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-overlap-"));
  t.after(() => {
    clearGuardianTelemetryConfig();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  fs.writeFileSync(
    path.join(dir, "opencode-guardian.json"),
    JSON.stringify({ enabled: true, updateNotice: { enabled: false }, telemetry: { level: "violations" } })
  );

  const bus = createSharedGlobalBus();
  const synthetics = [];
  const sessionsById = new Map([
    [
      "ses-overlap-1",
      {
        directory: dir,
        messages: [
          { id: "u1", type: "user", text: "Fix the failing test." },
          {
            id: "a1",
            type: "assistant",
            content: [{ type: "text", text: "The test failure is unrelated to this change and pre-existing." }],
          },
        ],
      },
    ],
  ]);

  const cleanup1 = await Guardian.setup(makeHost({ dir, bus, sessionsById, synthetics }));
  const cleanup2 = await Guardian.setup(makeHost({ dir, bus, sessionsById, synthetics }));
  t.after(async () => {
    await cleanup2?.();
    await cleanup1?.();
  });

  // Event without event.location (forces session.get lookup path too)
  await bus.broadcast({
    type: "session.execution.succeeded",
    data: { sessionID: "ses-overlap-1" },
  });
  assert.equal(synthetics.length, 1, `overlapping same-dir instances must send 1 remediation, got ${synthetics.length}`);

  // Dispose old instance; new instance must continue inspecting new turns
  await cleanup1?.();
  sessionsById.set("ses-overlap-2", {
    directory: dir,
    messages: [
      { id: "u2", type: "user", text: "Fix the other test." },
      {
        id: "a2",
        type: "assistant",
        content: [{ type: "text", text: "The test failure is unrelated to this change and pre-existing." }],
      },
    ],
  });
  await bus.broadcast({
    type: "session.execution.succeeded",
    location: { directory: dir },
    data: { sessionID: "ses-overlap-2" },
  });
  assert.equal(synthetics.length, 2, "surviving instance must handle subsequent sessions after old instance disposes");
});

test("3. Multi-location StreamLoopWatcher interrupts a looping session EXACTLY ONCE across 3 instances", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-multiloc-stream-"));
  const globalCfgDir = path.join(root, "global-opencode");
  const dirA = path.join(root, "proj-a");
  const dirB = path.join(root, "proj-b");
  const dirC = path.join(root, "proj-c");
  for (const d of [globalCfgDir, dirA, dirB, dirC]) fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(globalCfgDir, "opencode.json"), JSON.stringify({ plugin: ["opencode-guardian@latest"] }));
  for (const d of [dirA, dirB, dirC]) {
    fs.writeFileSync(path.join(d, "opencode-guardian.json"), JSON.stringify({ enabled: true, updateNotice: { enabled: false } }));
  }

  const prevConfigDir = process.env.OPENCODE_CONFIG_DIR;
  process.env.OPENCODE_CONFIG_DIR = globalCfgDir;
  t.after(() => {
    if (prevConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
    else process.env.OPENCODE_CONFIG_DIR = prevConfigDir;
    clearGuardianTelemetryConfig();
    fs.rmSync(root, { recursive: true, force: true });
  });

  const bus = createSharedGlobalBus();
  const synthetics = [];
  const interrupts = [];
  const sessionsById = new Map([["ses-loop-a", { directory: dirA, messages: [] }]]);

  const cleanups = [];
  t.after(async () => {
    for (const c of cleanups.reverse()) await c?.();
  });
  cleanups.push(await Guardian.setup(makeHost({ dir: dirA, bus, sessionsById, synthetics, interrupts })));
  cleanups.push(await Guardian.setup(makeHost({ dir: dirB, bus, sessionsById, synthetics, interrupts })));
  cleanups.push(await Guardian.setup(makeHost({ dir: dirC, bus, sessionsById, synthetics, interrupts })));

  await bus.broadcast(
    {
      type: "session.reasoning.delta",
      location: { directory: dirA },
      data: {
        sessionID: "ses-loop-a",
        assistantMessageID: "msg-loop-1",
        ordinal: 0,
        delta: "Hmm... ".repeat(35),
      },
    },
    80
  );

  assert.equal(interrupts.length, 1, `expected exactly 1 stream interrupt across 3 locations, got ${interrupts.length}`);
  assert.equal(interrupts[0].viaDirectory, dirA, "interrupt must be issued by the owning location instance");
});

test("4. Single global Guardian instance still supervises a second directory when no dedicated instance exists there", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-single-global-"));
  const globalCfgDir = path.join(root, "global-opencode");
  const dirA = path.join(root, "proj-a");
  const dirB = path.join(root, "proj-b");
  for (const d of [globalCfgDir, dirA, dirB]) fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(globalCfgDir, "opencode.json"), JSON.stringify({ plugin: ["opencode-guardian@latest"] }));
  fs.writeFileSync(path.join(dirA, "opencode-guardian.json"), JSON.stringify({ enabled: true, updateNotice: { enabled: false } }));

  const prevConfigDir = process.env.OPENCODE_CONFIG_DIR;
  process.env.OPENCODE_CONFIG_DIR = globalCfgDir;
  t.after(() => {
    if (prevConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
    else process.env.OPENCODE_CONFIG_DIR = prevConfigDir;
    clearGuardianTelemetryConfig();
    fs.rmSync(root, { recursive: true, force: true });
  });

  const bus = createSharedGlobalBus();
  const synthetics = [];
  const sessionsById = new Map([
    [
      "ses-in-b",
      {
        directory: dirB,
        messages: [
          { id: "u1", type: "user", text: "Fix the bug." },
          {
            id: "a1",
            type: "assistant",
            content: [{ type: "text", text: "The test failure is unrelated to this change and pre-existing." }],
          },
        ],
      },
    ],
  ]);

  const cleanup = await Guardian.setup(makeHost({ dir: dirA, bus, sessionsById, synthetics }));
  t.after(async () => cleanup?.());

  await bus.broadcast({
    type: "session.execution.succeeded",
    location: { directory: dirB },
    data: { sessionID: "ses-in-b" },
  });

  assert.equal(synthetics.length, 1, "single global instance must still supervise projectB when no instance owns projectB");
});

test("5. TUI sidebar header stays clean next to version and conversation banner shows distinct intervention type badges", () => {
  const source = fs.readFileSync(new URL("../src/tui.tsx", import.meta.url), "utf8");
  const runtime = fs.readFileSync(new URL("../dist/tui-runtime.js", import.meta.url), "utf8");

  // Sidebar header must NOT cram inline `· ${statusLabel()}` next to the version
  assert.doesNotMatch(source, /· \$\{statusLabel\(\)\}/, "status/warning text must not clutter the version header row");

  // Conversation banner must clearly distinguish every intervention type
  for (const badge of ["⊘ BLOCKED", "↻ REMEDIATION", "⏹ STREAM STOP", "▲ WARNING"]) {
    assert.ok(source.includes(badge), `src/tui.tsx must define distinct badge ${badge}`);
    assert.ok(runtime.includes(badge), `dist/tui-runtime.js must emit distinct badge ${badge}`);
  }
});
