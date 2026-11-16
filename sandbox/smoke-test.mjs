import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import OpencodeGuardian from "../dist/index.js";

console.log("==================================================");
console.log("  OPENCODE-GUARDIAN ISOLATED SANDBOX SMOKE TEST");
console.log("==================================================");

const sandboxDir = path.dirname(new URL(import.meta.url).pathname);
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-smoke-state-"));
process.env.OPENCODE_GUARDIAN_STATE_DIR = stateDir;

// Mock OpenCode V2 host context
let lastPrompt = null;
let emitEvent = null;
const mockHost = {
  location: { directory: sandboxDir },
  options: { secrets: { enabled: false }, updateNotice: { enabled: false } },
  event: {
    subscribe({ signal }) {
      return (async function* () {
        while (!signal.aborted) {
          const next = await new Promise((resolve) => { emitEvent = resolve; });
          if (next === null) break;
          yield next;
        }
      })();
    },
  },
  session: {
    get: async () => ({ id: "sandbox-session-001", parentID: undefined }),
    context: async () => [
      { id: "user-1", type: "user", text: "Please implement the payment calculation." },
      {
        id: "asst-1",
        type: "assistant",
        content: [
          {
            type: "text",
            text: "I finished it. This basic implementation is good enough for now, and the failure on checkout is unrelated to this change.",
          },
          {
            type: "tool",
            name: "write",
            state: {
              input: {
                content: "function calculate() {\n  // TODO: implement later\n  throw new NotImplementedError();\n}",
              },
            },
          },
        ],
      },
    ],
    synthetic: async ({ text, resume }) => {
      if (resume !== false) lastPrompt = text;
    },
  },
};

// Initialize plugin in OpenCode V2 mode
console.log("\n[1] Initializing OpencodeGuardian via OpenCode V2 'setup(ctx)'...");
const cleanup = await OpencodeGuardian.setup(mockHost);
console.log("    ✓ Plugin initialized via V2 setup().");

// Simulate session.idle event
console.log("\n[2] Triggering 'session.idle' event...");
emitEvent({ type: "session.idle", data: { sessionID: "sandbox-session-001" } });
const deadline = Date.now() + 1500;
while (!lastPrompt && Date.now() < deadline) {
  await new Promise((r) => setTimeout(r, 15));
}
emitEvent(null);
await cleanup?.();
fs.rmSync(stateDir, { recursive: true, force: true });

if (lastPrompt) {
  console.log("\n[3] RESULT: 🛡️ OpencodeGuardian successfully intercepted and blocked the agent!");
  console.log("--------------------------------------------------");
  console.log("Remediation prompt sent to agent:\n");
  console.log(lastPrompt);
  console.log("--------------------------------------------------");
  console.log("\n✓ All systems operational in isolated sandbox. No live processes touched.");
} else {
  console.error("FAIL: OpencodeGuardian did not intercept the turn.");
  process.exit(1);
}
