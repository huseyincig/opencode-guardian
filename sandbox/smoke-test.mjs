import path from "node:path";
import OpencodeGuardian from "../dist/index.js";

console.log("==================================================");
console.log("  OPENCODE-GUARDIAN ISOLATED SANDBOX SMOKE TEST");
console.log("==================================================");

const sandboxDir = path.dirname(new URL(import.meta.url).pathname);

// Mock OpenCode client
let lastPrompt = null;
const mockClient = {
  session: {
    messages: async () => ({ data: [
      {
        info: { id: "user-1", role: "user" },
        parts: [{ type: "text", text: "Please implement the payment calculation." }],
      },
      {
        info: { id: "asst-1", role: "assistant" },
        parts: [
          {
            type: "text",
            text: "I finished it. This basic implementation is good enough for now, and the failure on checkout is unrelated to this change.",
          },
          {
            type: "tool",
            state: {
              input: {
                content: "function calculate() {\n  // TODO: implement later\n  throw new NotImplementedError();\n}",
              },
            },
          },
        ],
      },
    ] }),
    promptAsync: async ({ body }) => {
      lastPrompt = body.parts?.[0]?.text;
      return { data: {}, error: undefined };
    },
  },
};

// Initialize plugin in OpenCode v1 mode
console.log("\n[1] Initializing OpencodeGuardian via OpenCode v1 'server' adapter...");
const hooks = await OpencodeGuardian.server({
  client: mockClient,
  directory: sandboxDir,
});

console.log("    ✓ Plugin initialized. Registered hooks:", Object.keys(hooks));

// Simulate session.idle event
console.log("\n[2] Triggering 'session.idle' event...");
await hooks.event({
  event: {
    type: "session.idle",
    properties: { sessionID: "sandbox-session-001" },
  },
});

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
