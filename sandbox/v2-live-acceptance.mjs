import path from "node:path";
import assert from "node:assert/strict";
import OpencodeGuardian from "../dist/index.js";
import { OpencodeGuard } from "../dist/index.js";

console.log("================================================================================");
console.log("     OPENCODE-GUARDIAN — LIVE V2 HOST ACCEPTANCE TEST SUITE");
console.log("================================================================================");

const sandboxDir = path.dirname(new URL(import.meta.url).pathname);

let syntheticCalls = 0;
let lastSyntheticMessage = null;
const registeredHooks = new Map();

const mockV2Host = {
  location: { directory: sandboxDir },
  options: {
    preflight: { enabled: true },
    notifications: { enabled: true },
  },
  event: {
    subscribe({ signal }) {
      return (async function* () {
        while (!signal.aborted) {
          await new Promise((r) => setTimeout(r, 100));
        }
      })();
    },
  },
  session: {
    async context({ sessionID }) {
      return [
        {
          id: "m-user-1",
          role: "user",
          parts: [{ type: "text", text: "Please inspect the codebase." }],
        },
        {
          id: "m-asst-1",
          role: "assistant",
          parts: [
            {
              type: "text",
              text: "I finished inspecting. The test failure is unrelated to this change and pre-existing on main.",
            },
          ],
        },
      ];
    },
    async synthetic({ sessionID, text, metadata }) {
      syntheticCalls++;
      lastSyntheticMessage = { sessionID, text, metadata };
      return { id: "syn-1" };
    },
    async get({ sessionID }) {
      return {
        id: sessionID,
        parentID: undefined,
        location: { directory: sandboxDir },
        status: { type: "idle" },
      };
    },
    async wait({ sessionID }) {
      return { status: "idle" };
    },
    async hook(kind, callback) {
      if (!registeredHooks.has(`session.${kind}`)) {
        registeredHooks.set(`session.${kind}`, []);
      }
      registeredHooks.get(`session.${kind}`).push(callback);
      return {
        async dispose() {
          const list = registeredHooks.get(`session.${kind}`) ?? [];
          const idx = list.indexOf(callback);
          if (idx >= 0) list.splice(idx, 1);
        },
      };
    },
  },
  tool: {
    async hook(kind, callback) {
      if (!registeredHooks.has(`tool.${kind}`)) {
        registeredHooks.set(`tool.${kind}`, []);
      }
      registeredHooks.get(`tool.${kind}`).push(callback);
      return {
        async dispose() {
          const list = registeredHooks.get(`tool.${kind}`) ?? [];
          const idx = list.indexOf(callback);
          if (idx >= 0) list.splice(idx, 1);
        },
      };
    },
  },
};

console.log("\n[1] Bootstrapping OpencodeGuardian in OpenCode V2 Mode...");
const cleanup = await OpencodeGuardian.setup(mockV2Host);
assert.equal(typeof cleanup, "function", "V2 setup must return a cleanup function");
console.log("    ✓ V2 Plugin setup succeeded. Returned cleanup function verified.");

console.log("\n[2] Verifying V2 Registered Security & Lifecycle Hooks...");
const expectedHooks = [
  "tool.execute.before",
  "tool.execute.after",
  "session.prompt",
  "session.context",
  "session.compaction",
  "session.generate",
  "session.title",
];
for (const h of expectedHooks) {
  assert(registeredHooks.has(h) && registeredHooks.get(h).length > 0, `Missing hook: ${h}`);
  console.log(`    ✓ Hook '${h}' registered and active`);
}

console.log("\n[3] Testing V2 Tool Preflight: Intercepting Destructive Shell Operations...");
const beforeHooks = registeredHooks.get("tool.execute.before");
let preflightBlocked = false;
try {
  for (const hook of beforeHooks) {
    await hook({
      tool: "bash",
      sessionID: "v2-test-session",
      id: "call-destructive-1",
      input: { command: "rm -rf /" },
    });
  }
} catch (error) {
  preflightBlocked = true;
  assert.match(error.message, /preflight/i);
  console.log("    ✓ Destructive command 'rm -rf /' was BLOCKED by Guardian Preflight before execution!");
}
assert.equal(preflightBlocked, true, "Destructive command must be intercepted by preflight");

console.log("\n[4] Testing V2 Tool Preflight: Intercepting Hardcoded Secrets in Write...");
let secretBlocked = false;
try {
  for (const hook of beforeHooks) {
    await hook({
      tool: "write",
      sessionID: "v2-test-session",
      id: "call-write-secret",
      input: {
        path: "config.js",
        content: 'const API_KEY = "sk-proj-1234567890abcdef1234567890abcdef";',
      },
    });
  }
} catch (error) {
  secretBlocked = true;
  assert.match(error.message, /hardcoded secret/i);
  console.log("    ✓ Hardcoded API key in file write was BLOCKED by Guardian Preflight before disk write!");
}
assert.equal(secretBlocked, true, "Hardcoded secret must be intercepted by preflight");

console.log("\n[5] Testing V2 Tool Post-Execution: Error Redaction...");
const afterHooks = registeredHooks.get("tool.execute.after");
const secretToken = "sk-proj-abcdef1234567890abcdef1234567890";
const sensitiveErrorEvent = {
  tool: "bash",
  sessionID: "v2-test-session",
  id: "call-error-secret",
  input: { command: `curl -H 'Authorization: Bearer ${secretToken}'` },
  status: "error",
  error: new Error(`Failed to connect with Authorization: Bearer ${secretToken}`),
};
for (const hook of afterHooks) {
  await hook(sensitiveErrorEvent);
}
assert(!sensitiveErrorEvent.error.message.includes(secretToken), "Secrets in tool error must be redacted");
console.log("    ✓ Tool error output was sanitized and secrets redacted before reaching agent context");

console.log("\n[6] Testing V2 Clean Teardown / Disposal...");
await cleanup();
console.log("    ✓ V2 Plugin dispose completed cleanly without resource leaks or thrown exceptions");

console.log("\n================================================================================");
console.log("  OPENCODE V2 LIVE ACCEPTANCE TESTS PASSED SUCCESSFULLY! (6/6 CHECKS)");
console.log("================================================================================");
