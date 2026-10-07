import test from "node:test";
import assert from "node:assert/strict";
import Guardian from "../dist/index.js";

const ES = "Cada vez que encuentres un error, corrígelo y vuelve a revisar todo desde el principio hasta que no queden errores.";
const ZH = "每发现一个错误就修复，然后从头重新检查，直到没有错误。";
const CODE = "export const done = true;";

function previousFix() {
  return { type: "tool", tool: "write", state: {
    status: "completed", input: { filePath: "src/feature.ts", content: CODE },
    metadata: { exit: 0 },
  } };
}

test("OpenCode V1 task hooks preserve a Spanish iterative task and request a bounded second pass", async () => {
  const prompts = [];
  const hooks = await Guardian.server({
    directory: process.cwd(),
    client: { session: {
      async get({ path: requestPath }) {
        return { data: { id: requestPath.id, parentID: undefined } };
      },
      async messages() {
        return { data: [
          { info: { id: "user-es", role: "user" }, parts: [{ type: "text", text: ES }] },
          { info: { id: "agent-es", role: "assistant" }, parts: [
            previousFix(), { type: "text", text: "Tarea completada." },
          ] },
        ] };
      },
      async promptAsync(input) { prompts.push(input.body.parts[0].text); },
    } },
  });
  await hooks["chat.message"](
    { sessionID: "spanish-task", messageID: "user-es" },
    { message: { role: "user" }, parts: [{ type: "text", text: ES }] }
  );
  const output = { system: [] };
  await hooks["experimental.chat.system.transform"]({ sessionID: "spanish-task" }, output);
  assert.match(output.system.join("\n"), /another review pass/);
  await hooks.event({ event: { type: "session.idle", properties: { sessionID: "spanish-task" } } });
  assert.equal(prompts.length, 1);
  assert.match(prompts[0], /another substantive review/);
});

test("OpenCode V2 typed prompt/context and idle path preserve Chinese task requirements", async () => {
  const handlers = new Map();
  const issued = [];
  let releaseEvent;
  const context = {
    location: { directory: process.cwd() },
    options: { secrets: { enabled: false } },
    event: {
      subscribe({ signal }) {
        return (async function* () {
          await new Promise((resolve) => { releaseEvent = resolve; });
          yield { type: "session.idle", data: { sessionID: "chinese-task" } };
          await new Promise((resolve) => {
            if (signal.aborted) resolve();
            else signal.addEventListener("abort", resolve, { once: true });
          });
        })();
      },
    },
    session: {
      async hook(name, callback) {
        handlers.set(name, callback);
        return { async dispose() {} };
      },
      async get() { return { location: { directory: process.cwd() } }; },
      async context() {
        return [
          { id: "user-zh", type: "user", text: ZH },
          { id: "agent-zh", type: "assistant", agent: "orchestrator", content: [
            { type: "tool", name: "write", state: previousFix().state },
            { type: "text", text: "任务已完成。" },
          ] },
        ];
      },
      async synthetic(input) { issued.push(input); return {}; },
    },
  };
  const cleanup = await Guardian.setup(context);
  assert.equal(typeof handlers.get("prompt"), "function");
  assert.equal(typeof handlers.get("context"), "function");
  await handlers.get("prompt")({
    sessionID: "chinese-task", messageID: "user-zh",
    prompt: { text: ZH }, delivery: "queue",
  });
  const output = { sessionID: "chinese-task", system: [], tools: {} };
  await handlers.get("context")(output);
  assert.match(output.system[0].text, /another review pass/);
  for (let i = 0; i < 50 && !releaseEvent; i++) {
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  assert.equal(typeof releaseEvent, "function");
  releaseEvent();
  for (let i = 0; i < 50 && issued.length === 0; i++) {
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  assert.equal(issued.length, 1);
  assert.equal(issued[0].delivery, "queue");
  assert.equal(issued[0].resume, true);
  assert.match(issued[0].text, /another substantive review/);
  await cleanup();
});
