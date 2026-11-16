import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Guardian, { readGuardianStatus } from "../dist/index.js";

function disabledDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-disabled-adapter-"));
  const oldState = process.env.OPENCODE_GUARDIAN_STATE_DIR;
  process.env.OPENCODE_GUARDIAN_STATE_DIR = path.join(directory, "state");
  fs.writeFileSync(path.join(directory, "opencode-guardian.json"),
    JSON.stringify({ enabled: false, preflight: { enabled: true } }));
  t.after(() => {
    if (oldState === undefined) delete process.env.OPENCODE_GUARDIAN_STATE_DIR;
    else process.env.OPENCODE_GUARDIAN_STATE_DIR = oldState;
    fs.rmSync(directory, { recursive: true, force: true });
  });
  return directory;
}

test("disabled V2 plugin does not subscribe or register hooks", async (t) => {
  const directory = disabledDirectory(t);
  const cleanup = await Guardian.setup({ location: { directory },
    event: { subscribe() { assert.fail("disabled plugin must not subscribe"); } },
    session: {
      async context() { assert.fail("disabled plugin must not inspect context"); },
      async synthetic() { assert.fail("disabled plugin must not send remediation"); },
      async hook() { assert.fail("disabled plugin must not install task hooks"); },
    },
    tool: { async hook() { assert.fail("disabled plugin must not install preflight"); } },
  });
  assert.equal(cleanup, undefined);
  assert.equal(readGuardianStatus().preflight, "disabled");
});
