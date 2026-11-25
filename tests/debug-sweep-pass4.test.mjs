import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { registerMeshStateRpc } from "../dist/bridge.js";
import { evaluatePreflight } from "../dist/preflight.js";
import { collectTurnEvidence } from "../dist/evidence.js";
import { assessCommandPreflight } from "../dist/secrets/preflight.js";
import { sanitizeObject, sanitizeString } from "../dist/secrets/sanitizer.js";
import { findAllSecretsInCode } from "../dist/rules/no-secrets.js";
import { destructiveOperationsRule } from "../dist/rules/destructive-operations.js";
import { noStubsRule } from "../dist/rules/no-stubs.js";
import { noGhostDepsRule } from "../dist/rules/no-ghost-deps.js";
import { noShortcutsRule } from "../dist/rules/no-shortcuts.js";

function makeBashTurn(command, output = "", exitCode = 0, directory = process.cwd()) {
  const messages = [
    { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Fix the bug" }] },
    {
      info: { id: "a1", role: "assistant" },
      parts: [
        {
          type: "tool",
          tool: "bash",
          state: {
            status: "completed",
            input: { command },
            output,
            exitCode,
            metadata: { exit: exitCode },
          },
        },
        { type: "text", text: "Done." },
      ],
    },
  ];
  const evidence = collectTurnEvidence(messages, directory);
  return {
    sessionID: "ses_p4_bash",
    directory,
    messages,
    currentTurn: messages,
    evidence,
    ruleConfig: { severity: "error" },
  };
}

function makeWriteTurn(filePath, content, directory) {
  const messages = [
    { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Update file" }] },
    {
      info: { id: "a1", role: "assistant" },
      parts: [
        {
          type: "tool",
          tool: "write",
          state: {
            status: "completed",
            input: { filePath, content },
            output: "ok",
          },
        },
        { type: "text", text: "Updated." },
      ],
    },
  ];
  const evidence = collectTurnEvidence(messages, directory);
  return {
    sessionID: "ses_p4_write",
    directory,
    messages,
    currentTurn: messages,
    evidence,
    ruleConfig: { severity: "error" },
  };
}

describe("Debug Sweep Pass-4 — Final Hardening Closure", () => {
  test("L1-1 & L1-2: standby dispose awaits async promoted reg.dispose() and uses shared mesh state", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-p4-rpc-"));
    try {
      let releaseRegB;
      let releaseDisposeB;
      let regBDisposed = false;
      const dA = await registerMeshStateRpc({
        owner: "host-a",
        directory: dir,
        rpcRegister: async () => ({ dispose: async () => {} }),
      });
      const dB = await registerMeshStateRpc({
        owner: "standby-b",
        directory: dir,
        rpcRegister: async () => {
          await new Promise((r) => {
            releaseRegB = r;
          });
          return {
            dispose: async () => {
              await new Promise((r) => {
                releaseDisposeB = r;
              });
              regBDisposed = true;
            },
          };
        },
      });
      const pA = dA();
      await new Promise((r) => setTimeout(r, 10));
      let dBResolved = false;
      const pB = dB().then(() => {
        dBResolved = true;
      });
      await new Promise((r) => setTimeout(r, 10));
      releaseRegB?.();
      await new Promise((r) => setTimeout(r, 15));
      assert.equal(dBResolved, false, "dB() must wait until async promoted reg.dispose() finishes");
      assert.equal(regBDisposed, false);
      releaseDisposeB?.();
      await Promise.all([pA, pB]);
      assert.equal(dBResolved, true);
      assert.equal(regBDisposed, true);
      // Shared WeakMap must exist on global mesh state for cross-bundle interoperability
      const meshState = globalThis[Symbol.for("opencode.mesh.v2")];
      assert.ok(meshState?.rpcStandbyPromotions instanceof WeakMap);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("L1-3..L1-7: env -S trailing args, env combined/signal/-- flags, bash -c post-flags & mixed quotes, sudo -D, inline eval flags", () => {
    const blockedBash = [
      'env -S "git reset" --hard',
      'env -S "rm -r" -f /',
      "env -Srm -rf /",
      "env -iC /tmp rm -rf /",
      "env -iu PATH rm -rf /",
      "env --ignore-signal=PIPE rm -rf /",
      'bash -c -e "rm -rf /"',
      'bash -c -o errexit "rm -rf /"',
      "bash -c 'rm -rf '/",
      "bash -c rm' -rf /'",
      "sudo -D /tmp rm -rf /",
      "sudo -D/tmp rm -rf /",
    ];
    for (const command of blockedBash) {
      assert.notEqual(evaluatePreflight("bash", { command }, [], "strict"), undefined, `must block bash: ${command}`);
    }

    const blockedProc = [
      { executable: "env", args: ["-S", "git reset", "--hard"] },
      { executable: "env", args: ["-Srm", "-rf", "/"] },
      { executable: "env", args: ["-S", "node", "-e", "process.exit(1)"] },
      { executable: "env", args: ["-iC", "/tmp", "bash", "-c", "rm -rf /"] },
      { executable: "env", args: ["-iC", "/tmp", "node", "-e", "process.exit(1)"] },
      { executable: "bash", args: ["-c", "-e", "rm -rf /"] },
      { executable: "bash", args: ["-c", "-o", "errexit", "rm -rf /"] },
      { executable: "sudo", args: ["-D", "/tmp", "rm", "-rf", "/"] },
      { executable: "sudo", args: ["-D", "/tmp", "bash", "-c", "rm -rf /"] },
      { executable: "node", args: ["--eval=process.exit(1)"] },
      { executable: "node", args: ["--print=1+1"] },
      { executable: "python3", args: ['-cimport os; os.system("id")'] },
    ];
    for (const proc of blockedProc) {
      assert.notEqual(evaluatePreflight("process_start", proc, [], "strict"), undefined, `must block proc: ${JSON.stringify(proc)}`);
    }

    assert.equal(assessCommandPreflight("env -- FOO=1").isHighRiskEnvDump, true);
  });

  test("L1-8 & L1-9: multi-statement subshell pipefail exclusion, case-preserved grep -A/-B/-C/-E, and grep -r rejection", () => {
    const out = "Tests: 5 passed, 5 total";
    // Multi-statement subshell pipefail must NOT leak outside subshell
    const subshellLeak = collectTurnEvidence(
      [{ info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: "(true; set -o pipefail); npm test | cat" }, output: "ok", exitCode: 0, metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(subshellLeak.records.find((r) => r.kind === "test")?.status, "unknown");

    // Pipefail INSIDE same subshell IS valid
    const subshellValid = collectTurnEvidence(
      [{ info: { id: "a2", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: "(set -o pipefail; npm test | cat)" }, output: out, exitCode: 0, metadata: { exit: 0 } } }] }],
      process.cwd()
    );
    assert.equal(subshellValid.records.find((r) => r.kind === "test")?.status, "success");

    // Legitimate grep -A/-B/-C/-E -i must pass (no FP)
    for (const cmd of [
      'npm test | grep -A 5 "Tests:"',
      'npm test | grep -B 2 "Tests:"',
      'npm test | grep -C 3 "Tests:"',
      'npm test | grep -E -i "Tests:"',
    ]) {
      const ev = collectTurnEvidence(
        [{ info: { id: "a3", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: cmd }, output: out, exitCode: 0, metadata: { exit: 0 } } }] }],
        process.cwd()
      );
      assert.equal(ev.records.find((r) => r.kind === "test")?.status, "success", `legitimate grep must pass: ${cmd}`);
    }

    // Recursive grep -r reads disk instead of stdin -> must stay unknown
    for (const cmd of ['npm test | grep -r "Tests:"', 'npm test | grep -R "Tests:"', 'npm test | grep -ir "Tests:"']) {
      const ev = collectTurnEvidence(
        [{ info: { id: "a4", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: cmd }, output: out, exitCode: 0, metadata: { exit: 0 } } }] }],
        process.cwd()
      );
      assert.equal(ev.records.find((r) => r.kind === "test")?.status, "unknown", `recursive grep must stay unknown: ${cmd}`);
    }
  });

  test("L2-1 & L2-5: >2 MiB single-line chunking around delimiters/long quotes and optional-chaining secret args", () => {
    const cases = [
      ["x".repeat(1024 * 1024 - 14) + " password: SuperSecretPassword123 " + "y".repeat(1024 * 1024), "SuperSecretPassword123"],
      ["x".repeat(1024 * 1024 - 26) + " Authorization: Bearer secret_bearer_token_987654321 " + "y".repeat(1024 * 1024), "secret_bearer_token_987654321"],
      ["[" + '{"a":1},'.repeat(Math.floor((1024 * 1024 - 15) / 8)) + '{"password": "SuperSecretPassword123"},{"b":"' + "y".repeat(1024 * 1024) + '"}]', "SuperSecretPassword123"],
      ["x".repeat(1024 * 1024 - 2500) + ' token="' + "a".repeat(2490) + ' SECRET_AFTER_2500_CHARS_999"' + "y".repeat(1024 * 1024), "SECRET_AFTER_2500_CHARS_999"],
    ];
    for (const [raw, secret] of cases) {
      const res = sanitizeObject({ buf: Buffer.from(raw, "utf8") });
      const out = res.sanitized.buf.toString("utf8");
      assert.equal(out.includes(secret), false, `>2 MiB single-line chunking leaked ${secret}`);
    }

    // L2-5: optional-chaining with non-identifier literal args MUST redact/flag
    assert.equal(sanitizeString("password: ab?.cd(MySecret2024!)").sanitized.includes("MySecret2024"), false);
    assert.equal(
      sanitizeString('const c = { password: cfg?.fallback("SuperSecretPass123!") };').sanitized.includes("SuperSecretPass123"),
      false
    );
    assert.ok(
      findAllSecretsInCode("x_vault_key: ab?.cd(MySecret2024!)", "cfg.yaml", undefined, { customSensitiveKeys: ["x_vault_key"] }).length > 0
    );
    // Clean optional-chaining code ref still preserved
    assert.equal(sanitizeString("const x = { password: cfg?.getSecret(req.id) };").redactedCount, 0);
  });

  test("L2-2, L2-3, L2-4: git -u/-S guardBypass, chained/escaped heredocs & 2> stderr redir in no-stubs, and ${...} comments in ghost-deps & shortcuts", async () => {
    // L2-2: git -u / -S bypasses must block; -auno must NOT false-positive
    for (const cmd of [
      "git push -u --no-verify origin main",
      'git commit -S --no-verify -m "fix"',
      'git commit -S -n -m "fix"',
      'git commit -u --no-verify -m "fix"',
      'git commit -u -n -m "fix"',
      "git merge -S --no-verify feat",
      'git commit -anSkey -m "fix"',
    ]) {
      assert.equal((await destructiveOperationsRule.inspect(makeBashTurn(cmd))).decision, "block", `must block: ${cmd}`);
    }
    for (const okCmd of ['git commit -auno -m "fix"', 'git commit -aSkeyn -m "fix"']) {
      assert.equal((await destructiveOperationsRule.inspect(makeBashTurn(okCmd))).decision, "pass", `must pass: ${okCmd}`);
    }

    // L2-3: no-stubs chained heredoc, <<\EOF, multi-line quoted printf, and 2> stderr before stdout
    for (const stubCmd of [
      "cat <<'EOF' > src/app.py && true\ndef broken():\n    pass\nEOF",
      "cat <<'EOF' > src/app.ts && true\nexport function broken() {\n}\nEOF",
      "cat <<\\EOF > src/app.py\ndef broken():\n    pass\nEOF",
      "printf '%s\\n' 'def broken():\n    pass' > src/app.py",
      "cat <<'EOF' 2>fixtures/err.log > src/app.ts\nexport function broken() { throw new NotImplementedError(); }\nEOF",
      "cat <<'EOF' 2>/tmp/err.log > src/app.ts\nexport function broken() {}\nEOF",
    ]) {
      assert.equal((await noStubsRule.inspect(makeBashTurn(stubCmd))).decision, "block", `must block stub: ${stubCmd}`);
    }
    assert.equal(
      (await noStubsRule.inspect(makeBashTurn("cat <<\\EOF > tests/helper.ts\nexport function mockCb() {}\nEOF"))).decision,
      "pass"
    );

    // L2-4: // and /* */ comments inside ${...} template interpolation
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-p4-tpl-"));
    try {
      fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({ name: "p4", dependencies: {} }));
      const ghostBypass = 'const s = `${\n  // don\'t break\n  value\n}`;\nimport ghost from "totally-fake-ghost-pkg";\n';
      assert.equal((await noGhostDepsRule.inspect(makeWriteTurn("src/a.ts", ghostBypass, tmpDir))).decision, "block");

      const ghostFp = 'const s = `${\n  // require("not-installed-example")\n  value\n}`;\n';
      assert.equal((await noGhostDepsRule.inspect(makeWriteTurn("src/b.ts", ghostFp, tmpDir))).decision, "pass");

      const shortcutAfterApostrophe = "const s = `${\n  // don't break\n  value\n}`;\n// TODO: finish later\n";
      assert.equal((await noShortcutsRule.inspect(makeWriteTurn("src/c.ts", shortcutAfterApostrophe, tmpDir))).decision, "block");

      const shortcutInsideInterp = "const s = `${\n  // TODO: finish later\n  value\n}`;\n";
      assert.equal((await noShortcutsRule.inspect(makeWriteTurn("src/d.ts", shortcutInsideInterp, tmpDir))).decision, "block");
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
