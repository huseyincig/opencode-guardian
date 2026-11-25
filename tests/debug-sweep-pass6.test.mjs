import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { evaluatePreflight } from "../dist/preflight.js";
import { collectTurnEvidence } from "../dist/evidence.js";
import { assessCommandPreflight } from "../dist/secrets/preflight.js";
import { sanitizeString } from "../dist/secrets/sanitizer.js";
import { noStubsRule } from "../dist/rules/no-stubs.js";
import { noSecretsRule } from "../dist/rules/no-secrets.js";

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
    sessionID: "ses_p6",
    directory,
    messages,
    currentTurn: messages,
    evidence,
    ruleConfig: { severity: "error" },
  };
}

describe("Debug Sweep Pass-6 & Live opencode.db Replay Closure", () => {
  test("P1-1: case-sensitive sudo -H/-P/-uroot/-Dtmp and flock -e never eat downstream commands or chdir", () => {
    for (const command of [
      "sudo -H rm -rf /",
      'sudo -H bash -c "rm -rf /"',
      "sudo -H git reset --hard",
      "sudo -P rm -rf /",
      "sudo -uroot rm -rf /",
      "sudo -Dtmp rm -rf /",
      "flock -e /tmp/l rm -rf /",
    ]) {
      assert.equal(evaluatePreflight("bash", { command }, [], "strict"), "destructive-command", `must block: ${command}`);
    }
    assert.equal(assessCommandPreflight("sudo -H env -0").isHighRiskEnvDump, true);
    assert.equal(
      evaluatePreflight("process_start", { executable: "sudo", args: ["-uroot", "rm", "-rf", "/"] }, [], "strict"),
      "destructive-command"
    );
    assert.equal(
      evaluatePreflight("process_start", { executable: "sudo", args: ["-uroot", "node", "-e", "process.exit(1)"] }, [], "strict"),
      "uninspectable-shell-input"
    );

    const ev = collectTurnEvidence(
      [
        {
          info: { id: "a1", role: "assistant" },
          parts: [
            {
              type: "tool",
              tool: "bash",
              state: {
                status: "completed",
                input: { command: "sudo -H env -C /tmp npm test" },
                output: "Tests: 5 passed, 5 total",
                exitCode: 0,
                metadata: { exit: 0 },
              },
            },
          ],
        },
      ],
      process.cwd()
    );
    assert.equal(ev.records.find((r) => r.kind === "test")?.status, "unknown");
  });

  test("P1-2 & P2-1: process_start stops at positional shell/PowerShell scripts and avoids interpreter attached-flag FPs", () => {
    for (const proc of [
      { executable: "bash", args: ["evil.sh", "-c", "echo ok"] },
      { executable: "pwsh", args: ["-File", "evil.ps1", "-Command", "echo ok"] },
      { executable: "pwsh", args: ["evil.ps1", "-c", "echo ok"] },
    ]) {
      assert.equal(evaluatePreflight("process_start", proc, [], "strict"), "uninspectable-shell-input", `must block: ${JSON.stringify(proc)}`);
    }

    for (const okProc of [
      { executable: "ruby", args: ["-rfileutils", "script.rb"] },
      { executable: "perl", args: ["-Mfeature", "script.pl"] },
      { executable: "perl", args: ["-Iextra", "script.pl"] },
      { executable: "ruby", args: ["-Ctmp", "script.rb"] },
      { executable: "node", args: ["-Cdevelopment", "app.js"] },
      { executable: "python3", args: ["-mcoverage", "run"] },
    ]) {
      assert.equal(evaluatePreflight("process_start", okProc, [], "strict"), undefined, `must allow: ${JSON.stringify(okProc)}`);
    }
  });

  test("P1-3: no-stubs uses unquoted heredoc detection for printf/echo and handles echo -n -e", async () => {
    for (const cmd of [
      'printf \'const x = "<<EOF";\\ndef broken():\\n    pass\\n\' > src/app.py',
      'printf \'const x = "<<EOF";\\nexport function broken() { throw new NotImplementedError(); }\\n\' > src/app.ts',
      'printf \'const doc = "<<EOF";\nexport function broken() { throw new NotImplementedError(); }\n\' > src/app.ts',
      "echo -n -e 'def broken():\\n    pass' > src/app.py",
    ]) {
      assert.equal((await noStubsRule.inspect(makeBashTurn(cmd))).decision, "block", `must block: ${cmd}`);
    }
  });

  test("Live opencode.db replay fixes: V2 edit appendContent/prependContent & sanitizer RegExp.lastIndex / Markdown inline code", async () => {
    // OpenCode v2.4.1 edit tool appendContent/prependContent must pass preflight when clean and block secrets/stubs
    assert.equal(
      evaluatePreflight("edit", { path: "tests/unit/a.test.mjs", appendContent: "\ntest('ok', () => {});\n" }, [], "strict"),
      undefined
    );
    assert.equal(
      evaluatePreflight("edit", { path: "src/cfg.ts", appendContent: 'export const k = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD";' }, [], "strict"),
      "hardcoded-secret-in-file-write"
    );
    const messages = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Append code" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "edit",
            state: {
              status: "completed",
              input: { path: "src/app.ts", appendContent: "\nexport function broken() { throw new NotImplementedError(); }\n" },
              output: "ok",
            },
          },
          { type: "text", text: "Appended." },
        ],
      },
    ];
    const ev = collectTurnEvidence(messages, process.cwd());
    assert.equal(ev.fileMutations.length, 1);
    assert.equal(
      (await noStubsRule.inspect({ sessionID: "s1", directory: process.cwd(), messages, currentTurn: messages, evidence: ev, ruleConfig: { severity: "error" } })).decision,
      "block"
    );
    const secMsgs = [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "Append secret" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [
          {
            type: "tool",
            tool: "edit",
            state: {
              status: "completed",
              input: { path: "src/app.ts", prependContent: 'const k = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD";\n' },
              output: "ok",
            },
          },
          { type: "text", text: "Done." },
        ],
      },
    ];
    assert.equal(
      (await noSecretsRule.inspect({ sessionID: "s2", directory: process.cwd(), messages: secMsgs, currentTurn: secMsgs, ruleConfig: { severity: "error" } })).decision,
      "block"
    );

    // Real-world sanitizer false-positive fixes from opencode.db replay
    assert.equal(sanitizeString("PEM_PRIVATE_KEY_REGEX.lastIndex = 0;").redactedCount, 0);
    assert.equal(sanitizeString("Standing authorization: `check` and `move` are covered.").redactedCount, 0);
    // Real secrets in backticks or assignments still redact!
    assert.equal(sanitizeString("authorization: `sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD`").sanitized.includes("sk-proj-"), false);
  });
});
