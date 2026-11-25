import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { evaluatePreflight } from "../dist/preflight.js";
import { collectTurnEvidence } from "../dist/evidence.js";
import { assessCommandPreflight } from "../dist/secrets/preflight.js";
import { sanitizeObject, sanitizeString } from "../dist/secrets/sanitizer.js";
import { findAllSecretsInCode } from "../dist/rules/no-secrets.js";
import { destructiveOperationsRule } from "../dist/rules/destructive-operations.js";
import { noStubsRule } from "../dist/rules/no-stubs.js";

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
    sessionID: "ses_p5",
    directory,
    messages,
    currentTurn: messages,
    evidence,
    ruleConfig: { severity: "error" },
  };
}

describe("Debug Sweep Pass-5 — Final Zero-Finding Convergence", () => {
  test("L1 P1-1..P1-4 & P2-1..P2-3: env -uSECRET/-S/-C, bash -/-O/-eo, sudo -nD/-nu, python -Wonce FP, perl/node/python flags, evidence subshell/grep/chdir", () => {
    const blockedBash = [
      "env -uSECRET rm -rf /",
      "env -iuSECRET rm -rf /",
      "env -CSrc rm -rf /",
      'env -S "-i rm -rf /"',
      'env -S "-C /tmp rm -rf /"',
      'env -S "-- rm -rf /"',
      'env -S "-i env"',
      'env -S "FOO=1"',
      'bash -c - "rm -rf /"',
      'sh -c - "rm -rf /"',
      'bash -O extglob -c "rm -rf /"',
      'bash -c -O extglob "rm -rf /"',
      'bash -eo pipefail -c "rm -rf /"',
      'bash -c -eo pipefail "rm -rf /"',
      "sudo -nD /tmp rm -rf /",
      "sudo -nu root rm -rf /",
    ];
    for (const command of blockedBash) {
      assert.notEqual(evaluatePreflight("bash", { command }, [], "strict"), undefined, `must block bash: ${command}`);
    }

    const blockedProc = [
      { executable: "env", args: ["-uSECRET", "rm", "-rf", "/"] },
      { executable: "env", args: ["-CSrc", "rm", "-rf", "/"] },
      { executable: "env", args: ["-S", "-i rm -rf /"] },
      { executable: "env", args: ["-S", "-i node -e process.exit(1)"] },
      { executable: "bash", args: ["-c", "-", "rm -rf /"] },
      { executable: "bash", args: ["-c", "-O", "extglob", "rm -rf /"] },
      { executable: "bash", args: ["-c", "-eo", "pipefail", "rm -rf /"] },
      { executable: "sudo", args: ["-nD", "/tmp", "rm", "-rf", "/"] },
      { executable: "node", args: ["--input-type", "module", "-e", "process.exit(1)"] },
      { executable: "perl", args: ['-esystem("id")'] },
      { executable: "python3", args: ["--check-hash-based-pycs", "default", "-c", "import os"] },
    ];
    for (const proc of blockedProc) {
      assert.notEqual(evaluatePreflight("process_start", proc, [], "strict"), undefined, `must block proc: ${JSON.stringify(proc)}`);
    }

    // P2-1 FP checks: python3 -Wonce and -Xtracemalloc must NOT be blocked
    for (const okProc of [
      { executable: "python3", args: ["-Wonce", "app.py"] },
      { executable: "python3", args: ["-Xtracemalloc", "app.py"] },
    ]) {
      assert.equal(evaluatePreflight("process_start", okProc, [], "strict"), undefined, `must allow proc: ${JSON.stringify(okProc)}`);
    }

    // P2-3: env -u<VAR_WITH_UNDERSCORE>
    for (const cmd of ["env -uNODE_ENV", "env -0uNODE_ENV", "env -vuNODE_ENV"]) {
      assert.equal(assessCommandPreflight(cmd).isHighRiskEnvDump, true, `env dump must be detected: ${cmd}`);
    }

    // P1-4 & P2-2 evidence checks
    const out = "Tests: 5 passed, 5 total";
    for (const badCmd of [
      "env -iC /tmp npm test",
      "env -iC/tmp npm test",
      "sudo -D/tmp npm test",
      "{ (set -o pipefail); }; npm test | cat",
      'npm test | grep --directories=recurse "Tests:"',
    ]) {
      const ev = collectTurnEvidence(
        [{ info: { id: "a1", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: badCmd }, output: out, exitCode: 0, metadata: { exit: 0 } } }] }],
        process.cwd()
      );
      assert.equal(ev.records.find((r) => r.kind === "test")?.status, "unknown", `must stay unknown: ${badCmd}`);
    }

    for (const goodCmd of [
      'npm test | grep -iA 5 "Tests:"',
      'npm test | grep -EA 5 "Tests:"',
      'npm test | grep -iC 3 "Tests:"',
      "npm test | grep -eerror",
      "npm test | grep -efail",
    ]) {
      const ev = collectTurnEvidence(
        [{ info: { id: "a2", role: "assistant" }, parts: [{ type: "tool", tool: "bash", state: { status: "completed", input: { command: goodCmd }, output: out, exitCode: 0, metadata: { exit: 0 } } }] }],
        process.cwd()
      );
      assert.equal(ev.records.find((r) => r.kind === "test")?.status, "success", `legitimate grep must pass: ${goodCmd}`);
    }
  });

  test("L2 Findings 1..4: >2MiB space-before-delimiter & apostrophes, heredoc apostrophes/printf/ANSI-C, git rebase/am -m, optional-chaining digit args", async () => {
    // Finding 1: >2 MiB single-line chunking
    const jsonPrefix = "[" + '{"a":1},'.repeat(Math.floor((1024 * 1024 - 14) / 8));
    const chunkCases = [
      [jsonPrefix + '{"password" : "SuperSecretPassword123"},{"b":"' + "y".repeat(1024 * 1024) + '"}]', "SuperSecretPassword123", undefined],
      ["x".repeat(1024 * 1024 - 15) + " database_url = SuperSecretValue123 " + "y".repeat(1024 * 1024), "SuperSecretValue123", undefined],
      ["x".repeat(1024 * 1024 - 14) + " x_vault_val = SuperSecretVault123 " + "y".repeat(1024 * 1024), "SuperSecretVault123", { customSensitiveKeys: ["x_vault_val"] }],
      ["note: don't panic " + "a".repeat(1024 * 1024 + 256 * 1024 - 30) + " password=SuperSecretAfterApostrophe999 " + "b".repeat(1024 * 1024), "SuperSecretAfterApostrophe999", undefined],
      ["note: don't panic " + "a".repeat(1024 * 1024 + 256 * 1024 - 35) + " sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD " + "b".repeat(1024 * 1024), "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD", undefined],
    ];
    for (const [raw, secret, opts] of chunkCases) {
      const res = sanitizeObject({ buf: Buffer.from(raw, "utf8") }, opts);
      assert.equal(res.sanitized.buf.toString("utf8").includes(secret), false, `leaked ${secret}`);
    }

    // Finding 2: no-stubs heredoc apostrophe isolation, quoted <<EOF, printf \n, and ANSI-C $'...'
    const heredocBypass = [
      "cat <<'EOF' > src/types.d.ts",
      "// it's a type definition",
      "export type X = string;",
      "EOF",
      "cat <<'EOF' > src/app.ts",
      "export function broken() { throw new NotImplementedError(); }",
      "EOF",
    ].join("\n");
    assert.equal((await noStubsRule.inspect(makeBashTurn(heredocBypass))).decision, "block");

    const heredocFp = [
      "cat <<'EOF' > src/app.ts",
      "// don't break this",
      "export function ok() { return 1; }",
      "EOF",
      "cat <<'EOF' > tests/helper.ts",
      "export function mockCb() {}",
      "EOF",
    ].join("\n");
    assert.equal((await noStubsRule.inspect(makeBashTurn(heredocFp))).decision, "pass");

    const quotedFakeHeredoc = [
      'echo "use <<EOF for heredocs" > types.d.ts',
      "cat <<'EOF' > src/app.ts",
      "export function broken() { throw new NotImplementedError(); }",
      "EOF",
    ].join("\n");
    assert.equal((await noStubsRule.inspect(makeBashTurn(quotedFakeHeredoc))).decision, "block");

    for (const printfCmd of [
      'printf "def broken():\\n    pass\\n" > src/app.py',
      "printf 'def broken():\\n    pass\\n' > src/app.py",
      "printf $'// don\\'t > fixtures/fake.ts\\nexport function broken() { throw new NotImplementedError(); }' > src/app.ts",
    ]) {
      assert.equal((await noStubsRule.inspect(makeBashTurn(printfCmd))).decision, "block", `must block: ${printfCmd}`);
    }

    // Finding 3: git rebase -m / git am -m must NOT swallow --no-verify
    for (const gitCmd of ["git rebase -m --no-verify main", "git am -m --no-verify patch.mbox"]) {
      assert.equal((await destructiveOperationsRule.inspect(makeBashTurn(gitCmd))).decision, "block", `must block: ${gitCmd}`);
    }

    // Finding 4: optional-chaining call args with digits/overlong tokens must redact/flag
    assert.equal(sanitizeString("password: ab?.cd(mySecret2024)").sanitized.includes("mySecret2024"), false);
    assert.equal(sanitizeString("password: a?.b(deadbeef0123456789abcdef)").sanitized.includes("deadbeef"), false);
    assert.ok(
      findAllSecretsInCode("x_vault_key: ab?.cd(mySecret2024)", "a.yaml", undefined, { customSensitiveKeys: ["x_vault_key"] }).length > 0
    );
  });
});
