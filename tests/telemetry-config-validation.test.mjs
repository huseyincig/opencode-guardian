import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadConfig, resolveEffectiveConfig, GuardianConfigError, DEFAULT_CONFIG } from "../dist/engine.js";

test("loadConfig accepts valid telemetry configurations", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-cfg-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
    telemetry: {
      enabled: true,
      level: "violations",
      maxBytes: 1048576,
    },
  }));

  const config = loadConfig(dir);
  assert.equal(config.telemetry?.enabled, true);
  assert.equal(config.telemetry?.level, "violations");
  assert.equal(config.telemetry?.maxBytes, 1048576);
});

test("loadConfig rejects invalid telemetry configurations", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-cfg-err-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  // Invalid level
  fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
    telemetry: { level: "invalid-level" },
  }));
  assert.throws(() => loadConfig(dir), GuardianConfigError);

  // Invalid maxBytes (negative)
  fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
    telemetry: { maxBytes: -50 },
  }));
  assert.throws(() => loadConfig(dir), GuardianConfigError);

  // Invalid maxBytes (not a number)
  fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
    telemetry: { maxBytes: "one-megabyte" },
  }));
  assert.throws(() => loadConfig(dir), GuardianConfigError);

  // Invalid enabled (not a boolean)
  fs.writeFileSync(path.join(dir, "opencode-guardian.json"), JSON.stringify({
    telemetry: { enabled: "yes" },
  }));
  assert.throws(() => loadConfig(dir), GuardianConfigError);
});

test("resolveEffectiveConfig merges telemetry configuration", () => {
  const base = {
    ...DEFAULT_CONFIG,
    telemetry: { enabled: true, level: "all", maxBytes: 2097152 },
  };

  const effective = resolveEffectiveConfig(base, {
    telemetry: { level: "violations" },
  });

  assert.equal(effective.telemetry?.enabled, true);
  assert.equal(effective.telemetry?.level, "violations");
  assert.equal(effective.telemetry?.maxBytes, 2097152);
});
