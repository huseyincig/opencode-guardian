import test from "node:test";
import assert from "node:assert/strict";
import {
  GuardEngine,
  parseOpenCodeHandoff,
  sanitizeObject,
  stampMeshMetadata,
  verifyMeshMetadata,
  isTrustedMeshMessage,
  forgetMeshSession,
  normalizeV2Messages,
} from "../dist/index.js";
import { getActiveMeshHandoff, MESH_SYMBOL } from "../dist/bridge.js";

test("Finding 2: sanitizeObject preserves opencode-mesh.token for verifyMeshMetadata", () => {
  const sessionID = "sess-sanitize-mesh-token";
  const metadata = stampMeshMetadata(sessionID, {
    owner: "opencode-guardian",
    kind: "remediation",
    protected: true,
    legacyGuardian: true,
  });

  const { sanitized } = sanitizeObject({ metadata });
  assert.equal(verifyMeshMetadata(sessionID, sanitized.metadata, "remediation", "opencode-guardian"), true);
  assert.equal(isTrustedMeshMessage({ metadata: sanitized.metadata }, sessionID, "remediation"), true);

  // Also verifies fallback to legacy opencode-guardian-provenance if mesh token was altered
  const tamperedMeshToken = {
    ...sanitized.metadata,
    "opencode-mesh": {
      ...(sanitized.metadata["opencode-mesh"]),
      token: "[REDACTED]",
    },
  };
  assert.equal(verifyMeshMetadata(sessionID, tamperedMeshToken, "remediation", "opencode-guardian"), true);
  forgetMeshSession(sessionID);
});

test("Finding 3 & 5: GuardEngine syncs active mesh handoff and ignores trusted mesh messages during question_presented", async () => {
  const engine = new GuardEngine({
    enabled: true,
    strictMode: true,
    remediationBudget: 3,
    rules: {
      "safety/destructive-operations": "error",
    },
  });
  const sessionID = "sess-mesh-handoff-sync";
  const destructiveMessages = [
    { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "clean up old files" }] },
    {
      info: { id: "a1", role: "assistant" },
      parts: [
        { type: "text", text: "Running `rm -rf /` now." },
        {
          type: "tool",
          tool: "bash",
          state: { status: "completed", input: { command: "rm -rf /" }, output: "" },
        },
      ],
    },
  ];

  // 1. Trigger a blocking destructive operation that creates a handoff
  const blockResult = await engine.inspect(sessionID, "/tmp", destructiveMessages);

  assert.equal(blockResult.decision, "block");
  const meshHandoff = getActiveMeshHandoff(sessionID);
  assert.ok(meshHandoff, "setActiveMeshHandoff should be populated on block");
  assert.equal(meshHandoff?.action, "question_required");

  // 2. Rollback should clear the mesh handoff as well
  blockResult.rollback?.();
  assert.equal(getActiveMeshHandoff(sessionID), undefined);

  // 3. Re-inspect to enter handed_off -> question_presented, then verify trusted mesh message doesn't clear it
  const blockAgain = await engine.inspect(sessionID, "/tmp", destructiveMessages);
  assert.equal(blockAgain.decision, "block");
  assert.ok(getActiveMeshHandoff(sessionID));

  const questionAsked = await engine.inspect(
    sessionID,
    "/tmp",
    [
      { info: { id: "u1", role: "user" }, parts: [{ type: "text", text: "clean up old files" }] },
      {
        info: { id: "a1", role: "assistant" },
        parts: [{ type: "tool", tool: "question", state: { status: "completed", input: {}, output: "" } }],
      },
    ]
  );
  assert.equal(questionAsked.decision, "pass");

  const meshMeta = stampMeshMetadata(sessionID, { owner: "opencode-smart-questions", kind: "remediation", synthetic: true });
  const afterMeshMsg = await engine.inspect(
    sessionID,
    "/tmp",
    [
      { info: { id: "u2", role: "user" }, parts: [{ type: "text", text: "remediation", metadata: meshMeta }] },
    ]
  );
  assert.equal(afterMeshMsg.decision, "pass");
  assert.ok(getActiveMeshHandoff(sessionID), "trusted mesh message must not clear question_presented handoff");

  forgetMeshSession(sessionID);
});

test("Finding 5: parseOpenCodeHandoff accepts opencode-hi source and rejects unknown", () => {
  const hiHandoff = parseOpenCodeHandoff(
    "[OPENCODE_HANDOFF:v1]\nsource=opencode-hi\naction=question_required\nkind=choice\nauto_select=allowed\nhandoff_id=hi_123"
  );
  assert.equal(hiHandoff?.source, "opencode-hi");
  assert.equal(hiHandoff?.handoffId, "hi_123");

  const unknownHandoff = parseOpenCodeHandoff(
    "[OPENCODE_HANDOFF:v1]\nsource=unknown\naction=question_required\nkind=choice\nauto_select=allowed\nhandoff_id=123"
  );
  assert.equal(unknownHandoff, null);
});

test("Finding 8: forgetMeshSession releases and removes remoteInteractionLeases for sessionID", () => {
  const sessionID = "sess-remote-lease-cleanup";
  const meshState = globalThis[MESH_SYMBOL];
  assert.ok(meshState);

  let released = false;
  const leaseKey = `/tmp/project::${sessionID}::opencode-smart-questions`;
  meshState.remoteInteractionLeases.set(leaseKey, () => {
    released = true;
  });

  forgetMeshSession(sessionID);
  assert.equal(released, true);
  assert.equal(meshState.remoteInteractionLeases.has(leaseKey), false);
});

test("Finding 10: normalizeV2Messages preserves running status for synthetic shell state=running", () => {
  const normalized = normalizeV2Messages([
    {
      id: "m-running",
      type: "synthetic",
      text: "running npm test",
      metadata: { source: "shell", state: "running", shellID: "sh-1" },
    },
  ]);

  assert.equal(normalized.length, 1);
  assert.equal(normalized[0].parts[0].state.status, "running");
});
