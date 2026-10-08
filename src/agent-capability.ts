import { isFileMutationTool, isShellExecutionTool } from "./preflight.js";
import type { SessionMessage } from "./types.js";

export type AgentMutationCapability =
  | "read-only"
  | "write-allowed"
  | "write-requires-approval"
  | "unknown";

export interface AgentMutationEvidence {
  agentName?: string | undefined;
  edit?: ("allow" | "deny" | "ask" | "restricted" | "disabled" | "unset") | undefined;
  bash?: ("allow" | "deny" | "ask" | "restricted" | "disabled" | "unset") | undefined;
  mutatingTools?: string[] | undefined;
  unknownTools?: string[] | undefined;
  reasons: string[];
}

export interface AgentMutationProfile {
  capability: AgentMutationCapability;
  evidence: AgentMutationEvidence;
}

export const KNOWN_READ_ONLY_TOOLS = new Set([
  "read_file", "view_file", "cat", "read", "file_read", "read_text_file",
  "glob", "list", "file_list", "dir", "ls", "directory_list", "list_files", "file_search",
  "grep", "search", "code_search", "find",
  "webfetch", "web_fetch", "websearch", "web_search", "read_url_content", "fetch",
  "ask_question", "question", "form", "form_create", "form_get", "form_reply", "form_list",
  "subagent", "task",
  "lsp", "definition", "hover", "references", "document_symbols",
  "status", "git_status", "vcs",
]);

export function isKnownReadOnlyTool(toolName: string): boolean {
  const normalized = toolName.toLowerCase().trim();
  const mcpAction = /^mcp__[a-z0-9_]+__(.+)$/.exec(normalized)?.[1];
  const last = mcpAction ?? normalized.split(/[.:/]/).at(-1) ?? "";
  return KNOWN_READ_ONLY_TOOLS.has(normalized) || KNOWN_READ_ONLY_TOOLS.has(last);
}

export interface V2PermissionRule {
  permission?: string | undefined;
  action?: string | undefined;
  pattern?: string | undefined;
  resource?: string | undefined;
  effect?: string | undefined;
}

export interface NormalizedAgentInput {
  name?: string | undefined;
  tools?: Record<string, boolean> | undefined;
  permission?: unknown;
  permissions?: unknown;
  v1Permission?: {
    edit?: string | undefined;
    bash?: string | Record<string, string> | undefined;
    [key: string]: unknown;
  } | undefined;
  v2Permissions?: V2PermissionRule[] | undefined;
}

function resolveV2ChannelEffect(
  rules: NonNullable<NormalizedAgentInput["v2Permissions"]>,
  targetAction: string
): "allow" | "deny" | "ask" | "restricted" | "unset" {
  let generalEffect: "allow" | "deny" | "ask" | undefined;
  let hasScopedRule = false;
  let scopedOverride = false;

  for (const rule of rules) {
    const rawAction = (rule.permission ?? rule.action ?? "").toLowerCase().trim();
    const rawEffect = (
      rule.action && !rule.permission && !rule.effect
        ? rule.action
        : (rule.effect ?? rule.action ?? "")
    ).toLowerCase().trim();

    if (!["allow", "deny", "ask"].includes(rawEffect)) continue;
    const effect = rawEffect as "allow" | "deny" | "ask";

    const matchesAction =
      rawAction === targetAction ||
      (targetAction === "shell" && rawAction === "bash") ||
      (targetAction === "bash" && rawAction === "shell") ||
      rawAction === "*";
    if (!matchesAction) continue;

    // V2 permission rules are ordered and the LAST matching rule wins.
    // For a generic mutation-capability decision, a '*' resource is the only
    // proof of a channel-wide effect. A later scoped rule that changes that
    // effect means the channel is restricted rather than universally allow/
    // deny/ask. A later '*' rule supersedes all earlier scoped exceptions.
    const resource = (rule.resource ?? rule.pattern ?? "*").trim();
    if (resource === "*") {
      generalEffect = effect;
      scopedOverride = false;
      continue;
    }

    hasScopedRule = true;
    if (generalEffect !== undefined && effect !== generalEffect) {
      scopedOverride = true;
    }
  }

  if (scopedOverride) return "restricted";
  return generalEffect ?? (hasScopedRule ? "restricted" : "unset");
}

function resolveV1BashEffect(
  bash: string | Record<string, string> | undefined
): "allow" | "deny" | "ask" | "restricted" | "unset" {
  if (typeof bash === "string") {
    const norm = bash.toLowerCase().trim();
    return norm === "allow" || norm === "deny" || norm === "ask" ? norm : "unset";
  }

  if (bash && typeof bash === "object" && !Array.isArray(bash)) {
    const wildcard = bash["*"];
    if (typeof wildcard === "string") {
      const effect = wildcard.toLowerCase().trim();
      if (effect === "allow" || effect === "deny" || effect === "ask") {
        return effect;
      }
    }
    if (Object.keys(bash).length > 0) return "restricted";
  }

  return "unset";
}

/**
 * Pure policy evaluation to classify mutation capability.
 */
export function evaluateAgentMutationProfile(
  input: NormalizedAgentInput
): AgentMutationProfile {
  const reasons: string[] = [];
  const tools = input.tools ?? {};

  // Normalize v1 and v2 permissions from aliases if provided
  const v2Permissions: Array<{
    permission?: string | undefined;
    action?: string | undefined;
    pattern?: string | undefined;
    resource?: string | undefined;
    effect?: string | undefined;
  }> | undefined =
    input.v2Permissions ??
    (Array.isArray(input.permissions)
      ? (input.permissions as Array<{
          permission?: string | undefined;
          action?: string | undefined;
          pattern?: string | undefined;
          resource?: string | undefined;
          effect?: string | undefined;
        }>)
      : Array.isArray(input.permission)
      ? (input.permission as Array<{
          permission?: string | undefined;
          action?: string | undefined;
          pattern?: string | undefined;
          resource?: string | undefined;
          effect?: string | undefined;
        }>)
      : undefined);

  const v1Permission: {
    edit?: string | undefined;
    bash?: string | Record<string, string> | undefined;
    [key: string]: unknown;
  } | undefined =
    input.v1Permission ??
    (!Array.isArray(input.permission) && input.permission && typeof input.permission === "object"
      ? (input.permission as {
          edit?: string | undefined;
          bash?: string | Record<string, string> | undefined;
          [key: string]: unknown;
        })
      : !Array.isArray(input.permissions) && input.permissions && typeof input.permissions === "object"
      ? (input.permissions as {
          edit?: string | undefined;
          bash?: string | Record<string, string> | undefined;
          [key: string]: unknown;
        })
      : undefined);

  // 1. Resolve Edit channel
  let editEffect: "allow" | "deny" | "ask" | "restricted" | "disabled" | "unset" = "unset";
  if (tools.edit === false) {
    editEffect = "disabled";
    reasons.push("edit tool explicitly disabled in tools");
  } else if (v2Permissions) {
    editEffect = resolveV2ChannelEffect(v2Permissions, "edit");
    reasons.push(`v2 edit permission: ${editEffect}`);
  } else if (v1Permission?.edit) {
    const norm = String(v1Permission.edit).toLowerCase().trim();
    if (norm === "allow" || norm === "deny" || norm === "ask") {
      editEffect = norm;
    }
    reasons.push(`v1 edit permission: ${editEffect}`);
  }

  // 2. Resolve Shell/Bash channel
  let bashEffect: "allow" | "deny" | "ask" | "restricted" | "disabled" | "unset" = "unset";
  if (tools.bash === false || tools.shell === false) {
    bashEffect = "disabled";
    reasons.push("bash/shell tool explicitly disabled in tools");
  } else if (v2Permissions) {
    bashEffect = resolveV2ChannelEffect(v2Permissions, "shell");
    reasons.push(`v2 shell permission: ${bashEffect}`);
  } else if (v1Permission?.bash !== undefined) {
    bashEffect = resolveV1BashEffect(v1Permission.bash);
    reasons.push(`v1 bash permission: ${bashEffect}`);
  }

  // 3. Inspect other active tools
  const mutatingTools: string[] = [];
  const unknownTools: string[] = [];

  for (const [toolName, enabled] of Object.entries(tools)) {
    if (!enabled) continue;
    if (toolName === "edit" || toolName === "bash" || toolName === "shell") continue;

    if (isFileMutationTool(toolName)) {
      mutatingTools.push(toolName);
    } else if (isShellExecutionTool(toolName)) {
      mutatingTools.push(toolName);
    } else if (!isKnownReadOnlyTool(toolName)) {
      unknownTools.push(toolName);
    }
  }

  // Check if any mutating tool has specific permission in V2
  let mutatingToolAllowed = false;
  let mutatingToolRequiresApproval = false;

  for (const mTool of mutatingTools) {
    if (v2Permissions) {
      const effect = resolveV2ChannelEffect(v2Permissions, mTool);
      if (effect === "allow") mutatingToolAllowed = true;
      else if (effect === "ask") mutatingToolRequiresApproval = true;
      else if (effect === "unset") {
        // Active mutating tool without deny defaults to ask or allow
        mutatingToolRequiresApproval = true;
      }
    } else {
      // In V1, active mutating tool without deny allows mutation
      mutatingToolAllowed = true;
    }
  }

  // 4. Decision logic
  // Priority 1: WRITE-ALLOWED
  if (editEffect === "allow" || bashEffect === "allow" || mutatingToolAllowed) {
    reasons.push("proven mutation channel with allow permission");
    return {
      capability: "write-allowed",
      evidence: {
        agentName: input.name,
        edit: editEffect,
        bash: bashEffect,
        mutatingTools,
        unknownTools,
        reasons,
      },
    };
  }

  // Priority 2: WRITE-REQUIRES-APPROVAL
  if (
    editEffect === "ask" ||
    bashEffect === "ask" ||
    mutatingToolRequiresApproval
  ) {
    reasons.push("mutation channel requires approval (ask)");
    return {
      capability: "write-requires-approval",
      evidence: {
        agentName: input.name,
        edit: editEffect,
        bash: bashEffect,
        mutatingTools,
        unknownTools,
        reasons,
      },
    };
  }

  // Priority 3: READ-ONLY vs UNKNOWN
  const allMutationsDeniedOrDisabled =
    (editEffect === "deny" || editEffect === "disabled") &&
    (bashEffect === "deny" || bashEffect === "disabled") &&
    mutatingTools.length === 0;

  if (allMutationsDeniedOrDisabled) {
    if (unknownTools.length > 0) {
      reasons.push(`mutations denied but unknown tools active: ${unknownTools.join(", ")}`);
      return {
        capability: "unknown",
        evidence: {
          agentName: input.name,
          edit: editEffect,
          bash: bashEffect,
          mutatingTools,
          unknownTools,
          reasons,
        },
      };
    }

    reasons.push("all mutation channels explicitly denied or disabled and no unknown tools");
    return {
      capability: "read-only",
      evidence: {
        agentName: input.name,
        edit: editEffect,
        bash: bashEffect,
        mutatingTools,
        unknownTools,
        reasons,
      },
    };
  }

  // Inconclusive or unset permissions
  reasons.push("inconclusive permissions or missing evidence");
  return {
    capability: "unknown",
    evidence: {
      agentName: input.name,
      edit: editEffect,
      bash: bashEffect,
      mutatingTools,
      unknownTools,
      reasons,
    },
  };
}

export function canSubagentRemediate(profile: AgentMutationProfile): boolean {
  return profile.capability === "write-allowed";
}

export function isWriteCapableAgent(context: {
  isSubagent?: boolean;
  agentCapability?: AgentMutationCapability | undefined;
}): boolean {
  if (context.isSubagent) {
    return context.agentCapability === "write-allowed";
  }
  return context.agentCapability !== "read-only" && context.agentCapability !== "write-requires-approval";
}

// Session-scoped capability and live permission-rule caches.
const sessionCapabilityCache = new Map<string, AgentMutationProfile>();
const sessionV2PermissionCache = new Map<string, V2PermissionRule[]>();

export function getCachedAgentCapability(sessionID: string): AgentMutationProfile | undefined {
  return sessionCapabilityCache.get(sessionID);
}

export function cacheAgentCapability(sessionID: string, profile: AgentMutationProfile): void {
  sessionCapabilityCache.set(sessionID, profile);
}

export function cacheV2SessionPermissions(
  sessionID: string,
  permissions: readonly V2PermissionRule[]
): void {
  sessionV2PermissionCache.set(
    sessionID,
    permissions.map((rule) => ({ ...rule }))
  );
  sessionCapabilityCache.delete(sessionID);
}

export function getCachedV2SessionPermissions(
  sessionID: string
): readonly V2PermissionRule[] | undefined {
  return sessionV2PermissionCache.get(sessionID);
}

export function clearAgentCapability(sessionID: string): void {
  sessionCapabilityCache.delete(sessionID);
  sessionV2PermissionCache.delete(sessionID);
}

export function clearAllAgentCapabilities(): void {
  sessionCapabilityCache.clear();
  sessionV2PermissionCache.clear();
}

/**
 * Resolves capability for a V1 agent via the V1 client.
 */
export async function resolveV1AgentCapability(
  client: {
    app?: {
      agents?: (...args: any[]) => Promise<any>;
    } | undefined;
  },
  directory: string,
  agentName?: string | undefined,
  messageTools?: Record<string, boolean> | undefined
): Promise<AgentMutationProfile> {
  if (!agentName) {
    return {
      capability: "unknown",
      evidence: { reasons: ["no agent name provided"] },
    };
  }

  try {
    if (typeof client.app?.agents === "function") {
      const response = await client.app.agents({ query: { directory } });
      if (Array.isArray(response.data)) {
        const found = response.data.find((a: any) => a.name === agentName);
        if (found) {
          const mergedTools = {
            ...found.tools,
            ...messageTools,
          };
          return evaluateAgentMutationProfile({
            name: found.name,
            v1Permission: found.permission,
            tools: mergedTools,
          });
        }
      }
    }
  } catch {
    return {
      capability: "unknown",
      evidence: {
        agentName,
        reasons: ["client.app.agents query failed"],
      },
    };
  }

  return {
    capability: "unknown",
    evidence: {
      agentName,
      reasons: ["agent not found in V1 agent list"],
    },
  };
}

/**
 * Resolves capability for a V2 agent via the V2 context.
 */
export async function resolveV2AgentCapability(
  context: {
    agent?: {
      list?: (...args: any[]) => Promise<any>;
    } | undefined;
    session?: {
      get?: (...args: any[]) => Promise<any>;
    } | undefined;
  },
  sessionID: string,
  agentName?: string | undefined,
  messageTools?: Record<string, boolean> | undefined,
  directory?: string | undefined
): Promise<AgentMutationProfile> {
  let resolvedAgentName = agentName;
  let resolvedDirectory = directory;
  let sessionPermissions = getCachedV2SessionPermissions(sessionID);

  try {
    if (typeof context.session?.get === "function") {
      const session = await context.session.get({ sessionID });
      if (!resolvedAgentName && typeof session?.agent === "string") {
        resolvedAgentName = session.agent;
      }
      if (
        !resolvedDirectory &&
        typeof session?.location?.directory === "string" &&
        session.location.directory.length > 0
      ) {
        resolvedDirectory = session.location.directory;
      }
      if (Array.isArray(session?.permissions)) {
        sessionPermissions = session.permissions as V2PermissionRule[];
        cacheV2SessionPermissions(sessionID, sessionPermissions);
      }
    }
  } catch {
    // Transient session.get failure is tolerated; a live event/cache or agent
    // catalog lookup can still provide bounded capability evidence.
  }

  if (sessionPermissions && sessionPermissions.length > 0) {
    return evaluateAgentMutationProfile({
      name: resolvedAgentName,
      v2Permissions: [...sessionPermissions],
      tools: messageTools,
    });
  }

  // Query the agent catalog in the active session/worktree location.
  if (resolvedAgentName && typeof context.agent?.list === "function") {
    try {
      const agentList = await context.agent.list(
        resolvedDirectory ? { location: { directory: resolvedDirectory } } : undefined
      );
      if (Array.isArray(agentList.data)) {
        const found = agentList.data.find(
          (a: any) => a?.name === resolvedAgentName || a?.id === resolvedAgentName
        );
        if (found) {
          const mergedTools = {
            ...found.tools,
            ...messageTools,
          };
          return evaluateAgentMutationProfile({
            name: found.name ?? found.id,
            v2Permissions: found.permissions,
            tools: mergedTools,
          });
        }
      }
    } catch {
      return {
        capability: "unknown",
        evidence: {
          agentName: resolvedAgentName,
          reasons: ["context.agent.list query failed"],
        },
      };
    }
  }

  return {
    capability: "unknown",
    evidence: {
      agentName: resolvedAgentName,
      reasons: ["agent permissions not found in session or V2 agent list"],
    },
  };
}

export function extractAgentNameFromMessages(messages: readonly SessionMessage[]): string | undefined {
  const lastWithAgent = messages.findLast(
    (m) => typeof m.info?.agent === "string" && m.info.agent.length > 0
  );
  return lastWithAgent?.info.agent;
}
