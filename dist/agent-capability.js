import { extractToolAction, isFileMutationTool, isShellExecutionTool } from "./preflight.js";
export const KNOWN_READ_ONLY_TOOLS = new Set([
    "read_file", "view_file", "cat", "read", "file_read", "read_text_file",
    "glob", "list", "file_list", "dir", "ls", "directory_list", "list_files", "file_search",
    "grep", "search", "code_search", "find",
    "webfetch", "web_fetch", "websearch", "web_search", "read_url_content", "fetch",
    "ask_question", "question", "form", "form_create", "form_get", "form_reply", "form_list",
    "subagent", "task",
    "lsp", "definition", "hover", "references", "document_symbols",
    "status", "git_status", "vcs", "diff", "git_diff", "log", "git_log", "show", "git_show",
]);
export function isKnownReadOnlyTool(toolName) {
    const normalized = toolName.toLowerCase().trim();
    const last = extractToolAction(normalized);
    return KNOWN_READ_ONLY_TOOLS.has(normalized) || KNOWN_READ_ONLY_TOOLS.has(last);
}
function resolveV2ChannelEffect(rules, targetAction) {
    let generalEffect;
    let hasScopedRule = false;
    let scopedOverride = false;
    for (const rule of rules) {
        const rawAction = (rule.permission ?? rule.action ?? "").toLowerCase().trim();
        const rawEffect = (rule.action && !rule.permission && !rule.effect
            ? rule.action
            : (rule.effect ?? rule.action ?? "")).toLowerCase().trim();
        if (!["allow", "deny", "ask"].includes(rawEffect))
            continue;
        const effect = rawEffect;
        const matchesAction = rawAction === targetAction ||
            (targetAction === "shell" && rawAction === "bash") ||
            (targetAction === "bash" && rawAction === "shell") ||
            rawAction === "*";
        if (!matchesAction)
            continue;
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
    if (scopedOverride)
        return "restricted";
    return generalEffect ?? (hasScopedRule ? "restricted" : "unset");
}
/**
 * Pure policy evaluation to classify mutation capability.
 */
export function evaluateAgentMutationProfile(input) {
    const reasons = [];
    const tools = input.tools ?? {};
    // Normalize V2 permissions from aliases if provided
    const v2Permissions = input.v2Permissions ??
        (Array.isArray(input.permissions)
            ? input.permissions
            : Array.isArray(input.permission)
                ? input.permission
                : undefined);
    // 1. Resolve Edit channel
    let editEffect = "unset";
    if (tools.edit === false) {
        editEffect = "disabled";
        reasons.push("edit tool explicitly disabled in tools");
    }
    else if (v2Permissions) {
        editEffect = resolveV2ChannelEffect(v2Permissions, "edit");
        reasons.push(`v2 edit permission: ${editEffect}`);
    }
    // 2. Resolve Shell/Bash channel
    let bashEffect = "unset";
    if ((tools.bash === false || tools.shell === false) &&
        tools.bash !== true && tools.shell !== true) {
        bashEffect = "disabled";
        reasons.push("bash/shell tool explicitly disabled in tools");
    }
    else if (v2Permissions) {
        bashEffect = resolveV2ChannelEffect(v2Permissions, "shell");
        reasons.push(`v2 shell permission: ${bashEffect}`);
    }
    // 3. Inspect other active tools
    const mutatingTools = [];
    const unknownTools = [];
    for (const [toolName, enabled] of Object.entries(tools)) {
        if (!enabled)
            continue;
        if (toolName === "edit" || toolName === "bash" || toolName === "shell")
            continue;
        if (isFileMutationTool(toolName)) {
            mutatingTools.push(toolName);
        }
        else if (isShellExecutionTool(toolName)) {
            mutatingTools.push(toolName);
        }
        else if (!isKnownReadOnlyTool(toolName)) {
            unknownTools.push(toolName);
        }
    }
    // Check if any mutating tool has specific permission in V2
    let mutatingToolAllowed = false;
    let mutatingToolRequiresApproval = false;
    for (const mTool of mutatingTools) {
        if (v2Permissions) {
            const effect = resolveV2ChannelEffect(v2Permissions, mTool);
            if (effect === "allow")
                mutatingToolAllowed = true;
            else if (effect === "ask")
                mutatingToolRequiresApproval = true;
            else if (effect === "unset") {
                // Active mutating tool without deny defaults to ask or allow
                mutatingToolRequiresApproval = true;
            }
        }
        else {
            // An enabled tool is availability, not authorization.
            mutatingToolRequiresApproval = true;
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
    if (editEffect === "ask" ||
        bashEffect === "ask" ||
        mutatingToolRequiresApproval) {
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
    const allMutationsDeniedOrDisabled = (editEffect === "deny" || editEffect === "disabled") &&
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
export function canSubagentRemediate(profile) {
    return profile.capability === "write-allowed";
}
export function isWriteCapableAgent(context) {
    if (context.isSubagent) {
        return context.agentCapability === "write-allowed";
    }
    return context.agentCapability !== "read-only" && context.agentCapability !== "write-requires-approval";
}
// Session-scoped capability and live permission-rule caches.
const MAX_CAPABILITY_CACHE_SESSIONS = 512;
const sessionCapabilityCache = new Map();
const sessionV2PermissionCache = new Map();
export function getCachedAgentCapability(sessionID) {
    const profile = sessionCapabilityCache.get(sessionID);
    return profile ? structuredClone(profile) : undefined;
}
export function cacheAgentCapability(sessionID, profile) {
    sessionCapabilityCache.delete(sessionID);
    sessionCapabilityCache.set(sessionID, structuredClone(profile));
    while (sessionCapabilityCache.size > MAX_CAPABILITY_CACHE_SESSIONS) {
        const oldest = sessionCapabilityCache.keys().next().value;
        if (oldest === undefined)
            break;
        sessionCapabilityCache.delete(oldest);
    }
}
export function cacheV2SessionPermissions(sessionID, permissions) {
    sessionV2PermissionCache.delete(sessionID);
    sessionV2PermissionCache.set(sessionID, permissions.map((rule) => ({ ...rule })));
    while (sessionV2PermissionCache.size > MAX_CAPABILITY_CACHE_SESSIONS) {
        const oldest = sessionV2PermissionCache.keys().next().value;
        if (oldest === undefined)
            break;
        sessionV2PermissionCache.delete(oldest);
    }
    sessionCapabilityCache.delete(sessionID);
}
export function getCachedV2SessionPermissions(sessionID) {
    return sessionV2PermissionCache.get(sessionID)?.map((rule) => ({ ...rule }));
}
export function clearAgentCapability(sessionID) {
    sessionCapabilityCache.delete(sessionID);
    sessionV2PermissionCache.delete(sessionID);
}
export function clearAllAgentCapabilities() {
    sessionCapabilityCache.clear();
    sessionV2PermissionCache.clear();
}
/**
 * Resolves capability for a V2 agent via the V2 context.
 */
export async function resolveV2AgentCapability(context, sessionID, agentName, messageTools, directory) {
    let resolvedAgentName = agentName;
    let resolvedDirectory = directory;
    let sessionPermissions = getCachedV2SessionPermissions(sessionID);
    try {
        if (typeof context.session?.get === "function") {
            const session = await context.session.get({ sessionID });
            if (!resolvedAgentName && typeof session?.agent === "string") {
                resolvedAgentName = session.agent;
            }
            if (!resolvedDirectory &&
                typeof session?.location?.directory === "string" &&
                session.location.directory.length > 0) {
                resolvedDirectory = session.location.directory;
            }
            if (Array.isArray(session?.permissions)) {
                sessionPermissions = session.permissions;
                cacheV2SessionPermissions(sessionID, sessionPermissions);
            }
        }
    }
    catch {
        // Transient session.get failure is tolerated; a live event/cache or agent
        // catalog lookup can still provide bounded capability evidence.
    }
    // Query the agent catalog in the active session/worktree location and merge
    // agent base permissions with session-scoped overrides (Permission.merge order).
    let foundAgent;
    if (resolvedAgentName && typeof context.agent?.list === "function") {
        try {
            const agentList = await context.agent.list(resolvedDirectory ? { location: { directory: resolvedDirectory } } : undefined);
            const agents = Array.isArray(agentList)
                ? agentList
                : Array.isArray(agentList?.data)
                    ? agentList.data
                    : undefined;
            if (agents) {
                foundAgent = agents.find((a) => a?.name === resolvedAgentName || a?.id === resolvedAgentName);
            }
        }
        catch {
            if (!sessionPermissions || sessionPermissions.length === 0) {
                return {
                    capability: "unknown",
                    evidence: {
                        agentName: resolvedAgentName,
                        reasons: ["context.agent.list query failed"],
                    },
                };
            }
        }
    }
    const basePermissions = Array.isArray(foundAgent?.permissions)
        ? foundAgent.permissions
        : [];
    const mergedPermissions = [
        ...basePermissions,
        ...(sessionPermissions ?? []),
    ];
    if (foundAgent || mergedPermissions.length > 0) {
        const mergedTools = {
            ...foundAgent?.tools,
            ...messageTools,
        };
        return evaluateAgentMutationProfile({
            name: foundAgent?.name ?? foundAgent?.id ?? resolvedAgentName,
            v2Permissions: mergedPermissions,
            tools: mergedTools,
        });
    }
    return {
        capability: "unknown",
        evidence: {
            agentName: resolvedAgentName,
            reasons: ["agent permissions not found in session or V2 agent list"],
        },
    };
}
export function extractAgentNameFromMessages(messages) {
    const lastWithAgent = messages.findLast((m) => typeof m.info?.agent === "string" && m.info.agent.length > 0);
    return lastWithAgent?.info.agent;
}
