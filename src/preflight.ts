import { isDestructiveCommand, isOpaqueShellExecution, isSimpleFileRemoval } from "./evidence.js";

export type PreflightFinding = "destructive-command" | "opaque-shell-execution" | "uninspectable-shell-input";

/**
 * Only inspect tools known to execute shell commands. Other tools are handled
 * by OpenCode's own permissions and the existing post-turn Guardian rules.
 */
const SHELL_TOOLS = new Set([
  "bash", "sh", "zsh", "shell", "terminal", "exec", "shell_exec",
  "execute_command", "command", "run_command", "run_shell_command",
  "powershell", "pwsh", "cmd",
]);

export function isShellExecutionTool(
  tool: string,
  additionalTools: readonly string[] = []
): boolean {
  const normalized = tool.toLowerCase();
  const last = normalized.split(/[.:/]/).at(-1) ?? "";
  return SHELL_TOOLS.has(last) || additionalTools.some((entry) => {
    const candidate = entry.trim().toLowerCase();
    return candidate === normalized || candidate === last;
  });
}

export function evaluatePreflight(
  tool: string,
  input: unknown,
  additionalTools: readonly string[] = []
): PreflightFinding | undefined {
  if (!isShellExecutionTool(tool, additionalTools)) return undefined;
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return "uninspectable-shell-input";
  }
  const args = input as Record<string, unknown>;
  const fields = ["command", "cmd", "script"].filter((key) =>
    Object.prototype.hasOwnProperty.call(args, key)
  );
  if (fields.length === 0) return "uninspectable-shell-input";
  const values = fields.map((key) => args[key]);
  if (values.some((value) => typeof value !== "string" || !value.trim())) {
    return "uninspectable-shell-input";
  }
  const commands = values as string[];
  if (commands.some((command) => isDestructiveCommand(command) || isSimpleFileRemoval(command))) return "destructive-command";
  if (commands.some(isOpaqueShellExecution)) return "opaque-shell-execution";
  // Different shell command aliases give no reliable way to know which the
  // host will execute. Do not pick only the first, apparently safe value.
  if (new Set(commands).size > 1) return "uninspectable-shell-input";
  return undefined;
}

export class GuardianPreflightError extends Error {
  readonly reason: PreflightFinding;

  constructor(reason: PreflightFinding) {
    const descriptions: Record<PreflightFinding, string> = {
      "destructive-command": "recognized destructive shell operation",
      "opaque-shell-execution": "decoded content piped into a shell",
      "uninspectable-shell-input": "missing or uninspectable shell command",
    };
    super(`[opencode-guardian preflight] Tool execution rejected: ${descriptions[reason]}. Disable the optional preflight feature only if you understand and accept the risk.`);
    this.name = "GuardianPreflightError";
    this.reason = reason;
  }
}

/**
 * Opt-in strict guard: reject recognized risks before a host executes a tool.
 * This does not parse arbitrary shell syntax or replace OS/host permissions.
 */
export function enforcePreflight(
  tool: string,
  input: unknown,
  additionalTools: readonly string[] = []
): void {
  const finding = evaluatePreflight(tool, input, additionalTools);
  if (finding) throw new GuardianPreflightError(finding);
}
