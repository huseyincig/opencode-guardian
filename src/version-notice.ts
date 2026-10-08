import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { guardianStateDirectory } from "./telemetry.js";

const PACKAGE = "opencode-guardian";
const CACHE_MS = 24 * 60 * 60 * 1000;
const REGISTRY = "https://registry.npmjs.org/opencode-guardian/latest";

export function newerStableVersion(current: string, latest: string): boolean {
  const pattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
  const a = pattern.exec(current);
  const b = pattern.exec(latest);
  if (!a || !b) return false;
  for (let i = 1; i <= 3; i++) {
    const currentText = a[i];
    const latestText = b[i];
    if (currentText === undefined || latestText === undefined) return false;
    const currentPart = BigInt(currentText);
    const latestPart = BigInt(latestText);
    if (latestPart !== currentPart) return latestPart > currentPart;
  }
  return false;
}

export interface UpdateCheckOptions {
  installedVersion?: string;
  cachePath?: string;
  now?: number;
  fetcher?: typeof fetch;
  allowDevelopment?: boolean;
  signal?: AbortSignal;
}

function installedVersion(): string | undefined {
  try {
    const info = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version?: unknown };
    return typeof info.version === "string" ? info.version : undefined;
  } catch { return undefined; }
}

function privateDirectory(dir: string): boolean {
  try {
    const stat = fs.lstatSync(dir);
    return stat.isDirectory() && !stat.isSymbolicLink() &&
      (process.platform === "win32" ||
        ((stat.mode & 0o077) === 0 &&
          (typeof process.getuid !== "function" || stat.uid === process.getuid())));
  } catch { return false; }
}

function readCache(cachePath: string, now: number): string | undefined {
  try {
    if (!privateDirectory(path.dirname(cachePath))) return undefined;
    const file = fs.lstatSync(cachePath);
    if (!file.isFile() || file.isSymbolicLink() ||
        (process.platform !== "win32" && (file.mode & 0o077) !== 0)) return undefined;
    const record = JSON.parse(fs.readFileSync(cachePath, "utf8")) as { checkedAt?: unknown; latest?: unknown };
    return typeof record.checkedAt === "number" && record.checkedAt <= now &&
      now - record.checkedAt < CACHE_MS && typeof record.latest === "string"
      ? record.latest : undefined;
  } catch { return undefined; }
}

function writeCache(cachePath: string, latest: string, now: number): void {
  let fd: number | undefined;
  try {
    const dir = path.dirname(cachePath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (!privateDirectory(dir)) return;
    fd = fs.openSync(cachePath, fs.constants.O_WRONLY | fs.constants.O_CREAT |
      fs.constants.O_TRUNC | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || (typeof process.getuid === "function" && stat.uid !== process.getuid())) return;
    if (process.platform !== "win32") fs.fchmodSync(fd, 0o600);
    fs.writeSync(fd, JSON.stringify({ checkedAt: now, latest }));
  } catch {
    // Cache is best effort, never prevent OpenCode startup.
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/** Network and filesystem failures are intentionally silent and never trigger an install. */
export async function checkGuardianUpdate(options: UpdateCheckOptions = {}): Promise<{ current: string; latest: string } | undefined> {
  if (options.signal?.aborted) return undefined;
  if (!options.allowDevelopment &&
      (process.env.NODE_TEST_CONTEXT || !fileURLToPath(import.meta.url).includes("node_modules"))) return undefined;
  const current = options.installedVersion ?? installedVersion();
  if (!current) return undefined;
  const now = options.now ?? Date.now();
  const cachePath = options.cachePath ?? path.join(guardianStateDirectory(), "update-check.json");
  let latest = readCache(cachePath, now);
  if (!latest) {
    try {
      const timeoutSignal = AbortSignal.timeout(3000);
      const signal = options.signal
        ? AbortSignal.any([options.signal, timeoutSignal])
        : timeoutSignal;
      const response = await (options.fetcher ?? fetch)(REGISTRY, {
        headers: { accept: "application/json" },
        signal,
      });
      if (!response.ok) return undefined;
      const body = await response.json() as { version?: unknown; name?: unknown };
      if (body.name !== PACKAGE || typeof body.version !== "string" ||
          !/^\d+\.\d+\.\d+$/.test(body.version)) return undefined;
      latest = body.version;
      writeCache(cachePath, latest, now);
    } catch { return undefined; }
  }
  if (options.signal?.aborted) return undefined;
  return newerStableVersion(current, latest) ? { current, latest } : undefined;
}

/** Fire-and-forget notification; all host UI errors are isolated from Guardian. */
export async function announceGuardianUpdate(
  show: (current: string, latest: string) => Promise<unknown> | unknown,
  options?: UpdateCheckOptions
): Promise<void> {
  try {
    const update = await checkGuardianUpdate(options);
    if (update && !options?.signal?.aborted) {
      await show(update.current, update.latest);
    }
  } catch { /* Optional notifications must not affect Guardian. */ }
}
