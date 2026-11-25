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
  let fd: number | undefined;
  try {
    if (!privateDirectory(path.dirname(cachePath))) return undefined;
    fd = fs.openSync(
      cachePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0)
    );
    const stat = fs.fstatSync(fd);
    if (
      !stat.isFile() ||
      stat.size <= 0 ||
      stat.size > 16 * 1024 ||
      (typeof process.getuid === "function" && stat.uid !== process.getuid()) ||
      (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    ) {
      return undefined;
    }
    const buf = Buffer.alloc(stat.size);
    const bytesRead = fs.readSync(fd, buf, 0, stat.size, 0);
    const record = JSON.parse(buf.toString("utf8", 0, bytesRead)) as { checkedAt?: unknown; latest?: unknown };
    return typeof record.checkedAt === "number" && record.checkedAt <= now &&
      now - record.checkedAt < CACHE_MS && typeof record.latest === "string"
      ? record.latest : undefined;
  } catch { return undefined; }
  finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

function writeCache(cachePath: string, latest: string, now: number): void {
  let fd: number | undefined;
  try {
    const dir = path.dirname(cachePath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (!privateDirectory(dir)) return;
    fd = fs.openSync(cachePath, fs.constants.O_WRONLY | fs.constants.O_CREAT |
      (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0), 0o600);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || (typeof process.getuid === "function" && stat.uid !== process.getuid())) return;
    fs.ftruncateSync(fd, 0);
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
      const MAX_RESPONSE_BYTES = 64 * 1024;
      const contentLength = Number(response.headers?.get?.("content-length") ?? "");
      if (Number.isFinite(contentLength) && contentLength > MAX_RESPONSE_BYTES) return undefined;
      let parsed: { version?: unknown; name?: unknown } | undefined;
      if (response.body && typeof response.body.getReader === "function") {
        const reader = response.body.getReader();
        const chunks: Uint8Array[] = [];
        let total = 0;
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value) {
              total += value.byteLength;
              if (total > MAX_RESPONSE_BYTES) {
                try { await reader.cancel(); } catch {}
                return undefined;
              }
              chunks.push(value);
            }
          }
        } finally {
          try { reader.releaseLock(); } catch {}
        }
        parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { version?: unknown; name?: unknown };
      } else if (typeof response.text === "function") {
        const raw = await response.text();
        if (raw.length > MAX_RESPONSE_BYTES) return undefined;
        parsed = JSON.parse(raw) as { version?: unknown; name?: unknown };
      } else {
        parsed = await response.json() as { version?: unknown; name?: unknown };
      }
      if (!parsed || parsed.name !== PACKAGE || typeof parsed.version !== "string" ||
          !/^\d+\.\d+\.\d+$/.test(parsed.version)) return undefined;
      latest = parsed.version;
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
