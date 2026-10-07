import { isSensitiveKey } from './patterns.js';

const COMMON_SAFE_VALUES = new Set<string>([
  'development',
  'production',
  'staging',
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  'postgres',
  'mongodb',
  'redis',
  'undefined',
  'true',
  'false',
  'null',
]);

export class RuntimeSecretRegistry {
  private secrets = new Set<string>();

  constructor() {
    this.scanEnv();
  }

  /**
   * Scans an environment object (defaults to process.env) and registers sensitive values.
   */
  public scanEnv(env: Record<string, string | undefined> = process.env): number {
    let added = 0;
    for (const [key, val] of Object.entries(env)) {
      if (!val || typeof val !== 'string') continue;
      if (isSensitiveKey(key)) {
        if (this.addSecret(val)) {
          added++;
        }
      }
    }
    return added;
  }

  /**
   * Registers a single secret value if it satisfies safety constraints.
   */
  public addSecret(val: string): boolean {
    if (!val || typeof val !== 'string') return false;
    const trimmed = val.trim();
    if (trimmed.length < 6) return false;
    if (COMMON_SAFE_VALUES.has(trimmed.toLowerCase())) return false;
    this.secrets.add(trimmed);
    return true;
  }

  /**
   * Returns registered secrets sorted by length descending to prevent partial replacement.
   */
  public getSecrets(): string[] {
    return Array.from(this.secrets).sort((a, b) => b.length - a.length);
  }

  /**
   * Clears all registered secrets (useful in tests).
   */
  public clear(): void {
    this.secrets.clear();
  }

  /**
   * Diagnostic summary: never leaks values or lengths directly.
   */
  public count(): number {
    return this.secrets.size;
  }
}

export const defaultRuntimeSecrets = new RuntimeSecretRegistry();
