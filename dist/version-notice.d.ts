export declare function newerStableVersion(current: string, latest: string): boolean;
export interface UpdateCheckOptions {
    installedVersion?: string;
    cachePath?: string;
    now?: number;
    fetcher?: typeof fetch;
    allowDevelopment?: boolean;
    signal?: AbortSignal;
}
/** Network and filesystem failures are intentionally silent and never trigger an install. */
export declare function checkGuardianUpdate(options?: UpdateCheckOptions): Promise<{
    current: string;
    latest: string;
} | undefined>;
/** Fire-and-forget notification; all host UI errors are isolated from Guardian. */
export declare function announceGuardianUpdate(show: (current: string, latest: string) => Promise<unknown> | unknown, options?: UpdateCheckOptions): Promise<void>;
