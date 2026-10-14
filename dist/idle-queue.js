/** Bounded per-session coalescing for advisory idle notifications. */
export function createIdleQueue(signal, onError) {
    const entries = new Map();
    const forget = (sessionID) => {
        const entry = entries.get(sessionID);
        if (!entry)
            return;
        if (entry.timer)
            clearTimeout(entry.timer);
        entry.controller.abort();
        entries.delete(sessionID);
    };
    const clear = () => { for (const id of entries.keys())
        forget(id); };
    signal.addEventListener("abort", clear, { once: true });
    const arm = (sessionID, entry) => {
        if (entry.timer)
            clearTimeout(entry.timer);
        entry.timer = setTimeout(() => {
            entry.timer = undefined;
            const job = entry.next;
            entry.next = undefined;
            if (!job || signal.aborted || entry.controller.signal.aborted)
                return;
            entry.running = true;
            const jobSignal = AbortSignal.any([signal, entry.controller.signal]);
            void job(jobSignal).catch(() => { if (!jobSignal.aborted)
                onError(); }).finally(() => {
                entry.running = false;
                if (entries.get(sessionID) !== entry)
                    return;
                if (entry.next && !jobSignal.aborted)
                    arm(sessionID, entry);
                else
                    entries.delete(sessionID);
            });
        }, 10);
    };
    return {
        enqueue(sessionID, job) {
            if (signal.aborted)
                return;
            let entry = entries.get(sessionID);
            if (!entry) {
                if (entries.size >= 128) {
                    const oldest = [...entries].find(([, value]) => !value.running);
                    if (!oldest) {
                        onError();
                        return;
                    }
                    forget(oldest[0]);
                    onError();
                }
                entry = { running: false, controller: new AbortController() };
                entries.set(sessionID, entry);
            }
            entry.next = job;
            // Keep the first deadline: a continuous stream must not postpone
            // inspection indefinitely by repeatedly resetting the timer.
            if (!entry.running && !entry.timer)
                arm(sessionID, entry);
        },
        forget,
        clear,
    };
}
