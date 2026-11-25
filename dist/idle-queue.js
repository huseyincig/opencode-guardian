/** Bounded per-session coalescing for advisory idle notifications. */
export function createIdleQueue(signal, onError) {
    const entries = new Map();
    const runDrop = (drop) => {
        if (!drop)
            return;
        try {
            drop();
        }
        catch { }
    };
    const forget = (sessionID) => {
        const entry = entries.get(sessionID);
        if (!entry)
            return;
        if (entry.timer)
            clearTimeout(entry.timer);
        const pendingDrop = entry.nextOnDrop;
        entry.next = undefined;
        entry.nextOnDrop = undefined;
        entry.controller.abort();
        entries.delete(sessionID);
        runDrop(pendingDrop);
    };
    const clear = () => { for (const id of Array.from(entries.keys()))
        forget(id); };
    signal.addEventListener("abort", clear, { once: true });
    const arm = (sessionID, entry) => {
        if (entry.timer)
            clearTimeout(entry.timer);
        entry.timer = setTimeout(() => {
            entry.timer = undefined;
            const job = entry.next;
            const onDrop = entry.nextOnDrop;
            entry.next = undefined;
            entry.nextOnDrop = undefined;
            if (!job || signal.aborted || entry.controller.signal.aborted) {
                runDrop(onDrop);
                return;
            }
            entry.running = true;
            const jobSignal = AbortSignal.any([signal, entry.controller.signal]);
            void job(jobSignal).catch(() => { if (!jobSignal.aborted)
                onError(); }).finally(() => {
                entry.running = false;
                if (entries.get(sessionID) !== entry)
                    return;
                if (entry.next && !jobSignal.aborted)
                    arm(sessionID, entry);
                else {
                    const leftoverDrop = entry.nextOnDrop;
                    entry.next = undefined;
                    entry.nextOnDrop = undefined;
                    entries.delete(sessionID);
                    runDrop(leftoverDrop);
                }
            });
        }, 10);
    };
    return {
        enqueue(sessionID, job, onDrop) {
            if (signal.aborted) {
                runDrop(onDrop);
                return;
            }
            let entry = entries.get(sessionID);
            if (!entry) {
                if (entries.size >= 128) {
                    const oldest = [...entries].find(([, value]) => !value.running);
                    if (!oldest) {
                        runDrop(onDrop);
                        onError();
                        return;
                    }
                    forget(oldest[0]);
                    onError();
                }
                entry = { running: false, controller: new AbortController() };
                entries.set(sessionID, entry);
            }
            if (entry.nextOnDrop) {
                const supersededDrop = entry.nextOnDrop;
                entry.nextOnDrop = undefined;
                runDrop(supersededDrop);
            }
            entry.next = job;
            entry.nextOnDrop = onDrop;
            // Keep the first deadline: a continuous stream must not postpone
            // inspection indefinitely by repeatedly resetting the timer.
            if (!entry.running && !entry.timer)
                arm(sessionID, entry);
        },
        has(sessionID) {
            return entries.has(sessionID);
        },
        forget,
        clear,
    };
}
