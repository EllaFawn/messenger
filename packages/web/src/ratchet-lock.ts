const LOCK_NAME = "messager-ratchet";

let tail: Promise<unknown> = Promise.resolve();

/**
 * Runs `task` while holding the one lock that guards the ratchet account and
 * sessions. Each change is read, made in memory and written back; two at
 * once would both start from the same state, and one would overwrite the
 * other. Holding a lock also stops a message being decrypted twice.
 *
 * Uses the Web Locks API, which covers every tab of the site; where that is
 * missing, a queue within this page. Never call it from inside `task`.
 */
export function withRatchetLock<T>(task: () => Promise<T>): Promise<T> {
  const locks = typeof navigator === "undefined" ? undefined : navigator.locks;
  if (locks !== undefined) {
    return locks.request(LOCK_NAME, task) as Promise<T>;
  }
  const run = tail.then(task, task);
  tail = run.catch(() => undefined);
  return run;
}
