import type { ApiClient } from "./api/client.js";
import type { StoredIdentity } from "./identity.js";
import { withRatchetLock } from "./ratchet-lock.js";
import { loadAccount, saveAccount } from "./storage/ratchet-store.js";

/** One-time keys kept on the server: everything the library hands out in one go. */
export const ONE_TIME_KEY_TARGET = 50;
/** Top up once the server holds fewer than this. */
export const ONE_TIME_KEY_LOW = 25;

/**
 * Makes sure the server holds enough of this user's one-time keys, and a
 * fallback key, so that others can start conversations while they are
 * offline. Returns how many one-time keys were uploaded.
 *
 * The account is saved before the upload, so a key can never be claimed by
 * someone else before its private half is safely stored here. If the upload
 * fails, the keys stay "unpublished" and are sent again next time.
 */
export function topUpOneTimeKeys(params: { db: IDBDatabase; client: ApiClient; me: StoredIdentity }): Promise<number> {
  const { db, client, me } = params;
  return withRatchetLock(async () => {
    const account = await loadAccount(db, me.pickleKey);
    const { count, hasFallback } = await client.countOneTimeKeys(me);

    let keys = account.unpublishedOneTimeKeys();
    if (count < ONE_TIME_KEY_LOW) {
      const wanted = Math.min(ONE_TIME_KEY_TARGET, account.maxOneTimeKeys) - count - keys.length;
      if (wanted > 0) {
        keys = account.generateOneTimeKeys(wanted);
      }
    }
    const fallback = hasFallback ? undefined : account.generateFallbackKey();
    if (keys.length === 0 && fallback === undefined) {
      return 0;
    }

    await saveAccount(db, account, me.pickleKey);
    await client.uploadOneTimeKeys(me, keys, fallback);
    account.markKeysAsPublished();
    await saveAccount(db, account, me.pickleKey);
    return keys.length;
  });
}
