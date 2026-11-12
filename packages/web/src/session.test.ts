import * as crypto from "@messager/crypto";
import { IDBFactory } from "fake-indexeddb";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ApiError, type ApiClient } from "./api/client.js";
import type { StoredIdentity } from "./identity.js";
import { describeError, loadSession, signUp } from "./session.js";
import { openDatabase } from "./storage/db.js";
import { loadIdentity } from "./storage/identity-store.js";

const NOW = 1_800_000_000_000;

let db: IDBDatabase;
let registerCalls: { identity: StoredIdentity; inviteCode: string }[];
let registerResult: () => void;
let client: ApiClient;

beforeAll(async () => {
  await crypto.ready;
});

beforeEach(async () => {
  db = await openDatabase(new IDBFactory());
  registerCalls = [];
  registerResult = () => undefined;
  client = {
    request: async () => undefined,
    getPubkeys: async () => {
      throw new Error("not used");
    },
    register: async (identity, inviteCode) => {
      registerCalls.push({ identity, inviteCode });
      registerResult();
    },
  };
});

describe("loadSession", () => {
  it("reports no identity in a fresh browser", async () => {
    expect(await loadSession(db)).toEqual({ status: "none" });
  });
});

describe("signUp", () => {
  it("creates an identity, registers it and remembers that it is registered", async () => {
    const session = await signUp({ db, client, inviteCode: "the-invite-code", now: () => NOW });
    expect(session.status).toBe("registered");
    expect(registerCalls).toHaveLength(1);
    expect(registerCalls[0]!.inviteCode).toBe("the-invite-code");

    const stored = await loadIdentity(db);
    expect(stored!.userId).toBe(registerCalls[0]!.identity.userId);
    expect(stored!.registeredAt).toBe(NOW);

    const reloaded = await loadSession(db);
    expect(reloaded.status).toBe("registered");
    expect(reloaded.status === "registered" && reloaded.identity.userId).toBe(stored!.userId);
  });

  it("stores the keys before contacting the server", async () => {
    let storedAtCallTime: StoredIdentity | null = null;
    client.register = async () => {
      storedAtCallTime = await loadIdentity(db);
    };
    await signUp({ db, client, inviteCode: "code", now: () => NOW });
    expect(storedAtCallTime).not.toBeNull();
  });

  it("keeps the keys when registration is refused, and reports unregistered", async () => {
    registerResult = () => {
      throw new ApiError(403, "invalid_invite");
    };
    const error = await signUp({ db, client, inviteCode: "wrong", now: () => NOW }).catch((e: unknown) => e);
    expect((error as ApiError).code).toBe("invalid_invite");

    const session = await loadSession(db);
    expect(session.status).toBe("unregistered");
    expect((await loadIdentity(db))!.registeredAt).toBeNull();
  });

  it("retries with the same keys instead of making new ones", async () => {
    registerResult = () => {
      throw new ApiError(403, "invalid_invite");
    };
    await signUp({ db, client, inviteCode: "wrong", now: () => NOW }).catch(() => undefined);
    registerResult = () => undefined;
    const session = await signUp({ db, client, inviteCode: "right", now: () => NOW });

    expect(session.status).toBe("registered");
    expect(registerCalls).toHaveLength(2);
    expect(registerCalls[1]!.identity.userId).toBe(registerCalls[0]!.identity.userId);
    expect(registerCalls[1]!.inviteCode).toBe("right");
  });

  it("treats 'already registered' as success, since only this key could have registered this userID", async () => {
    registerResult = () => {
      throw new ApiError(409, "already_registered");
    };
    const session = await signUp({ db, client, inviteCode: "code", now: () => NOW });
    expect(session.status).toBe("registered");
    expect((await loadIdentity(db))!.registeredAt).toBe(NOW);
  });

  it("does not contact the server again once registered", async () => {
    await signUp({ db, client, inviteCode: "code", now: () => NOW });
    const again = await signUp({ db, client, inviteCode: "code", now: () => NOW + 5 });
    expect(again.status).toBe("registered");
    expect(registerCalls).toHaveLength(1);
    expect((await loadIdentity(db))!.registeredAt).toBe(NOW);
  });

  it("keeps the keys when the connection fails", async () => {
    registerResult = () => {
      throw new ApiError(0, "network_error");
    };
    await signUp({ db, client, inviteCode: "code", now: () => NOW }).catch(() => undefined);
    expect((await loadSession(db)).status).toBe("unregistered");
  });

  it("rejects an empty invite code without creating anything", async () => {
    await expect(signUp({ db, client, inviteCode: "   ", now: () => NOW })).rejects.toThrow(/invite code/i);
    expect(await loadSession(db)).toEqual({ status: "none" });
    expect(registerCalls).toHaveLength(0);
  });

  it("trims spaces around a pasted invite code", async () => {
    await signUp({ db, client, inviteCode: "  pasted-code \n", now: () => NOW });
    expect(registerCalls[0]!.inviteCode).toBe("pasted-code");
  });
});

describe("describeError", () => {
  it.each([
    ["invalid_invite", /invite code/i],
    ["network_error", /reach the server/i],
    ["unauthorized", /clock/i],
  ])("explains %s in plain words", (code, pattern) => {
    expect(describeError(new ApiError(400, code))).toMatch(pattern);
  });

  it("gives a general message, including the code, for anything else", () => {
    expect(describeError(new ApiError(500, "internal_error"))).toMatch(/internal_error/);
  });

  it("passes through the message of an ordinary error", () => {
    expect(describeError(new Error("Enter the invite code."))).toBe("Enter the invite code.");
  });

  it("never shows raw non-error values", () => {
    expect(describeError({ secret: "x" })).toBe("Something went wrong.");
  });
});
