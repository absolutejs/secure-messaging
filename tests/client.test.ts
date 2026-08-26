import { describe, expect, test } from "bun:test";
import {
  defineE2EEProviderManifest,
  type DeliveryMessage,
  type DeliveryService,
  type E2EEKeyPackage,
  type KeyPackageDirectory,
  type LocalDeviceCredential,
  type MessagingProvider,
  type MessagingSession,
} from "@absolutejs/e2ee";
import {
  createSecureMessagingClient,
  type SecureMessagingOutboxEntry,
  type SecureMessagingStore,
  type SecureMessagingStoredConversation,
} from "../src";

const credential: LocalDeviceCredential = {
  bytes: Uint8Array.of(1),
  deviceId: "alice-phone",
  identityId: "alice",
  issuedAt: 1,
  keyHandle: "fake-key",
};

const createSurface = () => {
  let currentTime = 1_000;
  let commitFailure = false;
  let queue: DeliveryMessage[] = [];
  let deliveryFailure = false;
  const acknowledgements: string[] = [];
  const receipts = new Map<string, string>();
  const conversations = new Map<string, SecureMessagingStoredConversation>();
  const pending = new Map<string, SecureMessagingOutboxEntry>();
  const sessions = new Map<string, MessagingSession>();
  const keyPackages = new Map<string, E2EEKeyPackage>();
  const delivery: DeliveryService = {
    acknowledge: async ({ cursor }) => {
      acknowledgements.push(cursor);
    },
    receive: async () => ({ cursor: "cursor-1", messages: queue }),
    send: async (messages) => {
      if (deliveryFailure) throw new Error("delivery unavailable");
      queue = [...queue, ...messages];
    },
  };
  const keyPackageDirectory: KeyPackageDirectory = {
    claim: async (identityId) => {
      const entry = keyPackages.get(identityId);
      keyPackages.delete(identityId);
      return entry;
    },
    publish: async (keyPackage) => {
      keyPackages.set(keyPackage.credential.identityId, keyPackage);
    },
    remove: async () => undefined,
  };
  const store: SecureMessagingStore = {
    commit: async ({
      conversation,
      expectedRevision,
      inbound,
      outbox = [],
    }) => {
      if (commitFailure) return "state-conflict";
      const priorConversation = conversations.get(conversation.conversationId);
      if (
        (expectedRevision === undefined && priorConversation !== undefined) ||
        (expectedRevision !== undefined &&
          priorConversation?.revision !== expectedRevision)
      )
        return "state-conflict";
      if (inbound !== undefined) {
        const key = `${inbound.conversationId}:${inbound.messageId}`;
        const prior = receipts.get(key);
        if (prior !== undefined && prior !== inbound.digest)
          return "replay-conflict";
      }
      conversations.set(conversation.conversationId, {
        ...conversation,
        sealedState: conversation.sealedState.slice(),
      });
      if (inbound !== undefined)
        receipts.set(
          `${inbound.conversationId}:${inbound.messageId}`,
          inbound.digest,
        );
      for (const entry of outbox) pending.set(entry.queueId, entry);
      return "committed";
    },
    inspectInbound: async ({ conversationId, digest, messageId }) => {
      const key = `${conversationId}:${messageId}`;
      const prior = receipts.get(key);
      if (prior === digest) return "duplicate";
      if (prior !== undefined) return "conflict";
      return "new";
    },
    listOutbox: async (limit) => [...pending.values()].slice(0, limit),
    loadConversation: async (conversationId) =>
      conversations.get(conversationId),
    removeOutbox: async (queueIds) => {
      for (const queueId of queueIds) pending.delete(queueId);
    },
  };
  const createSession = (conversationId: string): MessagingSession => {
    const session: MessagingSession = {
      conversationId,
      epoch: 0,
      securityMode: "strict-e2ee",
      addMembers: async () => ({ epoch: 0, handshake: [], welcomes: [] }),
      close: async () => undefined,
      members: async () => [{ credential, index: 0 }],
      process: async (message) => ({
        kind: "application",
        message: {
          authenticatedContext: message.authenticatedContext,
          plaintext: message.bytes.slice(1),
          senderCredential: credential.bytes,
        },
      }),
      protect: async (plaintext, authenticatedContext) => ({
        authenticatedContext,
        bytes: Uint8Array.from([42, ...plaintext]),
        protocol: "TEST-1.0",
      }),
      removeMembers: async () => ({ epoch: 0, handshake: [], welcomes: [] }),
      selfUpdate: async () => ({ epoch: 0, handshake: [], welcomes: [] }),
    };
    sessions.set(conversationId, session);
    return session;
  };
  const provider: MessagingProvider = {
    manifest: defineE2EEProviderManifest({
      contract: 1,
      costModel: "free",
      description: "Test-only messaging provider.",
      id: "test.messaging",
      packageName: "@absolutejs/e2ee-test",
      protocols: ["TEST-1.0"],
      roles: ["messaging"],
      runtimes: ["bun"],
      security: {
        assurance: "experimental",
        forwardSecrecy: true,
        operatorCanDecrypt: false,
        postCompromiseSecurity: true,
        postQuantum: false,
        privateKeyProtection: "exportable",
        supportedModes: ["strict-e2ee"],
      },
      version: "0.0.0",
    }),
    createConversation: async ({ conversationId }) =>
      createSession(conversationId),
    createDeviceCredential: async () => credential,
    createKeyPackage: async () => {
      throw new Error("not used");
    },
    joinConversation: async () => {
      throw new Error("not used");
    },
    restoreConversation: async ({ sealedState }) =>
      createSession(new TextDecoder().decode(sealedState)),
    sealConversationState: async (session) =>
      new TextEncoder().encode(session.conversationId),
  };
  const client = createSecureMessagingClient({
    delivery,
    deviceCredential: credential,
    keyPackageDirectory,
    membershipPolicy: { authorize: () => true },
    now: () => currentTime,
    policy: {
      authorize: () => true,
      maximumFrameBytes: 4_096,
      maximumFutureSkewMs: 100,
      maximumMessageBytes: 256,
      maximumTtlMs: 1_000,
      securityMode: "strict-e2ee",
    },
    provider,
    store,
  });
  return {
    acknowledgements,
    client,
    getQueue: () => queue,
    pending,
    setCommitFailure: (value: boolean) => {
      commitFailure = value;
    },
    setDeliveryFailure: (value: boolean) => {
      deliveryFailure = value;
    },
    setNow: (value: number) => {
      currentTime = value;
    },
    setQueue: (value: DeliveryMessage[]) => {
      queue = value;
    },
  };
};

describe("secure messaging client", () => {
  test("sends, authenticates, deduplicates, and acknowledges a batch", async () => {
    const surface = createSurface();
    await surface.client.createConversation("conversation-1");
    await surface.client.send({
      conversationId: "conversation-1",
      id: "message-1",
      plaintext: new TextEncoder().encode("hello"),
      purpose: "chat.message",
      ttlMs: 500,
    });

    const first = await surface.client.receive();
    expect(first.messages[0]?.kind).toBe("application");
    if (first.messages[0]?.kind === "application")
      expect(
        new TextDecoder().decode(first.messages[0].message.plaintext),
      ).toBe("hello");
    const second = await surface.client.receive(first.cursor);
    expect(second.duplicates).toEqual(["message-1"]);
    expect(surface.acknowledgements).toEqual(["cursor-1", "cursor-1"]);
  });

  test("drops expired frames but fails closed on identifier conflicts", async () => {
    const surface = createSurface();
    await surface.client.createConversation("conversation-1");
    await surface.client.send({
      conversationId: "conversation-1",
      id: "expiring",
      plaintext: Uint8Array.of(1),
      purpose: "chat.message",
      ttlMs: 10,
    });
    surface.setNow(1_011);
    expect((await surface.client.receive()).expired).toEqual(["expiring"]);

    surface.setQueue([]);
    surface.setNow(1_100);
    await surface.client.send({
      conversationId: "conversation-1",
      id: "reused",
      plaintext: Uint8Array.of(1),
      purpose: "chat.message",
      ttlMs: 10,
    });
    await surface.client.receive();
    surface.setQueue([]);
    await surface.client.send({
      conversationId: "conversation-1",
      id: "reused",
      plaintext: Uint8Array.of(2),
      purpose: "chat.message",
      ttlMs: 10,
    });
    await expect(surface.client.receive()).rejects.toThrow("reused");
  });

  test("rejects restored state for another conversation", async () => {
    const surface = createSurface();
    await expect(
      surface.client.registerConversation(
        "expected",
        new TextEncoder().encode("different"),
      ),
    ).rejects.toThrow("another conversation");
  });

  test("fails closed on excessive sender clock lead", async () => {
    const surface = createSurface();
    await surface.client.createConversation("conversation-1");
    await surface.client.send({
      conversationId: "conversation-1",
      id: "future-message",
      plaintext: Uint8Array.of(1),
      purpose: "chat.message",
      ttlMs: 500,
    });
    surface.setNow(899);

    await expect(surface.client.receive()).rejects.toThrow("future");
    expect(surface.acknowledgements).toEqual([]);
  });

  test("atomically queues advanced state before retryable delivery", async () => {
    const surface = createSurface();
    await surface.client.createConversation("conversation-1");
    surface.setDeliveryFailure(true);
    expect(
      await surface.client.send({
        conversationId: "conversation-1",
        id: "queued-message",
        plaintext: Uint8Array.of(1),
        purpose: "chat.message",
        ttlMs: 500,
      }),
    ).toEqual({ delivery: "queued", id: "queued-message" });
    expect(surface.pending.size).toBe(1);

    surface.setDeliveryFailure(false);
    expect(await surface.client.flushOutbox()).toEqual({
      delivered: ["conversation-1:queued-message"],
      hasMore: false,
    });
    expect(surface.pending.size).toBe(0);
  });

  test("invalidates mutated in-memory state after a durable conflict", async () => {
    const surface = createSurface();
    await surface.client.createConversation("conversation-1");
    surface.setCommitFailure(true);
    await expect(
      surface.client.send({
        conversationId: "conversation-1",
        id: "conflicted-message",
        plaintext: Uint8Array.of(1),
        purpose: "chat.message",
        ttlMs: 500,
      }),
    ).rejects.toThrow("reload is required");
    surface.setCommitFailure(false);
    await expect(
      surface.client.send({
        conversationId: "conversation-1",
        id: "unsafe-continuation",
        plaintext: Uint8Array.of(2),
        purpose: "chat.message",
        ttlMs: 500,
      }),
    ).rejects.toThrow("not registered");
  });
});
