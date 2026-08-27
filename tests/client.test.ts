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
  SECURE_MESSAGING_FRAME_CONTRACT,
  createSecureMessagingClient,
  encodeSecureMessagingWelcomeFrame,
  type SecureMessagingInvitationDisposition,
  type SecureMessagingOutboxEntry,
  type SecureMessagingPolicyInput,
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

const createSurface = (
  invitationDisposition: SecureMessagingInvitationDisposition = "accept",
) => {
  let currentTime = 1_000;
  let commitFailure = false;
  let queue: DeliveryMessage[] = [];
  let deliveryFailure = false;
  const acknowledgements: string[] = [];
  const receipts = new Map<string, string>();
  const policyAuthorizations: Array<{
    input: SecureMessagingPolicyInput;
    processedMessages: number;
  }> = [];
  let processedMessages = 0;
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
    recordInbound: async (receipt) => {
      const key = `${receipt.conversationId}:${receipt.messageId}`;
      const prior = receipts.get(key);
      if (prior === receipt.digest) return "duplicate";
      if (prior !== undefined) return "conflict";
      receipts.set(key, receipt.digest);
      return "recorded";
    },
    removeConversation: async (conversationId, expectedRevision) => {
      if (conversations.get(conversationId)?.revision !== expectedRevision)
        return false;
      conversations.delete(conversationId);
      return true;
    },
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
      process: async (message) => {
        processedMessages += 1;
        return {
          kind: "application",
          message: {
            authenticatedContext: message.authenticatedContext,
            plaintext: message.bytes.slice(1),
            senderCredential: credential.bytes,
          },
        };
      },
      protect: async (plaintext, authenticatedContext) => ({
        authenticatedContext,
        bytes: Uint8Array.from([42, ...plaintext]),
        protocol: "TEST-1.0",
      }),
      removeMembers: async () => ({ epoch: 0, handshake: [], welcomes: [] }),
      replaceMembers: async () => ({ epoch: 0, handshake: [], welcomes: [] }),
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
    joinConversation: async ({ welcome }) =>
      createSession(new TextDecoder().decode(welcome)),
    restoreConversation: async ({ sealedState }) =>
      createSession(new TextDecoder().decode(sealedState)),
    sealConversationState: async (session) =>
      new TextEncoder().encode(session.conversationId),
  };
  const client = createSecureMessagingClient({
    delivery,
    deviceCredential: credential,
    keyPackageDirectory,
    membershipPolicy: {
      authorize: () => true,
      reviewInvitation: () => invitationDisposition,
    },
    now: () => currentTime,
    policy: {
      authorize: (input) => {
        policyAuthorizations.push({ input, processedMessages });
        return true;
      },
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
    policyAuthorizations,
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
    const sent = await surface.client.send({
      conversationId: "conversation-1",
      expectedSecurityEpoch: 0,
      id: "message-1",
      plaintext: new TextEncoder().encode("hello"),
      purpose: "chat.message",
      ttlMs: 500,
    });
    expect(sent.securityEpoch).toBe(0);

    const first = await surface.client.receive();
    expect(first.messages[0]?.kind).toBe("application");
    if (first.messages[0]?.kind === "application")
      expect(
        new TextDecoder().decode(first.messages[0].message.plaintext),
      ).toBe("hello");
    const second = await surface.client.receive(first.cursor);
    expect(second.duplicates).toEqual(["message-1"]);
    expect(surface.acknowledgements).toEqual(["cursor-1", "cursor-1"]);
    expect(surface.policyAuthorizations).toEqual([
      {
        input: expect.objectContaining({
          direction: "outbound",
          purpose: "chat.message",
          securityEpoch: 0,
        }),
        processedMessages: 0,
      },
      {
        input: expect.objectContaining({
          direction: "inbound",
          messageBytes: 5,
          purpose: "chat.message",
          securityEpoch: 0,
        }),
        processedMessages: 1,
      },
    ]);
  });

  test("fails closed when a sensitive send expects another MLS epoch", async () => {
    const surface = createSurface();
    await surface.client.createConversation("conversation-1");
    await expect(
      surface.client.send({
        conversationId: "conversation-1",
        expectedSecurityEpoch: 1,
        id: "epoch-bound-message",
        plaintext: Uint8Array.of(1),
        purpose: "secure-transfer.replacement",
        ttlMs: 500,
      }),
    ).rejects.toThrow("different security epoch");
    expect(surface.getQueue()).toEqual([]);
    expect(surface.pending.size).toBe(0);
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
    ).toEqual({
      delivery: "queued",
      id: "queued-message",
      securityEpoch: 0,
    });
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

  test("durably rejects an unsolicited invitation without activating it", async () => {
    const surface = createSurface("reject");
    const bytes = encodeSecureMessagingWelcomeFrame({
      contract: SECURE_MESSAGING_FRAME_CONTRACT,
      conversationId: "unsolicited",
      createdAt: 1_000,
      expiresAt: 1_500,
      id: "welcome-1",
      kind: "welcome",
      recipientDeviceId: credential.deviceId,
      securityMode: "strict-e2ee",
      welcomeBytes: new TextEncoder().encode("unsolicited"),
    });
    surface.setQueue([
      {
        bytes,
        conversationId: "unsolicited",
        id: "welcome-1",
        kind: "welcome",
        recipientDeviceId: credential.deviceId,
      },
    ]);

    expect((await surface.client.receive()).rejected).toEqual(["welcome-1"]);
    expect((await surface.client.receive()).duplicates).toEqual(["welcome-1"]);
    await expect(
      surface.client.send({
        conversationId: "unsolicited",
        id: "message-1",
        plaintext: Uint8Array.of(1),
        purpose: "chat.message",
        ttlMs: 100,
      }),
    ).rejects.toThrow("not registered");
  });

  test("keeps a pending invitation inert and deletes it on rejection", async () => {
    const surface = createSurface("pending");
    const bytes = encodeSecureMessagingWelcomeFrame({
      contract: SECURE_MESSAGING_FRAME_CONTRACT,
      conversationId: "pending-conversation",
      createdAt: 1_000,
      expiresAt: 1_500,
      id: "welcome-pending",
      kind: "welcome",
      recipientDeviceId: credential.deviceId,
      securityMode: "strict-e2ee",
      welcomeBytes: new TextEncoder().encode("pending-conversation"),
    });
    surface.setQueue([
      {
        bytes,
        conversationId: "pending-conversation",
        id: "welcome-pending",
        kind: "welcome",
        recipientDeviceId: credential.deviceId,
      },
    ]);

    expect((await surface.client.receive()).pendingInvitations).toEqual([
      "pending-conversation",
    ]);
    await expect(
      surface.client.send({
        conversationId: "pending-conversation",
        id: "blocked",
        plaintext: Uint8Array.of(1),
        purpose: "chat.message",
        ttlMs: 100,
      }),
    ).rejects.toThrow("must be accepted");
    await surface.client.rejectInvitation("pending-conversation");
    await expect(
      surface.client.acceptInvitation("pending-conversation"),
    ).rejects.toThrow("not registered");
  });
});
