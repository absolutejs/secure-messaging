import { describe, expect, test } from "bun:test";
import {
  defineE2EEProviderManifest,
  type DeliveryMessage,
  type DeliveryService,
  type LocalDeviceCredential,
  type MessagingProvider,
  type MessagingSession,
} from "@absolutejs/e2ee";
import {
  createSecureMessagingClient,
  type SecureMessagingReplayStore,
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
  let queue: DeliveryMessage[] = [];
  const acknowledgements: string[] = [];
  const claims = new Map<string, string>();
  const sessions = new Map<string, MessagingSession>();
  const delivery: DeliveryService = {
    acknowledge: async ({ cursor }) => {
      acknowledgements.push(cursor);
    },
    receive: async () => ({ cursor: "cursor-1", messages: queue }),
    send: async (messages) => {
      queue = [...queue, ...messages];
    },
  };
  const replayStore: SecureMessagingReplayStore = {
    claim: async ({ conversationId, digest, messageId }) => {
      const key = `${conversationId}:${messageId}`;
      const prior = claims.get(key);
      if (prior === digest) return "duplicate";
      if (prior !== undefined) return "conflict";
      claims.set(key, digest);
      return "accepted";
    },
    release: async ({ conversationId, digest, messageId }) => {
      const key = `${conversationId}:${messageId}`;
      if (claims.get(key) === digest) claims.delete(key);
    },
  };
  const createSession = (conversationId: string): MessagingSession => {
    const session: MessagingSession = {
      conversationId,
      epoch: 0,
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
    replayStore,
  });
  return {
    acknowledgements,
    client,
    getQueue: () => queue,
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
});
