import type {
  AuthenticationService,
  DeliveryMessage,
  DeliveryService,
  E2EEKeyPackage,
  KeyPackageDirectory,
} from "@absolutejs/e2ee";
import {
  createMlsMessagingProvider,
  type MlsStateProtection,
} from "@absolutejs/e2ee-mls";
import { expect, test } from "bun:test";
import {
  createSecureMessagingClient,
  type SecureMessagingOutboxEntry,
  type SecureMessagingStore,
  type SecureMessagingStoredConversation,
} from "../src";

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");

const createAuthenticationService = (): AuthenticationService => {
  const bindings = new Map<string, string>();
  let sequence = 0;
  return {
    issueDeviceCredential: async ({ deviceId, identityId, publicKey }) => {
      const bytes = new TextEncoder().encode(`credential-${sequence++}`);
      bindings.set(hex(bytes), hex(publicKey));
      return {
        bytes,
        deviceId,
        expiresAt: Date.now() + 60_000,
        identityId,
        issuedAt: Date.now(),
      };
    },
    sameIdentity: async (left, right) => left.identityId === right.identityId,
    validateDeviceCredential: async ({ credential, publicKey }) => ({
      identityId: credential.identityId,
      status:
        bindings.get(hex(credential.bytes)) === hex(publicKey)
          ? "valid"
          : "invalid",
    }),
  };
};

const createStateProtection = async (): Promise<MlsStateProtection> => {
  const key = await crypto.subtle.generateKey(
    { length: 256, name: "AES-GCM" },
    false,
    ["decrypt", "encrypt"],
  );
  return {
    open: async ({ sealedState }) =>
      new Uint8Array(
        await crypto.subtle.decrypt(
          { iv: sealedState.slice(0, 12), name: "AES-GCM" },
          key,
          sealedState.slice(12),
        ),
      ),
    seal: async ({ state }) => {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
          { iv, name: "AES-GCM" },
          key,
          Uint8Array.from(state),
        ),
      );
      const sealed = new Uint8Array(iv.length + ciphertext.length);
      sealed.set(iv);
      sealed.set(ciphertext, iv.length);
      return sealed;
    },
  };
};

const createStore = () => {
  const conversations = new Map<string, SecureMessagingStoredConversation>();
  const receipts = new Map<string, string>();
  const outbox = new Map<string, SecureMessagingOutboxEntry>();
  const store: SecureMessagingStore = {
    commit: async ({
      conversation,
      expectedRevision,
      inbound,
      outbox: next,
    }) => {
      const prior = conversations.get(conversation.conversationId);
      if (
        (expectedRevision === undefined && prior !== undefined) ||
        (expectedRevision !== undefined && prior?.revision !== expectedRevision)
      )
        return "state-conflict";
      if (inbound !== undefined) {
        const key = `${inbound.conversationId}:${inbound.messageId}`;
        const digest = receipts.get(key);
        if (digest !== undefined && digest !== inbound.digest)
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
      for (const entry of next ?? []) outbox.set(entry.queueId, entry);
      return "committed";
    },
    inspectInbound: async ({ conversationId, digest, messageId }) => {
      const prior = receipts.get(`${conversationId}:${messageId}`);
      return prior === undefined
        ? "new"
        : prior === digest
          ? "duplicate"
          : "conflict";
    },
    listOutbox: async (limit) => [...outbox.values()].slice(0, limit),
    loadConversation: async (conversationId) =>
      conversations.get(conversationId),
    removeOutbox: async (queueIds) => {
      for (const queueId of queueIds) outbox.delete(queueId);
    },
  };
  return { conversations, store };
};

test("orchestrates a durable MLS invitation and bidirectional messaging", async () => {
  const authenticationService = createAuthenticationService();
  const stateProtection = await createStateProtection();
  const providerOptions = {
    authenticationService,
    authorizeMembershipChange: () => true,
    stateProtection,
  };
  const aliceProvider = await createMlsMessagingProvider(providerOptions);
  const bobProvider = await createMlsMessagingProvider(providerOptions);
  const aliceCredential = await aliceProvider.createDeviceCredential({
    deviceId: "alice-phone",
    identityId: "alice",
  });
  const bobCredential = await bobProvider.createDeviceCredential({
    deviceId: "bob-laptop",
    identityId: "bob",
  });
  const keyPackages = new Map<string, E2EEKeyPackage>();
  const keyPackageDirectory: KeyPackageDirectory = {
    claim: async (identityId) => {
      const keyPackage = keyPackages.get(identityId);
      keyPackages.delete(identityId);
      return keyPackage;
    },
    publish: async (keyPackage) => {
      keyPackages.set(keyPackage.credential.identityId, keyPackage);
    },
    remove: async () => undefined,
  };
  const queues = new Map<string, DeliveryMessage[]>();
  const delivery: DeliveryService = {
    acknowledge: async ({ deviceId }) => {
      queues.set(deviceId, []);
    },
    receive: async ({ deviceId }) => ({
      cursor: `cursor-${deviceId}`,
      messages: queues.get(deviceId) ?? [],
    }),
    send: async (messages) => {
      for (const message of messages) {
        if (message.recipientDeviceId === undefined)
          throw new Error("Integration delivery requires an exact recipient.");
        queues.set(message.recipientDeviceId, [
          ...(queues.get(message.recipientDeviceId) ?? []),
          message,
        ]);
      }
    },
  };
  const aliceStore = createStore();
  const bobStore = createStore();
  let id = 0;
  const common = {
    delivery,
    idFactory: () => `membership-${id++}`,
    keyPackageDirectory,
    membershipPolicy: { authorize: () => true },
    policy: {
      authorize: () => true,
      maximumFrameBytes: 1_000_000,
      maximumFutureSkewMs: 300_000,
      maximumMessageBytes: 1_024,
      maximumTtlMs: 60_000,
      securityMode: "strict-e2ee" as const,
    },
  };
  const alice = createSecureMessagingClient({
    ...common,
    deviceCredential: aliceCredential,
    provider: aliceProvider,
    store: aliceStore.store,
  });
  const bob = createSecureMessagingClient({
    ...common,
    deviceCredential: bobCredential,
    provider: bobProvider,
    store: bobStore.store,
  });

  await bob.publishKeyPackage(Date.now() + 30_000);
  await alice.createConversation("conversation-1");
  const invitation = await alice.invite({
    conversationId: "conversation-1",
    identityId: "bob",
    ttlMs: 30_000,
  });
  expect(invitation.delivery).toBe("delivered");
  expect(invitation.epoch).toBe(1);
  expect((await bob.receive()).joined).toEqual(["conversation-1"]);

  await alice.send({
    conversationId: "conversation-1",
    id: "alice-message",
    plaintext: new TextEncoder().encode("hello Bob"),
    purpose: "chat.message",
    recipientDeviceId: "bob-laptop",
    ttlMs: 30_000,
  });
  const receivedByBob = await bob.receive();
  expect(receivedByBob.messages[0]?.kind).toBe("application");
  if (receivedByBob.messages[0]?.kind === "application")
    expect(
      new TextDecoder().decode(receivedByBob.messages[0].message.plaintext),
    ).toBe("hello Bob");

  await bob.closeConversation("conversation-1");
  const restoredBob = createSecureMessagingClient({
    ...common,
    deviceCredential: bobCredential,
    provider: bobProvider,
    store: bobStore.store,
  });
  await restoredBob.loadConversation("conversation-1");
  await restoredBob.send({
    conversationId: "conversation-1",
    id: "bob-message",
    plaintext: new TextEncoder().encode("hello Alice"),
    purpose: "chat.message",
    recipientDeviceId: "alice-phone",
    ttlMs: 30_000,
  });
  const receivedByAlice = await alice.receive();
  expect(receivedByAlice.messages[0]?.kind).toBe("application");
  expect(aliceStore.conversations.get("conversation-1")?.revision).toBe(4);
  expect(bobStore.conversations.get("conversation-1")?.revision).toBe(3);
});
