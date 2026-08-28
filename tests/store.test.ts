import { expect, test } from "bun:test";
import {
  resolveSecureMessagingStoreCommit,
  type SecureMessagingStore,
  type SecureMessagingStoredConversation,
} from "../src";

const conversation = (
  revision: number,
  marker = revision,
): SecureMessagingStoredConversation => ({
  conversationId: "conversation-1",
  revision,
  sealedState: Uint8Array.of(marker),
  securityMode: "strict-e2ee",
  status: "active",
});

const store = (
  stored: SecureMessagingStoredConversation | undefined,
): SecureMessagingStore => ({
  commit: async () => "committed",
  inspectInbound: async () => "new",
  listOutbox: async () => [],
  loadConversation: async () => stored,
  recordInbound: async () => "recorded",
  removeConversation: async () => false,
  removeOutbox: async () => undefined,
});

test("resolves exact applied, retryable, and conflicting commit states", async () => {
  expect(
    await resolveSecureMessagingStoreCommit(store(conversation(2)), {
      conversation: conversation(2),
      expectedRevision: 1,
    }),
  ).toBe("applied");
  expect(
    await resolveSecureMessagingStoreCommit(store(conversation(1)), {
      conversation: conversation(2),
      expectedRevision: 1,
    }),
  ).toBe("retry");
  expect(
    await resolveSecureMessagingStoreCommit(store(conversation(2, 99)), {
      conversation: conversation(2),
      expectedRevision: 1,
    }),
  ).toBe("conflict");
  expect(
    await resolveSecureMessagingStoreCommit(store(undefined), {
      conversation: conversation(1),
    }),
  ).toBe("retry");
});
