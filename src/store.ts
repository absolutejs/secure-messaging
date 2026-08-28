import type {
  SecureMessagingStore,
  SecureMessagingStoredConversation,
} from "./types";

export type SecureMessagingCommitResolution = "applied" | "conflict" | "retry";

const equalBytes = (left: Uint8Array, right: Uint8Array) => {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1)
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  return difference === 0;
};

const equalConversation = (
  left: SecureMessagingStoredConversation,
  right: SecureMessagingStoredConversation,
) =>
  left.conversationId === right.conversationId &&
  left.revision === right.revision &&
  left.securityMode === right.securityMode &&
  left.status === right.status &&
  equalBytes(left.sealedState, right.sealedState);

export const resolveSecureMessagingStoreCommit = async (
  store: SecureMessagingStore,
  input: {
    readonly conversation: SecureMessagingStoredConversation;
    readonly expectedRevision?: number;
  },
): Promise<SecureMessagingCommitResolution> => {
  const stored = await store.loadConversation(
    input.conversation.conversationId,
  );
  if (stored && equalConversation(stored, input.conversation)) return "applied";
  if (input.expectedRevision === undefined)
    return stored === undefined ? "retry" : "conflict";
  return stored?.revision === input.expectedRevision ? "retry" : "conflict";
};
