import type { DeliveryMessage, MessagingSession } from "@absolutejs/e2ee";
import {
  SecureMessagingConfigurationError,
  SecureMessagingProtocolError,
} from "./errors";
import {
  decodeSecureMessagingFrame,
  encodeSecureMessagingFrame,
} from "./frame";
import {
  SECURE_MESSAGING_FRAME_CONTRACT,
  type SecureMessagingClient,
  type SecureMessagingClientOptions,
  type SecureMessagingFlushResult,
  type SecureMessagingInboundReceipt,
  type SecureMessagingOutboxEntry,
  type SecureMessagingPolicyInput,
  type SecureMessagingReceiveResult,
  type SecureMessagingSendInput,
} from "./types";

type SessionEntry = {
  revision: number;
  readonly session: MessagingSession;
};

const validateOptions = (options: SecureMessagingClientOptions): void => {
  if (
    !Number.isSafeInteger(options.policy.maximumFrameBytes) ||
    options.policy.maximumFrameBytes < 1 ||
    !Number.isSafeInteger(options.policy.maximumFutureSkewMs) ||
    options.policy.maximumFutureSkewMs < 0 ||
    !Number.isSafeInteger(options.policy.maximumMessageBytes) ||
    options.policy.maximumMessageBytes < 1 ||
    !Number.isSafeInteger(options.policy.maximumTtlMs) ||
    options.policy.maximumTtlMs < 1 ||
    !options.provider.manifest.security.supportedModes.includes(
      options.policy.securityMode,
    )
  )
    throw new SecureMessagingConfigurationError(
      "Secure messaging policy is invalid or unsupported by the provider.",
    );
};

const authorize = async (
  options: SecureMessagingClientOptions,
  input: SecureMessagingPolicyInput,
): Promise<void> => {
  if (!(await options.policy.authorize(input)))
    throw new SecureMessagingProtocolError(
      `Secure messaging policy rejected ${input.direction} message ${input.messageId}.`,
    );
};

const digest = async (bytes: Uint8Array): Promise<string> => {
  const input = Uint8Array.from(bytes).buffer;
  const value = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
};

const createConversationLock = () => {
  const tails = new Map<string, Promise<void>>();
  return async <Result>(
    conversationId: string,
    operation: () => Promise<Result>,
  ): Promise<Result> => {
    const prior = tails.get(conversationId) ?? Promise.resolve();
    let release = (): void => undefined;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    tails.set(conversationId, current);
    await prior;
    try {
      return await operation();
    } finally {
      release();
      if (tails.get(conversationId) === current) tails.delete(conversationId);
    }
  };
};

export const createSecureMessagingClient = (
  options: SecureMessagingClientOptions,
): SecureMessagingClient => {
  validateOptions(options);
  const sessions = new Map<string, SessionEntry>();
  const withConversationLock = createConversationLock();
  const now = options.now ?? Date.now;
  let receiving = false;

  const requireEntry = (conversationId: string): SessionEntry => {
    const entry = sessions.get(conversationId);
    if (entry === undefined)
      throw new SecureMessagingProtocolError(
        `Conversation ${conversationId} is not registered.`,
      );
    return entry;
  };

  const discardEntry = async (
    conversationId: string,
    entry: SessionEntry,
  ): Promise<void> => {
    sessions.delete(conversationId);
    await entry.session.close().catch(() => undefined);
  };

  const commitEntry = async (input: {
    readonly entry: SessionEntry;
    readonly expectedRevision?: number;
    readonly inbound?: SecureMessagingInboundReceipt;
    readonly outbox?: readonly SecureMessagingOutboxEntry[];
  }): Promise<void> => {
    const { entry } = input;
    const conversationId = entry.session.conversationId;
    const revision = (input.expectedRevision ?? 0) + 1;
    const sealedState = await options.provider.sealConversationState(
      entry.session,
    );
    const committed = await options.store.commit({
      conversation: {
        conversationId,
        revision,
        sealedState,
        securityMode: options.policy.securityMode,
      },
      ...(input.expectedRevision === undefined
        ? {}
        : { expectedRevision: input.expectedRevision }),
      ...(input.inbound === undefined ? {} : { inbound: input.inbound }),
      ...(input.outbox === undefined ? {} : { outbox: input.outbox }),
    });
    if (committed !== "committed") {
      await discardEntry(conversationId, entry);
      throw new SecureMessagingProtocolError(
        `Atomic conversation commit failed with ${committed}; reload is required.`,
      );
    }
    entry.revision = revision;
  };

  const attachSession = async (input: {
    readonly conversationId: string;
    readonly expectedRevision?: number;
    readonly session: MessagingSession;
  }): Promise<void> => {
    if (input.session.conversationId !== input.conversationId) {
      await input.session.close();
      throw new SecureMessagingProtocolError(
        "Provider state belongs to another conversation.",
      );
    }
    const entry: SessionEntry = {
      revision: input.expectedRevision ?? 0,
      session: input.session,
    };
    sessions.set(input.conversationId, entry);
    if (input.expectedRevision === undefined) await commitEntry({ entry });
  };

  const createConversation = async (conversationId: string): Promise<void> =>
    withConversationLock(conversationId, async () => {
      if (sessions.has(conversationId))
        throw new SecureMessagingConfigurationError(
          `Conversation ${conversationId} is already registered.`,
        );
      await attachSession({
        conversationId,
        session: await options.provider.createConversation({
          conversationId,
          creatorCredential: options.deviceCredential,
          securityMode: options.policy.securityMode,
        }),
      });
    });

  const registerConversation = async (
    conversationId: string,
    sealedState: Uint8Array,
  ): Promise<void> =>
    withConversationLock(conversationId, async () => {
      if (sessions.has(conversationId))
        throw new SecureMessagingConfigurationError(
          `Conversation ${conversationId} is already registered.`,
        );
      await attachSession({
        conversationId,
        session: await options.provider.restoreConversation({ sealedState }),
      });
    });

  const loadConversation = async (conversationId: string): Promise<void> =>
    withConversationLock(conversationId, async () => {
      if (sessions.has(conversationId))
        throw new SecureMessagingConfigurationError(
          `Conversation ${conversationId} is already registered.`,
        );
      const stored = await options.store.loadConversation(conversationId);
      if (stored === undefined)
        throw new SecureMessagingProtocolError(
          `Conversation ${conversationId} has no durable state.`,
        );
      if (stored.securityMode !== options.policy.securityMode)
        throw new SecureMessagingProtocolError(
          "Stored conversation security mode does not match client policy.",
        );
      await attachSession({
        conversationId,
        expectedRevision: stored.revision,
        session: await options.provider.restoreConversation({
          sealedState: stored.sealedState,
        }),
      });
    });

  const flushOutbox = async (
    limit = 100,
  ): Promise<SecureMessagingFlushResult> => {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000)
      throw new SecureMessagingConfigurationError(
        "Outbox flush limit must be between 1 and 1000.",
      );
    const entries = await options.store.listOutbox(limit);
    if (entries.length > 0) {
      await options.delivery.send(entries.map(({ message }) => message));
      await options.store.removeOutbox(entries.map(({ queueId }) => queueId));
    }
    return Object.freeze({
      delivered: Object.freeze(entries.map(({ queueId }) => queueId)),
      hasMore: (await options.store.listOutbox(1)).length > 0,
    });
  };

  const send = async (input: SecureMessagingSendInput) => {
    const outbox = await withConversationLock(
      input.conversationId,
      async (): Promise<SecureMessagingOutboxEntry> => {
        const currentTime = now();
        if (
          input.plaintext.length === 0 ||
          input.plaintext.length > options.policy.maximumMessageBytes ||
          !Number.isSafeInteger(input.ttlMs) ||
          input.ttlMs < 1 ||
          input.ttlMs > options.policy.maximumTtlMs
        )
          throw new SecureMessagingProtocolError(
            "Outbound message size or lifetime violates policy.",
          );
        const expiresAt = currentTime + input.ttlMs;
        if (!Number.isSafeInteger(expiresAt))
          throw new SecureMessagingProtocolError("Outbound expiry is invalid.");
        const entry = requireEntry(input.conversationId);
        await authorize(options, {
          conversationId: input.conversationId,
          direction: "outbound",
          expiresAt,
          messageBytes: input.plaintext.length,
          messageId: input.id,
          senderDeviceId: options.deviceCredential.deviceId,
        });
        const protectedMessage = await entry.session.protect(input.plaintext, {
          conversationId: input.conversationId,
          expiresAt,
          purpose: input.purpose,
          securityEpoch: entry.session.epoch,
          senderId: options.deviceCredential.deviceId,
        });
        const bytes = encodeSecureMessagingFrame({
          authenticatedContext: protectedMessage.authenticatedContext,
          contract: SECURE_MESSAGING_FRAME_CONTRACT,
          createdAt: currentTime,
          expiresAt,
          id: input.id,
          protectedBytes: protectedMessage.bytes,
          protocol: protectedMessage.protocol,
        });
        if (bytes.length > options.policy.maximumFrameBytes)
          throw new SecureMessagingProtocolError(
            "Encoded outbound message exceeds the frame limit.",
          );
        const message: DeliveryMessage = {
          bytes,
          conversationId: input.conversationId,
          id: input.id,
          kind: "application",
          ...(input.recipientDeviceId === undefined
            ? {}
            : { recipientDeviceId: input.recipientDeviceId }),
        };
        const queued = Object.freeze({
          message,
          queueId: `${input.conversationId}:${input.id}`,
        });
        await commitEntry({
          entry,
          expectedRevision: entry.revision,
          outbox: [queued],
        });
        return queued;
      },
    );
    try {
      await options.delivery.send([outbox.message]);
      await options.store.removeOutbox([outbox.queueId]);
      return Object.freeze({ delivery: "delivered" as const, id: input.id });
    } catch {
      return Object.freeze({ delivery: "queued" as const, id: input.id });
    }
  };

  const receive = async (
    cursor?: string,
  ): Promise<SecureMessagingReceiveResult> => {
    if (receiving)
      throw new SecureMessagingConfigurationError(
        "Concurrent receive calls are not supported.",
      );
    receiving = true;
    try {
      const batch = await options.delivery.receive({
        deviceId: options.deviceCredential.deviceId,
        ...(cursor === undefined ? {} : { value: cursor }),
      });
      const duplicates: string[] = [];
      const expired: string[] = [];
      const messages: SecureMessagingReceiveResult["messages"][number][] = [];
      for (const deliveryMessage of batch.messages) {
        if (
          deliveryMessage.kind !== "application" ||
          deliveryMessage.bytes.length > options.policy.maximumFrameBytes ||
          (deliveryMessage.recipientDeviceId !== undefined &&
            deliveryMessage.recipientDeviceId !==
              options.deviceCredential.deviceId)
        )
          throw new SecureMessagingProtocolError(
            `Delivery metadata for message ${deliveryMessage.id} is invalid.`,
          );
        const frame = decodeSecureMessagingFrame(deliveryMessage.bytes);
        if (
          frame.id !== deliveryMessage.id ||
          frame.authenticatedContext.conversationId !==
            deliveryMessage.conversationId
        )
          throw new SecureMessagingProtocolError(
            `Delivery metadata for message ${deliveryMessage.id} does not match its authenticated frame.`,
          );
        const receivedAt = now();
        if (frame.expiresAt <= receivedAt) {
          expired.push(frame.id);
          continue;
        }
        if (frame.expiresAt - frame.createdAt > options.policy.maximumTtlMs)
          throw new SecureMessagingProtocolError(
            `Inbound message ${frame.id} violates policy limits.`,
          );
        if (frame.createdAt - receivedAt > options.policy.maximumFutureSkewMs)
          throw new SecureMessagingProtocolError(
            `Inbound message ${frame.id} was created too far in the future.`,
          );
        await authorize(options, {
          conversationId: deliveryMessage.conversationId,
          direction: "inbound",
          expiresAt: frame.expiresAt,
          messageBytes: frame.protectedBytes.length,
          messageId: frame.id,
          senderDeviceId: frame.authenticatedContext.senderId,
        });
        const frameDigest = await digest(deliveryMessage.bytes);
        await withConversationLock(deliveryMessage.conversationId, async () => {
          const inbound: SecureMessagingInboundReceipt = {
            conversationId: deliveryMessage.conversationId,
            digest: frameDigest,
            expiresAt: frame.expiresAt,
            messageId: frame.id,
          };
          const replay = await options.store.inspectInbound(inbound);
          if (replay === "duplicate") {
            duplicates.push(frame.id);
            return;
          }
          if (replay === "conflict")
            throw new SecureMessagingProtocolError(
              `Message identifier ${frame.id} was reused with different bytes.`,
            );
          const entry = requireEntry(deliveryMessage.conversationId);
          const result = await entry.session.process({
            authenticatedContext: frame.authenticatedContext,
            bytes: frame.protectedBytes,
            protocol: frame.protocol,
          });
          if (
            result?.kind === "application" &&
            result.message.plaintext.length > options.policy.maximumMessageBytes
          )
            throw new SecureMessagingProtocolError(
              `Decrypted message ${frame.id} exceeds the plaintext limit.`,
            );
          await commitEntry({
            entry,
            expectedRevision: entry.revision,
            inbound,
          });
          if (result !== undefined) messages.push(result);
        });
      }
      if (batch.cursor !== undefined)
        await options.delivery.acknowledge({
          cursor: batch.cursor,
          deviceId: options.deviceCredential.deviceId,
        });
      return Object.freeze({
        ...(batch.cursor === undefined ? {} : { cursor: batch.cursor }),
        duplicates: Object.freeze(duplicates),
        expired: Object.freeze(expired),
        messages: Object.freeze(messages),
      });
    } finally {
      receiving = false;
    }
  };

  return Object.freeze({
    closeConversation: async (conversationId) =>
      withConversationLock(conversationId, async () => {
        const entry = requireEntry(conversationId);
        await entry.session.close();
        sessions.delete(conversationId);
      }),
    createConversation,
    flushOutbox,
    loadConversation,
    receive,
    registerConversation,
    sealConversation: async (conversationId) =>
      options.provider.sealConversationState(
        requireEntry(conversationId).session,
      ),
    send,
  });
};
