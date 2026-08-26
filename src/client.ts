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
  type SecureMessagingPolicyInput,
  type SecureMessagingReceiveResult,
  type SecureMessagingSendInput,
} from "./types";

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

const requireSession = (
  sessions: ReadonlyMap<string, MessagingSession>,
  conversationId: string,
): MessagingSession => {
  const session = sessions.get(conversationId);
  if (session === undefined)
    throw new SecureMessagingProtocolError(
      `Conversation ${conversationId} is not registered.`,
    );
  return session;
};

export const createSecureMessagingClient = (
  options: SecureMessagingClientOptions,
): SecureMessagingClient => {
  validateOptions(options);
  const sessions = new Map<string, MessagingSession>();
  const now = options.now ?? Date.now;

  const createConversation = async (conversationId: string): Promise<void> => {
    if (sessions.has(conversationId))
      throw new SecureMessagingConfigurationError(
        `Conversation ${conversationId} is already registered.`,
      );
    const session = await options.provider.createConversation({
      conversationId,
      creatorCredential: options.deviceCredential,
      securityMode: options.policy.securityMode,
    });
    if (session.conversationId !== conversationId) {
      await session.close();
      throw new SecureMessagingProtocolError(
        "Provider created state for another conversation.",
      );
    }
    sessions.set(conversationId, session);
  };

  const registerConversation = async (
    conversationId: string,
    sealedState: Uint8Array,
  ): Promise<void> => {
    if (sessions.has(conversationId))
      throw new SecureMessagingConfigurationError(
        `Conversation ${conversationId} is already registered.`,
      );
    const session = await options.provider.restoreConversation({ sealedState });
    if (session.conversationId !== conversationId) {
      await session.close();
      throw new SecureMessagingProtocolError(
        "Restored state belongs to another conversation.",
      );
    }
    sessions.set(conversationId, session);
  };

  const send = async (input: SecureMessagingSendInput): Promise<void> => {
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
    const session = requireSession(sessions, input.conversationId);
    await authorize(options, {
      conversationId: input.conversationId,
      direction: "outbound",
      expiresAt,
      messageBytes: input.plaintext.length,
      messageId: input.id,
      senderDeviceId: options.deviceCredential.deviceId,
    });
    const protectedMessage = await session.protect(input.plaintext, {
      conversationId: input.conversationId,
      expiresAt,
      purpose: input.purpose,
      securityEpoch: session.epoch,
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
    await options.delivery.send([message]);
  };

  const receive = async (
    cursor?: string,
  ): Promise<SecureMessagingReceiveResult> => {
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
      const replay = await options.replayStore.claim({
        conversationId: deliveryMessage.conversationId,
        digest: frameDigest,
        expiresAt: frame.expiresAt,
        messageId: frame.id,
      });
      if (replay === "duplicate") {
        duplicates.push(frame.id);
        continue;
      }
      if (replay === "conflict")
        throw new SecureMessagingProtocolError(
          `Message identifier ${frame.id} was reused with different bytes.`,
        );
      try {
        const result = await requireSession(
          sessions,
          deliveryMessage.conversationId,
        ).process({
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
        if (result !== undefined) messages.push(result);
      } catch (error) {
        await options.replayStore.release({
          conversationId: deliveryMessage.conversationId,
          digest: frameDigest,
          messageId: frame.id,
        });
        throw error;
      }
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
  };

  return Object.freeze({
    closeConversation: async (conversationId) => {
      const session = requireSession(sessions, conversationId);
      await session.close();
      sessions.delete(conversationId);
    },
    createConversation,
    receive,
    registerConversation,
    sealConversation: async (conversationId) =>
      options.provider.sealConversationState(
        requireSession(sessions, conversationId),
      ),
    send,
  });
};
