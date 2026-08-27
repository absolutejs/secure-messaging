import {
  requireMessagingSessionMode,
  validateRecoveryGrant,
  validateRecoveryRequest,
  type DeliveryMessage,
  type MembershipChange,
  type MessagingSession,
} from "@absolutejs/e2ee";
import {
  SecureMessagingConfigurationError,
  SecureMessagingProtocolError,
} from "./errors";
import {
  decodeSecureMessagingFrame,
  decodeSecureMessagingWelcomeFrame,
  encodeSecureMessagingFrame,
  encodeSecureMessagingWelcomeFrame,
} from "./frame";
import {
  SECURE_MESSAGING_FRAME_CONTRACT,
  type SecureMessagingClient,
  type SecureMessagingClientOptions,
  type SecureMessagingFlushResult,
  type SecureMessagingInboundReceipt,
  type SecureMessagingInviteInput,
  type SecureMessagingMembershipDeliveryResult,
  type SecureMessagingOutboxEntry,
  type SecureMessagingPolicyInput,
  type SecureMessagingReceiveResult,
  type SecureMessagingRecoverInput,
  type SecureMessagingRemoveInput,
  type SecureMessagingSendInput,
} from "./types";

type SessionEntry = {
  revision: number;
  readonly session: MessagingSession;
  status: "active" | "pending-invitation";
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

const sameCredential = (
  left: import("@absolutejs/e2ee").DeviceCredential,
  right: import("@absolutejs/e2ee").DeviceCredential,
): boolean =>
  left.deviceId === right.deviceId &&
  left.identityId === right.identityId &&
  left.issuedAt === right.issuedAt &&
  left.expiresAt === right.expiresAt &&
  left.bytes.length === right.bytes.length &&
  left.bytes.every((value, index) => value === right.bytes[index]);

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
  if (
    (options.policy.securityMode === "managed-recovery") !==
    (options.recovery !== undefined)
  )
    throw new SecureMessagingConfigurationError(
      "Managed recovery requires one explicit recovery verifier, and strict E2EE forbids one.",
    );
  const sessions = new Map<string, SessionEntry>();
  const withConversationLock = createConversationLock();
  const now = options.now ?? Date.now;
  const idFactory = options.idFactory ?? crypto.randomUUID;
  let receiving = false;

  const requireEntry = (conversationId: string): SessionEntry => {
    const entry = sessions.get(conversationId);
    if (entry === undefined)
      throw new SecureMessagingProtocolError(
        `Conversation ${conversationId} is not registered.`,
      );
    return entry;
  };

  const requireActiveEntry = (conversationId: string): SessionEntry => {
    const entry = requireEntry(conversationId);
    if (entry.status !== "active")
      throw new SecureMessagingProtocolError(
        `Conversation ${conversationId} has a pending invitation that must be accepted first.`,
      );
    return entry;
  };

  const requireExpiry = (ttlMs: number, label: string) => {
    const currentTime = now();
    if (
      !Number.isSafeInteger(ttlMs) ||
      ttlMs < 1 ||
      ttlMs > options.policy.maximumTtlMs
    )
      throw new SecureMessagingProtocolError(
        `${label} lifetime violates messaging policy.`,
      );
    const expiresAt = currentTime + ttlMs;
    if (!Number.isSafeInteger(expiresAt))
      throw new SecureMessagingProtocolError(`${label} expiry is invalid.`);
    return { currentTime, expiresAt };
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
    try {
      const sealedState = await options.provider.sealConversationState(
        entry.session,
      );
      const committed = await options.store.commit({
        conversation: {
          conversationId,
          revision,
          sealedState,
          securityMode: options.policy.securityMode,
          status: entry.status,
        },
        ...(input.expectedRevision === undefined
          ? {}
          : { expectedRevision: input.expectedRevision }),
        ...(input.inbound === undefined ? {} : { inbound: input.inbound }),
        ...(input.outbox === undefined ? {} : { outbox: input.outbox }),
      });
      if (committed !== "committed")
        throw new SecureMessagingProtocolError(
          `Atomic conversation commit failed with ${committed}; reload is required.`,
        );
      entry.revision = revision;
    } catch (error) {
      await discardEntry(conversationId, entry);
      throw error;
    }
  };

  const attachSession = async (input: {
    readonly conversationId: string;
    readonly expectedRevision?: number;
    readonly inbound?: SecureMessagingInboundReceipt;
    readonly session: MessagingSession;
    readonly status?: SessionEntry["status"];
  }): Promise<void> => {
    try {
      requireMessagingSessionMode(input.session, options.policy.securityMode);
    } catch (error) {
      await input.session.close();
      throw error;
    }
    if (input.session.conversationId !== input.conversationId) {
      await input.session.close();
      throw new SecureMessagingProtocolError(
        "Provider state belongs to another conversation.",
      );
    }
    const entry: SessionEntry = {
      revision: input.expectedRevision ?? 0,
      session: input.session,
      status: input.status ?? "active",
    };
    sessions.set(input.conversationId, entry);
    if (input.expectedRevision === undefined)
      await commitEntry({
        entry,
        ...(input.inbound === undefined ? {} : { inbound: input.inbound }),
      });
  };

  const persistMutation = async <Result>(
    conversationId: string,
    entry: SessionEntry,
    operation: () => Promise<Result>,
  ): Promise<Result> => {
    try {
      return await operation();
    } catch (error) {
      if (sessions.get(conversationId) === entry)
        await discardEntry(conversationId, entry);
      throw error;
    }
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
      if (stored.status !== "active" && stored.status !== "pending-invitation")
        throw new SecureMessagingProtocolError(
          "Stored conversation has an invalid invitation status.",
        );
      await attachSession({
        conversationId,
        expectedRevision: stored.revision,
        session: await options.provider.restoreConversation({
          sealedState: stored.sealedState,
        }),
        status: stored.status,
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

  const deliverEntries = async (
    entries: readonly SecureMessagingOutboxEntry[],
  ): Promise<"delivered" | "queued"> => {
    try {
      await options.delivery.send(entries.map(({ message }) => message));
      await options.store.removeOutbox(entries.map(({ queueId }) => queueId));
      return "delivered";
    } catch {
      return "queued";
    }
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
        const entry = requireActiveEntry(input.conversationId);
        if (
          input.expectedSecurityEpoch !== undefined &&
          (!Number.isSafeInteger(input.expectedSecurityEpoch) ||
            input.expectedSecurityEpoch < 0 ||
            input.expectedSecurityEpoch !== entry.session.epoch)
        )
          throw new SecureMessagingProtocolError(
            "Outbound message expected a different security epoch.",
          );
        await authorize(options, {
          conversationId: input.conversationId,
          direction: "outbound",
          expiresAt,
          messageBytes: input.plaintext.length,
          messageId: input.id,
          senderDeviceId: options.deviceCredential.deviceId,
        });
        return persistMutation(input.conversationId, entry, async () => {
          const protectedMessage = await entry.session.protect(
            input.plaintext,
            {
              conversationId: input.conversationId,
              expiresAt,
              purpose: input.purpose,
              securityEpoch: entry.session.epoch,
              senderId: options.deviceCredential.deviceId,
            },
          );
          const bytes = encodeSecureMessagingFrame({
            authenticatedContext: protectedMessage.authenticatedContext,
            contract: SECURE_MESSAGING_FRAME_CONTRACT,
            createdAt: currentTime,
            expiresAt,
            id: input.id,
            kind: "application",
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
        });
      },
    );
    return Object.freeze({
      delivery: await deliverEntries([outbox]),
      id: input.id,
      securityEpoch:
        outbox.message.kind === "application"
          ? decodeSecureMessagingFrame(outbox.message.bytes)
              .authenticatedContext.securityEpoch
          : 0,
    });
  };

  const publishKeyPackage = async (expiresAt: number): Promise<string> => {
    const currentTime = now();
    if (
      !Number.isSafeInteger(expiresAt) ||
      expiresAt <= currentTime ||
      expiresAt - currentTime > options.policy.maximumTtlMs
    )
      throw new SecureMessagingProtocolError(
        "KeyPackage expiry violates messaging policy.",
      );
    const keyPackage = await options.provider.createKeyPackage({
      credential: options.deviceCredential,
      expiresAt,
    });
    await options.keyPackageDirectory.publish(keyPackage);
    return keyPackage.id;
  };

  const invite = async (
    input: SecureMessagingInviteInput,
  ): Promise<SecureMessagingMembershipDeliveryResult> => {
    const built = await withConversationLock(
      input.conversationId,
      async (): Promise<{
        readonly entries: readonly SecureMessagingOutboxEntry[];
        readonly epoch: number;
      }> => {
        const { currentTime, expiresAt } = requireExpiry(
          input.ttlMs,
          "Invitation",
        );
        const entry = requireActiveEntry(input.conversationId);
        const keyPackage = await options.keyPackageDirectory.claim(
          input.identityId,
        );
        if (keyPackage === undefined)
          throw new SecureMessagingProtocolError(
            `No KeyPackage is available for identity ${input.identityId}.`,
          );
        if (
          keyPackage.credential.identityId !== input.identityId ||
          keyPackage.expiresAt <= currentTime
        )
          throw new SecureMessagingProtocolError(
            "Claimed KeyPackage identity or expiry is invalid.",
          );
        const priorMembers = await entry.session.members();
        if (
          !(await options.membershipPolicy.authorize({
            action: "invite",
            conversationId: input.conversationId,
            members: priorMembers.map(({ credential }) => credential),
            target: keyPackage.credential,
          }))
        )
          throw new SecureMessagingProtocolError(
            `Membership policy rejected invitation for ${input.identityId}.`,
          );
        return persistMutation(input.conversationId, entry, async () => {
          const membership = await entry.session.addMembers([keyPackage]);
          const entries: SecureMessagingOutboxEntry[] = [];
          for (const welcome of membership.welcomes) {
            const id = idFactory();
            const message: DeliveryMessage = {
              bytes: encodeSecureMessagingWelcomeFrame({
                contract: SECURE_MESSAGING_FRAME_CONTRACT,
                conversationId: input.conversationId,
                createdAt: currentTime,
                expiresAt,
                id,
                kind: "welcome",
                recipientDeviceId: welcome.deviceId,
                securityMode: options.policy.securityMode,
                welcomeBytes: welcome.bytes,
              }),
              conversationId: input.conversationId,
              id,
              kind: "welcome",
              recipientDeviceId: welcome.deviceId,
            };
            entries.push({
              message,
              queueId: `${input.conversationId}:${id}`,
            });
          }
          for (const handshake of membership.handshake) {
            for (const member of priorMembers) {
              if (
                member.credential.deviceId === options.deviceCredential.deviceId
              )
                continue;
              const id = idFactory();
              const message: DeliveryMessage = {
                bytes: encodeSecureMessagingFrame({
                  authenticatedContext: handshake.authenticatedContext,
                  contract: SECURE_MESSAGING_FRAME_CONTRACT,
                  createdAt: currentTime,
                  expiresAt,
                  id,
                  kind: "commit",
                  protectedBytes: handshake.bytes,
                  protocol: handshake.protocol,
                }),
                conversationId: input.conversationId,
                id,
                kind: "commit",
                recipientDeviceId: member.credential.deviceId,
              };
              entries.push({
                message,
                queueId: `${input.conversationId}:${id}`,
              });
            }
          }
          if (entries.length === 0)
            throw new SecureMessagingProtocolError(
              "Provider did not produce membership delivery messages.",
            );
          if (
            entries.some(
              ({ message }) =>
                message.bytes.length > options.policy.maximumFrameBytes,
            )
          )
            throw new SecureMessagingProtocolError(
              "Encoded membership frame exceeds the frame limit.",
            );
          await commitEntry({
            entry,
            expectedRevision: entry.revision,
            outbox: entries,
          });
          return Object.freeze({
            entries: Object.freeze(entries),
            epoch: membership.epoch,
          });
        });
      },
    );
    return Object.freeze({
      delivery: await deliverEntries(built.entries),
      epoch: built.epoch,
      messageIds: Object.freeze(built.entries.map(({ message }) => message.id)),
    });
  };

  const buildHandshakeEntries = (input: {
    readonly conversationId: string;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly membership: MembershipChange;
    readonly recipientDeviceIds: readonly string[];
  }): readonly SecureMessagingOutboxEntry[] => {
    if (input.membership.welcomes.length !== 0)
      throw new SecureMessagingProtocolError(
        "Provider unexpectedly produced Welcome messages for this membership change.",
      );
    const entries: SecureMessagingOutboxEntry[] = [];
    for (const handshake of input.membership.handshake) {
      for (const recipientDeviceId of input.recipientDeviceIds) {
        const id = idFactory();
        const message: DeliveryMessage = {
          bytes: encodeSecureMessagingFrame({
            authenticatedContext: handshake.authenticatedContext,
            contract: SECURE_MESSAGING_FRAME_CONTRACT,
            createdAt: input.createdAt,
            expiresAt: input.expiresAt,
            id,
            kind: "commit",
            protectedBytes: handshake.bytes,
            protocol: handshake.protocol,
          }),
          conversationId: input.conversationId,
          id,
          kind: "commit",
          recipientDeviceId,
        };
        entries.push({
          message,
          queueId: `${input.conversationId}:${id}`,
        });
      }
    }
    if (
      entries.some(
        ({ message }) =>
          message.bytes.length > options.policy.maximumFrameBytes,
      )
    )
      throw new SecureMessagingProtocolError(
        "Encoded membership frame exceeds the frame limit.",
      );
    return Object.freeze(entries);
  };

  const persistMembershipChange = async (input: {
    readonly conversationId: string;
    readonly createdAt: number;
    readonly entry: SessionEntry;
    readonly expiresAt: number;
    readonly membership: MembershipChange;
    readonly recipientDeviceIds: readonly string[];
  }): Promise<{
    readonly entries: readonly SecureMessagingOutboxEntry[];
    readonly epoch: number;
  }> => {
    const entries = buildHandshakeEntries(input);
    await commitEntry({
      entry: input.entry,
      expectedRevision: input.entry.revision,
      ...(entries.length === 0 ? {} : { outbox: entries }),
    });
    return Object.freeze({ entries, epoch: input.membership.epoch });
  };

  const removeMembers = async (
    input: SecureMessagingRemoveInput,
  ): Promise<SecureMessagingMembershipDeliveryResult> => {
    const built = await withConversationLock(input.conversationId, async () => {
      const { currentTime, expiresAt } = requireExpiry(
        input.ttlMs,
        "Member removal",
      );
      const requested = new Set(input.deviceIds);
      if (
        requested.size === 0 ||
        requested.size !== input.deviceIds.length ||
        input.deviceIds.some((deviceId) => deviceId.length === 0)
      )
        throw new SecureMessagingProtocolError(
          "Member removal requires unique, non-empty device identifiers.",
        );
      if (requested.has(options.deviceCredential.deviceId))
        throw new SecureMessagingProtocolError(
          "Self-removal is not supported; another authorized member must remove this device.",
        );
      const entry = requireActiveEntry(input.conversationId);
      const members = await entry.session.members();
      const byDeviceId = new Map(
        members.map(({ credential: memberCredential }) => [
          memberCredential.deviceId,
          memberCredential,
        ]),
      );
      const targets = input.deviceIds.map((deviceId) => {
        const target = byDeviceId.get(deviceId);
        if (target === undefined)
          throw new SecureMessagingProtocolError(
            `Device ${deviceId} is not a conversation member.`,
          );
        return target;
      });
      for (const target of targets)
        if (
          !(await options.membershipPolicy.authorize({
            action: "remove",
            conversationId: input.conversationId,
            members: members.map(({ credential: member }) => member),
            target,
          }))
        )
          throw new SecureMessagingProtocolError(
            `Membership policy rejected removal of ${target.deviceId}.`,
          );
      return persistMutation(input.conversationId, entry, async () =>
        persistMembershipChange({
          conversationId: input.conversationId,
          createdAt: currentTime,
          entry,
          expiresAt,
          membership: await entry.session.removeMembers(input.deviceIds),
          recipientDeviceIds: members
            .map(({ credential: member }) => member.deviceId)
            .filter(
              (deviceId) =>
                deviceId !== options.deviceCredential.deviceId &&
                !requested.has(deviceId),
            ),
        }),
      );
    });
    return Object.freeze({
      delivery: await deliverEntries(built.entries),
      epoch: built.epoch,
      messageIds: Object.freeze(built.entries.map(({ message }) => message.id)),
    });
  };

  const selfUpdate = async (
    conversationId: string,
    ttlMs: number,
  ): Promise<SecureMessagingMembershipDeliveryResult> => {
    const built = await withConversationLock(conversationId, async () => {
      const { currentTime, expiresAt } = requireExpiry(ttlMs, "Self-update");
      const entry = requireActiveEntry(conversationId);
      const members = await entry.session.members();
      const local = members.find(
        ({ credential: member }) =>
          member.deviceId === options.deviceCredential.deviceId,
      )?.credential;
      if (local === undefined)
        throw new SecureMessagingProtocolError(
          "The local device is not a conversation member.",
        );
      if (
        !(await options.membershipPolicy.authorize({
          action: "self-update",
          conversationId,
          members: members.map(({ credential: member }) => member),
          target: local,
        }))
      )
        throw new SecureMessagingProtocolError(
          "Membership policy rejected the self-update.",
        );
      return persistMutation(conversationId, entry, async () =>
        persistMembershipChange({
          conversationId,
          createdAt: currentTime,
          entry,
          expiresAt,
          membership: await entry.session.selfUpdate(),
          recipientDeviceIds: members
            .map(({ credential: member }) => member.deviceId)
            .filter(
              (deviceId) => deviceId !== options.deviceCredential.deviceId,
            ),
        }),
      );
    });
    return Object.freeze({
      delivery: await deliverEntries(built.entries),
      epoch: built.epoch,
      messageIds: Object.freeze(built.entries.map(({ message }) => message.id)),
    });
  };

  const acceptInvitation = async (conversationId: string): Promise<void> =>
    withConversationLock(conversationId, async () => {
      const entry = requireEntry(conversationId);
      if (entry.status !== "pending-invitation")
        throw new SecureMessagingProtocolError(
          `Conversation ${conversationId} does not have a pending invitation.`,
        );
      entry.status = "active";
      await commitEntry({ entry, expectedRevision: entry.revision });
    });

  const rejectInvitation = async (conversationId: string): Promise<void> =>
    withConversationLock(conversationId, async () => {
      const entry = requireEntry(conversationId);
      if (entry.status !== "pending-invitation")
        throw new SecureMessagingProtocolError(
          `Conversation ${conversationId} does not have a pending invitation.`,
        );
      if (
        !(await options.store.removeConversation(
          conversationId,
          entry.revision,
        ))
      ) {
        await discardEntry(conversationId, entry);
        throw new SecureMessagingProtocolError(
          "Pending invitation changed concurrently; reload is required.",
        );
      }
      await discardEntry(conversationId, entry);
    });

  const recoverMember = async (
    input: SecureMessagingRecoverInput,
  ): Promise<SecureMessagingMembershipDeliveryResult> => {
    const { request, grant } = input;
    const built = await withConversationLock(
      request.conversationId,
      async () => {
        const { currentTime, expiresAt } = requireExpiry(
          input.ttlMs,
          "Recovery",
        );
        validateRecoveryRequest(
          request,
          options.policy.maximumTtlMs,
          currentTime,
        );
        validateRecoveryGrant(grant, request, currentTime);
        if (
          options.policy.securityMode !== "managed-recovery" ||
          options.recovery === undefined ||
          options.recovery.authorityId !== grant.authorityId ||
          !(await options.recovery.verify({ grant, request }))
        )
          throw new SecureMessagingProtocolError(
            "Recovery grant verification failed or the authority is not configured.",
          );
        const entry = requireActiveEntry(request.conversationId);
        const members = await entry.session.members();
        const lost = new Set(request.lostDeviceIds);
        const lostMembers = members.filter(({ credential }) =>
          lost.has(credential.deviceId),
        );
        if (
          lostMembers.length !== lost.size ||
          lostMembers.some(
            ({ credential }) =>
              credential.identityId !== request.subjectIdentityId,
          ) ||
          members.some(
            ({ credential }) =>
              credential.deviceId === request.replacementCredential.deviceId,
          )
        )
          throw new SecureMessagingProtocolError(
            "Recovery request does not exactly identify replaceable member devices.",
          );
        if (
          !(await options.membershipPolicy.authorize({
            action: "recover",
            authorityId: grant.authorityId,
            conversationId: request.conversationId,
            lostDeviceIds: request.lostDeviceIds,
            members: members.map(({ credential }) => credential),
            requestId: request.id,
            target: request.replacementCredential,
          }))
        )
          throw new SecureMessagingProtocolError(
            "Membership policy rejected the recovery grant.",
          );
        const keyPackage = await options.keyPackageDirectory.claim(
          request.subjectIdentityId,
        );
        if (
          keyPackage === undefined ||
          keyPackage.expiresAt <= currentTime ||
          !sameCredential(keyPackage.credential, request.replacementCredential)
        )
          throw new SecureMessagingProtocolError(
            "No exact, unexpired replacement KeyPackage is available.",
          );
        return persistMutation(request.conversationId, entry, async () => {
          const membership = await entry.session.replaceMembers({
            add: [keyPackage],
            removeDeviceIds: request.lostDeviceIds,
          });
          if (
            membership.welcomes.length !== 1 ||
            membership.welcomes[0]?.deviceId !==
              request.replacementCredential.deviceId
          )
            throw new SecureMessagingProtocolError(
              "Provider did not produce exactly one replacement Welcome.",
            );
          const entries: SecureMessagingOutboxEntry[] = [];
          const welcome = membership.welcomes[0];
          const welcomeId = idFactory();
          const welcomeMessage: DeliveryMessage = {
            bytes: encodeSecureMessagingWelcomeFrame({
              contract: SECURE_MESSAGING_FRAME_CONTRACT,
              conversationId: request.conversationId,
              createdAt: currentTime,
              expiresAt,
              id: welcomeId,
              kind: "welcome",
              recipientDeviceId: welcome.deviceId,
              securityMode: "managed-recovery",
              welcomeBytes: welcome.bytes,
            }),
            conversationId: request.conversationId,
            id: welcomeId,
            kind: "welcome",
            recipientDeviceId: welcome.deviceId,
          };
          entries.push({
            message: welcomeMessage,
            queueId: `${request.conversationId}:${welcomeId}`,
          });
          entries.push(
            ...buildHandshakeEntries({
              conversationId: request.conversationId,
              createdAt: currentTime,
              expiresAt,
              membership: { ...membership, welcomes: [] },
              recipientDeviceIds: members
                .map(({ credential }) => credential.deviceId)
                .filter(
                  (deviceId) =>
                    deviceId !== options.deviceCredential.deviceId &&
                    !lost.has(deviceId),
                ),
            }),
          );
          if (
            entries.some(
              ({ message }) =>
                message.bytes.length > options.policy.maximumFrameBytes,
            )
          )
            throw new SecureMessagingProtocolError(
              "Encoded recovery frame exceeds the frame limit.",
            );
          await commitEntry({
            entry,
            expectedRevision: entry.revision,
            outbox: entries,
          });
          return Object.freeze({
            entries: Object.freeze(entries),
            epoch: membership.epoch,
          });
        });
      },
    );
    return Object.freeze({
      delivery: await deliverEntries(built.entries),
      epoch: built.epoch,
      messageIds: Object.freeze(built.entries.map(({ message }) => message.id)),
    });
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
      const joined: string[] = [];
      const pendingInvitations: string[] = [];
      const rejected: string[] = [];
      const messages: SecureMessagingReceiveResult["messages"][number][] = [];
      for (const deliveryMessage of batch.messages) {
        if (
          deliveryMessage.bytes.length > options.policy.maximumFrameBytes ||
          (deliveryMessage.recipientDeviceId !== undefined &&
            deliveryMessage.recipientDeviceId !==
              options.deviceCredential.deviceId)
        )
          throw new SecureMessagingProtocolError(
            `Delivery metadata for message ${deliveryMessage.id} is invalid.`,
          );
        if (deliveryMessage.kind === "welcome") {
          const frame = decodeSecureMessagingWelcomeFrame(
            deliveryMessage.bytes,
          );
          if (
            frame.id !== deliveryMessage.id ||
            frame.conversationId !== deliveryMessage.conversationId ||
            frame.recipientDeviceId !== options.deviceCredential.deviceId ||
            deliveryMessage.recipientDeviceId !== frame.recipientDeviceId ||
            frame.securityMode !== options.policy.securityMode
          )
            throw new SecureMessagingProtocolError(
              `Welcome metadata for message ${deliveryMessage.id} is invalid.`,
            );
          const receivedAt = now();
          if (frame.expiresAt <= receivedAt) {
            expired.push(frame.id);
            continue;
          }
          if (
            frame.expiresAt - frame.createdAt > options.policy.maximumTtlMs ||
            frame.createdAt - receivedAt > options.policy.maximumFutureSkewMs
          )
            throw new SecureMessagingProtocolError(
              `Welcome message ${frame.id} violates time policy.`,
            );
          const frameDigest = await digest(deliveryMessage.bytes);
          await withConversationLock(frame.conversationId, async () => {
            const inbound: SecureMessagingInboundReceipt = {
              conversationId: frame.conversationId,
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
            if (sessions.has(frame.conversationId))
              throw new SecureMessagingProtocolError(
                `Conversation ${frame.conversationId} is already registered.`,
              );
            const session = await options.provider.joinConversation({
              credential: options.deviceCredential,
              expectedSecurityMode: options.policy.securityMode,
              welcome: frame.welcomeBytes,
            });
            try {
              requireMessagingSessionMode(session, options.policy.securityMode);
            } catch (error) {
              await session.close();
              throw error;
            }
            let members: Awaited<ReturnType<MessagingSession["members"]>>;
            let disposition: Awaited<
              ReturnType<
                SecureMessagingClientOptions["membershipPolicy"]["reviewInvitation"]
              >
            >;
            try {
              members = await session.members();
              disposition = await options.membershipPolicy.reviewInvitation({
                conversationId: frame.conversationId,
                members: members.map(({ credential }) => credential),
                target: options.deviceCredential,
              });
            } catch (error) {
              await session.close().catch(() => undefined);
              throw error;
            }
            if (
              disposition !== "accept" &&
              disposition !== "pending" &&
              disposition !== "reject"
            ) {
              await session.close();
              throw new SecureMessagingProtocolError(
                `Membership policy returned an invalid disposition for Welcome ${frame.id}.`,
              );
            }
            if (disposition === "reject") {
              await session.close();
              const recorded = await options.store.recordInbound(inbound);
              if (recorded === "conflict")
                throw new SecureMessagingProtocolError(
                  `Message identifier ${frame.id} was reused with different bytes.`,
                );
              if (recorded === "duplicate") duplicates.push(frame.id);
              else rejected.push(frame.id);
              return;
            }
            await attachSession({
              conversationId: frame.conversationId,
              inbound,
              session,
              status:
                disposition === "accept" ? "active" : "pending-invitation",
            });
            if (disposition === "accept") joined.push(frame.conversationId);
            else pendingInvitations.push(frame.conversationId);
          });
          continue;
        }
        if (
          deliveryMessage.kind !== "application" &&
          deliveryMessage.kind !== "commit" &&
          deliveryMessage.kind !== "proposal"
        )
          throw new SecureMessagingProtocolError(
            `Unsupported delivery kind for message ${deliveryMessage.id}.`,
          );
        const frame = decodeSecureMessagingFrame(deliveryMessage.bytes);
        if (
          frame.id !== deliveryMessage.id ||
          frame.kind !== deliveryMessage.kind ||
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
          const entry = requireActiveEntry(deliveryMessage.conversationId);
          try {
            const result = await entry.session.process({
              authenticatedContext: frame.authenticatedContext,
              bytes: frame.protectedBytes,
              protocol: frame.protocol,
            });
            if (
              result?.kind === "application" &&
              result.message.plaintext.length >
                options.policy.maximumMessageBytes
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
          } catch (error) {
            if (sessions.get(deliveryMessage.conversationId) === entry)
              await discardEntry(deliveryMessage.conversationId, entry);
            throw error;
          }
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
        joined: Object.freeze(joined),
        messages: Object.freeze(messages),
        pendingInvitations: Object.freeze(pendingInvitations),
        rejected: Object.freeze(rejected),
      });
    } finally {
      receiving = false;
    }
  };

  return Object.freeze({
    acceptInvitation,
    closeConversation: async (conversationId) =>
      withConversationLock(conversationId, async () => {
        const entry = requireEntry(conversationId);
        await entry.session.close();
        sessions.delete(conversationId);
      }),
    createConversation,
    flushOutbox,
    invite,
    loadConversation,
    publishKeyPackage,
    receive,
    recoverMember,
    rejectInvitation,
    registerConversation,
    removeMembers,
    sealConversation: async (conversationId) =>
      options.provider.sealConversationState(
        requireEntry(conversationId).session,
      ),
    send,
    selfUpdate,
  });
};
