import type {
  AuthenticatedContext,
  DeliveryService,
  LocalDeviceCredential,
  MessagingProcessResult,
  MessagingProvider,
  SecurityMode,
} from "@absolutejs/e2ee";

export const SECURE_MESSAGING_FRAME_CONTRACT = 1 as const;

export type SecureMessagingFrame = {
  readonly authenticatedContext: AuthenticatedContext;
  readonly contract: typeof SECURE_MESSAGING_FRAME_CONTRACT;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly id: string;
  readonly protectedBytes: Uint8Array;
  readonly protocol: string;
};

export type SecureMessagingStoredConversation = {
  readonly conversationId: string;
  readonly revision: number;
  readonly sealedState: Uint8Array;
  readonly securityMode: SecurityMode;
};

export type SecureMessagingInboundReceipt = {
  readonly conversationId: string;
  readonly digest: string;
  readonly expiresAt: number;
  readonly messageId: string;
};

export type SecureMessagingOutboxEntry = {
  readonly message: import("@absolutejs/e2ee").DeliveryMessage;
  readonly queueId: string;
};

export type SecureMessagingInboundStatus = "conflict" | "duplicate" | "new";

export type SecureMessagingStoreCommitResult =
  "committed" | "replay-conflict" | "state-conflict";

export type SecureMessagingStore = {
  /** Atomically commits state, a replay receipt, and queued delivery entries. */
  readonly commit: (input: {
    readonly conversation: SecureMessagingStoredConversation;
    readonly expectedRevision?: number;
    readonly inbound?: SecureMessagingInboundReceipt;
    readonly outbox?: readonly SecureMessagingOutboxEntry[];
  }) => Promise<SecureMessagingStoreCommitResult>;
  readonly inspectInbound: (input: {
    readonly conversationId: string;
    readonly digest: string;
    readonly messageId: string;
  }) => Promise<SecureMessagingInboundStatus>;
  readonly listOutbox: (
    limit: number,
  ) => Promise<readonly SecureMessagingOutboxEntry[]>;
  readonly loadConversation: (
    conversationId: string,
  ) => Promise<SecureMessagingStoredConversation | undefined>;
  readonly removeOutbox: (queueIds: readonly string[]) => Promise<void>;
};

export type SecureMessagingDirection = "inbound" | "outbound";

export type SecureMessagingPolicyInput = {
  readonly conversationId: string;
  readonly direction: SecureMessagingDirection;
  readonly expiresAt: number;
  readonly messageBytes: number;
  readonly messageId: string;
  readonly senderDeviceId: string;
};

export type SecureMessagingPolicy = {
  readonly authorize: (
    input: SecureMessagingPolicyInput,
  ) => boolean | Promise<boolean>;
  readonly maximumFrameBytes: number;
  readonly maximumFutureSkewMs: number;
  readonly maximumMessageBytes: number;
  readonly maximumTtlMs: number;
  readonly securityMode: SecurityMode;
};

export type SecureMessagingClientOptions = {
  readonly delivery: DeliveryService;
  readonly deviceCredential: LocalDeviceCredential;
  readonly now?: () => number;
  readonly policy: SecureMessagingPolicy;
  readonly provider: MessagingProvider;
  readonly store: SecureMessagingStore;
};

export type SecureMessagingSendInput = {
  readonly conversationId: string;
  readonly id: string;
  readonly plaintext: Uint8Array;
  readonly purpose: string;
  readonly recipientDeviceId?: string;
  readonly ttlMs: number;
};

export type SecureMessagingReceiveResult = {
  readonly cursor?: string;
  readonly duplicates: readonly string[];
  readonly expired: readonly string[];
  readonly messages: readonly MessagingProcessResult[];
};

export type SecureMessagingDeliveryResult = {
  readonly delivery: "delivered" | "queued";
  readonly id: string;
};

export type SecureMessagingFlushResult = {
  readonly delivered: readonly string[];
  readonly hasMore: boolean;
};

export type SecureMessagingClient = {
  readonly closeConversation: (conversationId: string) => Promise<void>;
  readonly createConversation: (conversationId: string) => Promise<void>;
  readonly flushOutbox: (limit?: number) => Promise<SecureMessagingFlushResult>;
  readonly loadConversation: (conversationId: string) => Promise<void>;
  readonly receive: (cursor?: string) => Promise<SecureMessagingReceiveResult>;
  readonly registerConversation: (
    conversationId: string,
    sealedState: Uint8Array,
  ) => Promise<void>;
  readonly sealConversation: (conversationId: string) => Promise<Uint8Array>;
  readonly send: (
    input: SecureMessagingSendInput,
  ) => Promise<SecureMessagingDeliveryResult>;
};
