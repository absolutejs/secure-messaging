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

export type SecureMessagingReplayClaim = "accepted" | "conflict" | "duplicate";

export type SecureMessagingReplayStore = {
  readonly claim: (input: {
    readonly conversationId: string;
    readonly digest: string;
    readonly expiresAt: number;
    readonly messageId: string;
  }) => Promise<SecureMessagingReplayClaim>;
  readonly release: (input: {
    readonly conversationId: string;
    readonly digest: string;
    readonly messageId: string;
  }) => Promise<void>;
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
  readonly replayStore: SecureMessagingReplayStore;
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

export type SecureMessagingClient = {
  readonly closeConversation: (conversationId: string) => Promise<void>;
  readonly createConversation: (conversationId: string) => Promise<void>;
  readonly receive: (cursor?: string) => Promise<SecureMessagingReceiveResult>;
  readonly registerConversation: (
    conversationId: string,
    sealedState: Uint8Array,
  ) => Promise<void>;
  readonly sealConversation: (conversationId: string) => Promise<Uint8Array>;
  readonly send: (input: SecureMessagingSendInput) => Promise<void>;
};
