import type {
  AuthenticatedContext,
  DeliveryService,
  DeviceCredential,
  KeyPackageDirectory,
  LocalDeviceCredential,
  MessagingProcessResult,
  MessagingProvider,
  RecoveryGrant,
  RecoveryGrantVerifier,
  RecoveryRequest,
  SecurityMode,
} from "@absolutejs/e2ee";

export const SECURE_MESSAGING_FRAME_CONTRACT = 1 as const;

export type SecureMessagingFrame = {
  readonly authenticatedContext: AuthenticatedContext;
  readonly contract: typeof SECURE_MESSAGING_FRAME_CONTRACT;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly id: string;
  readonly kind: "application" | "commit" | "proposal";
  readonly protectedBytes: Uint8Array;
  readonly protocol: string;
};

export type SecureMessagingWelcomeFrame = {
  readonly contract: typeof SECURE_MESSAGING_FRAME_CONTRACT;
  readonly conversationId: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly id: string;
  readonly kind: "welcome";
  readonly recipientDeviceId: string;
  readonly securityMode: SecurityMode;
  readonly welcomeBytes: Uint8Array;
};

export type SecureMessagingStoredConversation = {
  readonly conversationId: string;
  readonly revision: number;
  readonly sealedState: Uint8Array;
  readonly securityMode: SecurityMode;
  readonly status: "active" | "pending-invitation";
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
  readonly recordInbound: (
    receipt: SecureMessagingInboundReceipt,
  ) => Promise<Exclude<SecureMessagingInboundStatus, "new"> | "recorded">;
  readonly removeConversation: (
    conversationId: string,
    expectedRevision: number,
  ) => Promise<boolean>;
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

export type SecureMessagingMembershipAuthorization = {
  readonly action: "invite" | "remove" | "self-update";
  readonly conversationId: string;
  readonly members: readonly DeviceCredential[];
  readonly target: DeviceCredential;
};

export type SecureMessagingRecoveryAuthorization = {
  readonly action: "recover";
  readonly authorityId: string;
  readonly conversationId: string;
  readonly lostDeviceIds: readonly string[];
  readonly members: readonly DeviceCredential[];
  readonly requestId: string;
  readonly target: DeviceCredential;
};

export type SecureMessagingInvitationDisposition =
  "accept" | "pending" | "reject";

export type SecureMessagingClientBaseOptions = {
  readonly delivery: DeliveryService;
  readonly deviceCredential: LocalDeviceCredential;
  readonly idFactory?: () => string;
  readonly keyPackageDirectory: KeyPackageDirectory;
  readonly membershipPolicy: {
    readonly authorize: (
      input:
        | SecureMessagingMembershipAuthorization
        | SecureMessagingRecoveryAuthorization,
    ) => boolean | Promise<boolean>;
    readonly reviewInvitation: (
      input: Omit<SecureMessagingMembershipAuthorization, "action">,
    ) =>
      | SecureMessagingInvitationDisposition
      | Promise<SecureMessagingInvitationDisposition>;
  };
  readonly now?: () => number;
  readonly provider: MessagingProvider;
  readonly store: SecureMessagingStore;
};

export type SecureMessagingClientOptions = SecureMessagingClientBaseOptions &
  (
    | {
        readonly policy: SecureMessagingPolicy & {
          readonly securityMode: "managed-recovery";
        };
        readonly recovery: RecoveryGrantVerifier;
      }
    | {
        readonly policy: SecureMessagingPolicy & {
          readonly securityMode: "strict-e2ee";
        };
        readonly recovery?: never;
      }
  );

export type SecureMessagingInviteInput = {
  readonly conversationId: string;
  readonly identityId: string;
  readonly ttlMs: number;
};

export type SecureMessagingMembershipDeliveryResult = {
  readonly delivery: "delivered" | "queued";
  readonly epoch: number;
  readonly messageIds: readonly string[];
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
  readonly joined: readonly string[];
  readonly messages: readonly MessagingProcessResult[];
  readonly pendingInvitations: readonly string[];
  readonly rejected: readonly string[];
};

export type SecureMessagingRemoveInput = {
  readonly conversationId: string;
  readonly deviceIds: readonly string[];
  readonly ttlMs: number;
};

export type SecureMessagingRecoverInput = {
  readonly grant: RecoveryGrant;
  readonly request: RecoveryRequest;
  readonly ttlMs: number;
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
  readonly acceptInvitation: (conversationId: string) => Promise<void>;
  readonly closeConversation: (conversationId: string) => Promise<void>;
  readonly createConversation: (conversationId: string) => Promise<void>;
  readonly flushOutbox: (limit?: number) => Promise<SecureMessagingFlushResult>;
  readonly invite: (
    input: SecureMessagingInviteInput,
  ) => Promise<SecureMessagingMembershipDeliveryResult>;
  readonly loadConversation: (conversationId: string) => Promise<void>;
  readonly receive: (cursor?: string) => Promise<SecureMessagingReceiveResult>;
  readonly recoverMember: (
    input: SecureMessagingRecoverInput,
  ) => Promise<SecureMessagingMembershipDeliveryResult>;
  readonly rejectInvitation: (conversationId: string) => Promise<void>;
  readonly removeMembers: (
    input: SecureMessagingRemoveInput,
  ) => Promise<SecureMessagingMembershipDeliveryResult>;
  readonly publishKeyPackage: (expiresAt: number) => Promise<string>;
  readonly registerConversation: (
    conversationId: string,
    sealedState: Uint8Array,
  ) => Promise<void>;
  readonly sealConversation: (conversationId: string) => Promise<Uint8Array>;
  readonly send: (
    input: SecureMessagingSendInput,
  ) => Promise<SecureMessagingDeliveryResult>;
  readonly selfUpdate: (
    conversationId: string,
    ttlMs: number,
  ) => Promise<SecureMessagingMembershipDeliveryResult>;
};
