# `@absolutejs/secure-messaging`

Provider-neutral secure conversation orchestration for AbsoluteJS. It composes a
`MessagingProvider`, untrusted `DeliveryService`, application policy, and durable
atomic state/outbox/replay store behind one API. Cryptography remains in interchangeable
`@absolutejs/e2ee-*` providers.

The confidentiality mode is mandatory and explicit. `strict-e2ee` means only
verified participant devices may decrypt. `managed-recovery` is a separate
conversation contract and requires a visibly identified recovery authority in
the surrounding application. This package never silently changes modes.

```ts
import { createSecureMessagingClient } from "@absolutejs/secure-messaging";

const messaging = createSecureMessagingClient({
  delivery,
  deviceCredential,
  keyPackageDirectory,
  membershipPolicy: {
    authorize: ({ target }) => approvedIdentities.has(target.identityId),
    reviewInvitation: ({ members }) =>
      members.every(({ identityId }) => approvedIdentities.has(identityId))
        ? "accept"
        : "pending",
  },
  policy: {
    authorize: ({ direction, purpose, securityEpoch, senderDeviceId }) =>
      allowedPurposes.has(purpose) &&
      securityEpoch >= minimumEpoch &&
      (direction === "outbound" || trustedDevices.has(senderDeviceId)),
    maximumFrameBytes: 1_572_864,
    maximumFutureSkewMs: 300_000,
    maximumMessageBytes: 1_048_576,
    maximumTtlMs: 86_400_000,
    securityMode: "strict-e2ee",
  },
  provider,
  store,
});
```

For `managed-recovery`, also provide exactly one `recovery` verifier. A recovery
request is short-lived and binds the conversation, subject identity, replacement
device credential, and every lost device ID. After the configured authority and
local membership policy both approve it, `recoverMember()` adds the replacement
KeyPackage and removes the lost leaves in one MLS commit. Strict-E2EE clients
reject recovery-authority configuration.

Version `0.3.0` includes an explicit invitation inbox, durable MLS membership
maintenance. A cryptographically valid Welcome can be accepted immediately,
held as an inert `pending-invitation`, or durably rejected. Pending conversations
cannot send, invite, remove members, self-update, or process conversation traffic.
Member removal and self-update policy checks occur before MLS mutation, and the
resulting group state and retryable commit messages use one atomic store commit.
Managed state-loss recovery uses [RFC 9750's recovery-after-state-loss model](https://www.rfc-editor.org/rfc/rfc9750.html#section-6.6)
and never
hands serialized live group state to the recovery authority. Attachments, abuse
reports and federation live in separate packages and are not claimed by this
core package.

Version `0.4.0` adds `expectedSecurityEpoch` for sensitive application messages.
Use the epoch returned by `removeMembers()`, `recoverMember()`, or `selfUpdate()`
when sending an attachment replacement or another action that must occur in that
exact post-commit roster. The client checks the precondition before protecting or
persisting the message and returns the authenticated `securityEpoch` on success.
This follows [RFC 9420's epoch model](https://www.rfc-editor.org/rfc/rfc9420.html#section-3.1):
fresh Commit entropy is available only to members of the new epoch.
The real MLS integration suite sends a strict `@absolutejs/secure-transfer`
replacement in that epoch, verifies the replacement device can decode it, and
verifies the removed device cannot process the same application ciphertext.

Version `0.5.0` runs inbound application authorization only after the selected
E2EE provider has authenticated and processed the frame. The policy receives the
authenticated purpose and security epoch; for application messages,
`messageBytes` is the decrypted plaintext size. A rejection discards the
mutated in-memory session and requires a durable reload, so an unauthenticated
envelope cannot trigger authorization side effects.

Version `0.5.1` adds `receiveAndHandle()` for request/receipt protocols. Its
handler runs after MLS authentication and application policy, but before the
inbound replay receipt or transport cursor is committed. Replies returned by the
handler are protected at the same MLS epoch and placed in the durable outbox in
the same store commit as the inbound receipt and advanced provider state. The
method wipes inbound and reply plaintext and returns message IDs rather than
plaintext. Use the authenticated request ID as the downstream idempotency key:
an application side effect can be retried if the process exits before the atomic
commit.

Version `0.6.0` exports `SecureMessagingDurabilityUncertainError` for the
storage boundary where a mutation may have applied but its durability
acknowledgement was lost. Callers must resolve the authoritative store, reload
state, and retry only when the expected revision or effect is absent. The error
contains no conversation, message, queue, or provider data.

Version `0.6.1` adds `resolveSecureMessagingStoreCommit()`. After selecting the
authoritative store, pass it the intended conversation and expected revision.
It returns `applied` only when the complete stored conversation—including sealed
state—matches, `retry` only when the prior revision is still authoritative, and
`conflict` for every other state. Associated replay and outbox effects follow
the store's atomic commit contract.

## Security boundaries

- Delivery sees ciphertext and minimum routing metadata, never conversation keys.
- Unknown fields, malformed frames, metadata substitution, replay-ID conflicts,
  unauthorized messages, and processing errors fail closed without acknowledgement.
- Inbound `policy.authorize` may perform audit or approval effects because it is
  called only after cryptographic authentication. Treat delivery metadata and
  pre-decryption frame fields as untrusted everywhere else.
- `receiveAndHandle()` transfers ownership of its handler's reply buffers to the
  client and wipes them. Handler side effects must be idempotent because a crash
  after the effect but before the store commit causes safe redelivery.
- Exact duplicates and already-expired frames can be acknowledged without being
  processed.
- The store must atomically commit sealed provider state, its compare-and-set
  revision, an inbound replay receipt, and outbound queue entries. Splitting
  these writes can cause message loss, replay lockout, or MLS state divergence.
- `recordInbound` must durably preserve a rejected Welcome receipt without
  creating conversation state. `removeConversation` must compare-and-delete the
  exact revision while preserving replay receipts. These properties prevent a
  rejected invite from reappearing and prevent acceptance/rejection races.
- Invitation review receives identities verified by the selected E2EE provider,
  but applications should default unknown or unexpected groups to `pending` and
  require an authenticated, phishing-resistant approval ceremony before calling
  `acceptInvitation`.
- Removing a device prevents it from decrypting future epochs; it cannot erase
  plaintext or keys the device already possessed. Removed devices are not sent
  the removal commit.
- Recovery grants authorize membership replacement; they do not decrypt history.
  The authority verifier must authenticate the complete request, enforce its own
  approval ceremony, reject revoked/expired grants, and maintain an audit trail.
  Recovery cannot recover data that no surviving member or encrypted archive has.
- Outbox delivery is at-least-once. A crash after transport acceptance but before
  outbox removal can resend ciphertext; recipients handle the exact duplicate
  through the durable receipt committed with their new sealed state.
- A state conflict closes and removes the in-memory session. Reload durable state
  before any further operation.
- A `SecureMessagingDurabilityUncertainError` means success and failure are both
  possible. Never retry blindly: resolve the authoritative store and inspect the
  expected revision, replay receipt, or outbox effect first.
- Push notifications should carry only an opaque wake-up token.

See [SECURITY.md](./SECURITY.md) before production use.

## License

Apache-2.0
