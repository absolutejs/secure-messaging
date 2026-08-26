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
    authorize: ({ action, target }) =>
      action === "join" || approvedIdentities.has(target.identityId),
  },
  policy: {
    authorize: ({ direction, senderDeviceId }) =>
      direction === "outbound" || trustedDevices.has(senderDeviceId),
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

Version `0.1.0` covers authenticated application-message framing, KeyPackage
publication, policy-gated invitation, mode-bound Welcome processing, membership
commit routing, crash restoration, and retryable delivery. Attachments, member
removal orchestration, recovery workflows, abuse reports, and federation remain
explicit roadmap work and are not claimed by this release.

## Security boundaries

- Delivery sees ciphertext and minimum routing metadata, never conversation keys.
- Unknown fields, malformed frames, metadata substitution, replay-ID conflicts,
  unauthorized messages, and processing errors fail closed without acknowledgement.
- Exact duplicates and already-expired frames can be acknowledged without being
  processed.
- The store must atomically commit sealed provider state, its compare-and-set
  revision, an inbound replay receipt, and outbound queue entries. Splitting
  these writes can cause message loss, replay lockout, or MLS state divergence.
- Outbox delivery is at-least-once. A crash after transport acceptance but before
  outbox removal can resend ciphertext; recipients handle the exact duplicate
  through the durable receipt committed with their new sealed state.
- A state conflict closes and removes the in-memory session. Reload durable state
  before any further operation.
- Push notifications should carry only an opaque wake-up token.

See [SECURITY.md](./SECURITY.md) before production use.

## License

Apache-2.0
