# `@absolutejs/secure-messaging`

Provider-neutral secure conversation orchestration for AbsoluteJS. It composes a
`MessagingProvider`, untrusted `DeliveryService`, application policy, and durable
replay store behind one API. Cryptography remains in interchangeable
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
  replayStore,
});
```

Version `0.0.1` covers authenticated application-message framing and lifecycle.
Membership invitation delivery, durable optimistic conversation-state commits,
attachments, recovery workflows, abuse reports, and federation remain explicit
roadmap work and are not claimed by this release.

## Security boundaries

- Delivery sees ciphertext and minimum routing metadata, never conversation keys.
- Unknown fields, malformed frames, metadata substitution, replay-ID conflicts,
  unauthorized messages, and processing errors fail closed without acknowledgement.
- Exact duplicates and already-expired frames can be acknowledged without being
  processed.
- The replay store must implement an atomic claim and be durable across restarts.
- Push notifications should carry only an opaque wake-up token.

See [SECURITY.md](./SECURITY.md) before production use.

## License

Apache-2.0
