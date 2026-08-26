# Changelog

## 0.2.0

- Add explicit accept, pending, and reject dispositions for authenticated MLS
  Welcomes; pending conversations are durably stored but cannot exchange traffic
  or mutate membership.
- Add durable invitation acceptance, compare-and-delete rejection, and standalone
  replay receipts so rejected invitations remain rejected across retries.
- Add policy-gated member removal and self-update with atomic MLS state and
  retryable commit delivery.
- Verify pending activation, self-update, and post-removal confidentiality with
  the real `@absolutejs/e2ee-mls` provider.

## 0.1.0

- Add one atomic persistence contract for sealed provider state, inbound replay
  receipts, and retryable outbound delivery entries.
- Add durable outbox flushing and optimistic-concurrency invalidation that forces
  a reload instead of continuing from divergent group state.
- Add KeyPackage publication, policy-gated invitations, mode-bound Welcome
  handling, membership commit routing, and crash restoration.
- Exercise the complete flow with the real `@absolutejs/e2ee-mls@0.4.0`
  provider and encrypted state protection.

## 0.0.1

- Add provider-neutral secure conversation creation, restoration, sealing, send,
  receive, and close orchestration.
- Add strict authenticated framing with expiry, size, recipient, conversation,
  and delivery-metadata binding.
- Add application policy hooks, atomic replay claims, conflict detection, and
  acknowledge-after-processing delivery semantics.
