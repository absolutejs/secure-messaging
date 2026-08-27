# Changelog

## 0.5.1

- Add `receiveAndHandle()` so authenticated application work runs before its
  delivery cursor is acknowledged.
- Atomically persist handler-generated encrypted replies with the inbound replay
  receipt and advanced conversation state, leaving failed delivery in the
  durable outbox.
- Wipe handler-owned inbound and reply plaintext buffers on every completion
  path.

## 0.5.0

- Run inbound application policy only after the E2EE provider authenticates and
  processes the MLS frame; rejected decisions discard mutated session state.
- Give policy the authenticated purpose and MLS security epoch, and report
  decrypted application size rather than unauthenticated ciphertext size.

## 0.4.1

- Certify with real MLS sessions that an epoch-bound secure-transfer replacement
  reaches the replacement device while the removed device cannot decrypt it.

## 0.4.0

- Add an optional expected-security-epoch precondition for sensitive application
  messages and reject before MLS mutation when the conversation has advanced.
- Return the authenticated MLS security epoch from successful sends so callers
  can bind related application state to the exact epoch.

## 0.3.0

- Add managed recovery through short-lived, request-bound authority grants rather
  than escrow or restoration of live serialized MLS state.
- Bind recovery to the conversation, managed-recovery mode, subject identity,
  exact replacement credential, and exact lost-device set.
- Add the replacement KeyPackage and remove lost leaves in one MLS epoch using
  `@absolutejs/e2ee-mls@0.5.0`, with atomic state and outbox persistence.
- Verify with real MLS sessions that the replacement receives future messages
  while the removed device cannot decrypt the new epoch.

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
