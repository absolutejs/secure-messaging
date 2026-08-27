# Security policy

This package is experimental and has not received an independent security audit.
Do not describe it as audited or production-approved.

Report vulnerabilities privately through GitHub Security Advisories for
`absolutejs/secure-messaging`. Do not include private keys, plaintext messages,
credentials, or live ciphertext in reports.

Applications remain responsible for verified device identity, key transparency,
an atomic durable implementation of `SecureMessagingStore`, delivery availability
and ordering, abuse controls, encrypted state custody, and an explicit recovery
policy. KeyPackage claims are intentionally destructive: after a failed invite,
the recipient should publish fresh material rather than risk reuse. A successful
send is not proof of recipient display, human approval, or downstream action.

Treat unknown invitations as pending. Display identities and devices from the
provider-verified MLS roster through a phishing-resistant approval flow before
activation. Rejecting an invitation must retain its replay receipt, and removing
a pending conversation must use revision-checked deletion. Member removal only
protects future epochs; it cannot revoke information a former member already
decrypted or copied.

Bind attachment replacements and similarly sensitive post-membership messages
to `expectedSecurityEpoch`. Without that precondition, a concurrent Commit can
move the send into a newer roster than the application reviewed. The epoch guard
does not prove recipients displayed or persisted the application message.

Inbound `policy.authorize` runs after MLS authentication and receives the
authenticated purpose, sender device ID, security epoch, and plaintext size.
Rejected decisions discard the mutated in-memory session. Policy code may write
an audit decision, but it must remain idempotent because delivery is at-least-once.

Managed recovery follows RFC 9750 state-loss recovery by rejoining with a fresh
credential and removing lost leaves. The configured verifier must bind its proof
to the complete request and use a phishing-resistant approval ceremony. This
package deliberately does not send serialized live MLS state to a recovery
authority or restore a stale snapshot as a second live member.
