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

Managed recovery follows RFC 9750 state-loss recovery by rejoining with a fresh
credential and removing lost leaves. The configured verifier must bind its proof
to the complete request and use a phishing-resistant approval ceremony. This
package deliberately does not send serialized live MLS state to a recovery
authority or restore a stale snapshot as a second live member.
