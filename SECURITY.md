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
