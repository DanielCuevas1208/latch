# Security policy

Latch handles cryptographic keys. Report security issues promptly.

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Do not open a public issue for a vulnerability.

Send a private report to the repository owner on GitHub. Include the steps
to reproduce the problem. Include the affected version.

Do not share the details publicly until the maintainers fix the issue.

## What we consider a vulnerability

We treat these as vulnerabilities:

* A flaw that breaks message confidentiality.
* A flaw that breaks message integrity.
* A flaw that lets an attacker impersonate a peer.
* A flaw that leaks key material.
* A weakness in the ratchet or key derivation.

## Security review

The cryptographic design follows the Double Ratchet specification. The
implementation uses the OTP `crypto` module only. We recommend a third-party
audit before production use.
