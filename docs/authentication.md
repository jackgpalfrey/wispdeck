# Production authentication design

Status: implementation contract, 2026-07-11.

This document refines the trust model in `security-model.md` into concrete
authentication and recovery flows. Wispdeck does not claim production-ready
authentication unless every invariant in this document is implemented and
tested.

## Factors and assurance

An administrative session has one of three assurance states:

- `bootstrap`: password verified, but the account has no passkey yet. This
  session may only enroll the first passkey and sign out.
- `mfa`: password and a user-verifying WebAuthn credential were verified.
- `recovery`: password and a one-use recovery code were verified. This session
  may only enroll a replacement passkey, inspect security events, or sign out.

Once an account has a passkey, a password alone never creates an administrative
session. The first passkey is enrolled through a constrained bootstrap session.
All later passkey changes require a recently created `mfa` session. Sensitive
operations require authentication within the last ten minutes; otherwise the
operator signs in again.

## WebAuthn boundary

The relying-party ID is the exact admin hostname. It is never a parent domain
that may also contain hosted user content. Cross-origin ceremonies are disabled
and user verification is required.

WebAuthn ceremony state is server-side, single-use, bound to the initiating
session or login transaction, and expires after five minutes. Successful
assertions persist the authenticator sign counter, clone warning, and backup
state returned by the WebAuthn implementation.

Credential IDs are stored for lookup and revocation. The complete credential
record is encrypted with an installation key kept outside the control database.
WebAuthn user handles are derived with a keyed function from the application
user ID, so a database writer cannot create a valid user-handle mapping.

## Password establishment

Passwords are normalized to Unicode NFC before policy checks, hashing, and
verification. New passwords are compared as complete strings against:

- a built-in common and context-specific blocklist; and
- the padded Have I Been Pwned range API using a five-character SHA-1 prefix.

Only the range prefix is transmitted. Failure to perform the online check is a
hard failure unless the local CLI operator explicitly selects the documented
offline override. Login never calls an external service.

Changing a password requires a recent `mfa` session and the current password.
It revokes every session and pending ceremony, forcing a clean login.

## Recovery

Enrolling the first passkey generates ten independent 128-bit recovery codes.
They are displayed once. Only keyed digests are stored. A code is consumed
atomically and can never be reused.

Recovery requires both the account password and one unused recovery code. A
recovery session cannot administer Wispdeck; it can only enroll a replacement
passkey, inspect relevant security events, or sign out. Enrolling a replacement
upgrades the session to `mfa` and generates a fresh recovery-code set.

An operator with local filesystem access may reset passkeys or a password using
the CLI. Local recovery invalidates every session, passkey, recovery code, and
pending ceremony. There is no email recovery or security-question bypass.

## Installation key

The authentication key contains 256 random bits and is loaded from a file that
must not be stored in the control database. Wispdeck refuses production startup
if it is absent, malformed, or accessible by group or other users. Losing this
key makes passkey records and recovery codes unusable, so backups must include
it. A copied database without the key is not sufficient to add a valid factor.

## Sessions and audit

Session identifiers remain opaque 256-bit values stored only as digests.
Operators can list and revoke their sessions. Password changes, local recovery,
passkey changes, recovery-code use, and session revocation are audited without
recording secrets or WebAuthn challenge material.

Forwarding headers are ignored unless the immediate peer matches an explicitly
configured trusted-proxy CIDR. When trusted, the effective client address is
the rightmost untrusted address in the forwarding chain.

