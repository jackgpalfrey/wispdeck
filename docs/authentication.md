# Production authentication design

Status: implementation contract, 2026-07-11.

This document refines the trust model in `security-model.md` into concrete
authentication and recovery flows. Wispdeck does not claim production-ready
authentication unless every invariant in this document is implemented and
tested.

## Factors and assurance

An administrative session has one of three assurance states:

- `bootstrap`: password verified, but the account has no second factor yet.
  This session may only enroll the first passkey or TOTP authenticator and sign
  out.
- `mfa`: password and either a user-verifying WebAuthn credential or TOTP code
  were verified.
- `recovery`: password and a one-use recovery code were verified. This session
  may only enroll a replacement factor, inspect security events, or sign out.

Once an account has any second factor, a password alone never creates an
administrative session. The first factor is enrolled through a constrained
bootstrap session. All later factor changes require a recently created `mfa`
session. Sensitive operations require authentication within the last ten
minutes; otherwise the operator signs in again.

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

## Authenticator-app boundary

TOTP implements RFC 6238 with a 160-bit random secret, HMAC-SHA-1 for broad
authenticator compatibility, six digits, and a 30-second time step. Validation
accepts only the current counter and one adjacent counter in each direction.
Every successfully verified counter is persisted atomically and a counter may
never be reused, including the code used to confirm enrollment.

The TOTP seed is encrypted with a dedicated installation-key subkey. Enrollment
state is server-side, encrypted, single-use, bound to the initiating session,
and expires after ten minutes. Enrollment and login verification are separately
rate limited. QR codes are rendered by Wispdeck and never sent to a third-party
service.

TOTP is more widely available than WebAuthn but is not phishing resistant. The
interface presents passkeys as the preferred method while allowing TOTP as a
standards-compatible alternative. An account may not delete its final MFA
factor.

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

Enrolling the first passkey or TOTP authenticator generates ten independent
128-bit recovery codes.
They are displayed once. Only keyed digests are stored. A code is consumed
atomically and can never be reused.

Recovery requires both the account password and one unused recovery code. A
recovery session cannot administer Wispdeck; it can only enroll a replacement
factor, inspect relevant security events, or sign out. Enrolling a replacement
upgrades the session to `mfa` and generates a fresh recovery-code set.

An operator with local filesystem access may reset MFA or a password using the
CLI. Local recovery invalidates every session, passkey, TOTP seed, recovery
code, and pending ceremony. There is no email recovery or security-question
bypass.

## Installation key

The authentication key contains 256 random bits and is loaded from a file that
must not be stored in the control database. Wispdeck refuses production startup
if it is absent, malformed, or accessible by group or other users. Losing this
key makes passkey records and recovery codes unusable, so backups must include
it. A copied database without the key is not sufficient to decrypt passkeys or
TOTP seeds, verify password hashes, or add a valid factor.

## Sessions and audit

Session identifiers remain opaque 256-bit values stored only as digests.
Operators can list and revoke their sessions. Password changes, local recovery,
factor changes, recovery-code use, and session revocation are audited without
recording secrets, one-time codes, or WebAuthn challenge material.

Forwarding headers are ignored unless the immediate peer matches an explicitly
configured trusted-proxy CIDR. When trusted, the effective client address is
the rightmost untrusted address in the forwarding chain.
