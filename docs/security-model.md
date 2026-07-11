# Security model

Status: initial v1 contract, 2026-07-11.

## Deployment boundary

Wispdeck has two different trust zones:

1. The **admin origin** serves Wispdeck's management interface.
2. **Content origins** serve user-uploaded HTML, CSS, and JavaScript.

User content is untrusted. It must never be served from the admin origin. The
admin session cookie is host-only and is never scoped to a parent domain.
Sibling subdomains are different origins but the same browser "site", so
`SameSite` cookies alone are not an adequate CSRF defence. All unsafe admin
requests require an exact `Origin` (or same-origin `Referer` fallback) and a
session-bound CSRF token.

The v1 server has local administrative users and no public registration, email
recovery, API tokens, or delegated authorization. Every local user has full
administrative control; roles require a separate authorization design.

## Passwords and bootstrap

- The initial administrator is created locally with `wispdeck admin create`.
- Passwords are never accepted in command-line arguments or environment
  variables. Automation may provide them through standard input explicitly.
- Passwords must contain 15 to 256 Unicode code points and may contain spaces.
  There are no composition or periodic-rotation rules.
- Passwords are normalized to Unicode NFC, keyed with an installation pepper,
  and encoded with Argon2id using a unique random salt. Hash parameters are
  stored with the hash so they can be upgraded after login.
- New passwords are checked against local contextual values and the padded HIBP
  k-anonymity range API unless a local operator explicitly chooses offline mode.
- Unknown users take the password-verification path using a dummy hash to
  reduce account-enumeration timing differences.

Password authentication is followed by mandatory, user-verifying WebAuthn once
the first passkey has been enrolled. Password-only bootstrap and recovery
sessions are capability-restricted and cannot administer Wispdeck.

## Sessions

- Session identifiers contain 256 bits from the operating system CSPRNG.
- Only a SHA-256 digest of the identifier is stored server-side.
- Cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, host-only, and
  use the `__Host-` prefix in production.
- Sessions have a 30-minute idle timeout and a 12-hour absolute lifetime.
- Logout deletes the server-side session before expiring the browser cookie.
- Authenticated responses use `Cache-Control: no-store`.
- Operators can inspect recent authentication events and revoke other sessions.

## Login abuse controls

Login failures use one generic response. Attempts are limited independently by
normalized username and client address using bounded, in-memory sliding
windows. Wispdeck does not trust forwarding headers unless a future deployment
configuration explicitly identifies a trusted proxy. Recovery attempts are
separately limited and recovery codes contain 128 random bits.

## Out of scope for this slice

- TLS termination and reverse-proxy configuration
- Uploaded-site isolation and content security policy
- Data API authorization
- Email or support-mediated account recovery
- Distributed rate limiting
- Configurable audit-log retention policy

These are not assumed safe by the authentication implementation and must be
designed before their corresponding feature is exposed.
