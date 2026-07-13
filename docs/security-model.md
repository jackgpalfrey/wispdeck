# Security model

Status: v1 implementation contract, 2026-07-13.

## Deployment boundary

Wispdeck has two different trust zones:

1. The **application origin** serves Wispdeck's management interface and may
   also serve short-link redirects.
2. **Content origins** serve user-uploaded HTML, CSS, and JavaScript.

User content is untrusted. It must never be served from the application origin.
The application session cookie is host-only and is never scoped to a parent domain.
Sibling subdomains are different origins but the same browser "site", so
`SameSite` cookies alone are not an adequate CSRF defence. All unsafe application
requests require an exact `Origin`, same-origin `Referer`, or the
browser-controlled `Sec-Fetch-Site: same-origin` fallback. Authenticated unsafe
requests also require a session-bound CSRF token.

The v1 server has local users and no public registration, email recovery, API
tokens, or delegated authorization. Users have either the `user` or
`superuser` role. Superusers can create, disable, enable, and change the role of
other users; the final active superuser is protected by a transactional
database invariant. User status and role changes apply to existing sessions
immediately.

## Short links

Short-link names are globally unique within a deployment and contain only
lowercase ASCII letters, numbers, and hyphens. Wispdeck reserves its application
route names before they can become public redirects. Destinations must be
absolute HTTP or HTTPS URLs, may not contain embedded credentials, and are
validated again during resolution so corrupted storage cannot inject an unsafe
`Location` header.

Users can list and mutate only their own links. Superusers can list and mutate
all links. Ownership predicates are part of the same SQL statement as each
mutation, rather than a separate check vulnerable to a time-of-check/time-of-use
race. All unsafe requests retain the application origin and CSRF requirements.
Disabled, retired, unknown, and invalid links share the same public `404`
response. Retiring a link preserves its name as a tombstone, preventing an old
shared URL from being claimed by another user. Redirect resolution atomically
increments a count and records the most recent use.

## Passwords and bootstrap

- The initial superuser is created locally with `wispdeck admin create`.
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

Password authentication is followed by a mandatory second factor once either a
passkey or authenticator app has been enrolled. Before enrollment, an operator
may explicitly choose password-only administration; this choice is persisted,
audited, and prominently warned about in the interface. User-verifying WebAuthn
is preferred because it is phishing resistant. RFC 6238 TOTP is available as a
more broadly compatible alternative; its encrypted seed, single-use counters,
clock window, and rate limits are defined in `authentication.md`. Bootstrap
and recovery sessions are capability-restricted and cannot administer
Wispdeck. A deliberately opted-out password-only session can perform normal
administration. User management does not require MFA. Existing-factor changes
retain their separate recent-authentication rules.

## Sessions

- Session identifiers contain 256 bits from the operating system CSPRNG.
- Only a SHA-256 digest of the identifier is stored server-side.
- Cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, host-only, and
  use the `__Host-` prefix in production.
- Sessions have a 30-minute idle timeout and a 12-hour absolute lifetime.
- Logout deletes the server-side session before expiring the browser cookie.
- Authenticated responses use `Cache-Control: no-store`.
- Users can inspect recent authentication events and revoke individual or all
  other sessions.

## Login abuse controls

Login failures use one generic response. Attempts are limited independently by
normalized username and client address using bounded, in-memory sliding
windows. Wispdeck does not trust forwarding headers unless deployment
configuration explicitly identifies a trusted proxy. TOTP login, TOTP
enrollment, and recovery attempts are separately limited; recovery codes
contain 128 random bits.

## Out of scope for this slice

- TLS termination and reverse-proxy configuration
- Uploaded-site isolation and content security policy
- Data API authorization
- Email or support-mediated account recovery
- Distributed rate limiting
- Configurable audit-log retention policy

These are not assumed safe by the authentication implementation and must be
designed before their corresponding feature is exposed.
