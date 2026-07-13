# Security model

Status: v1 implementation contract, 2026-07-13.

## Deployment boundary

Wispdeck has two different trust zones:

1. The **application origin** serves Wispdeck's management interface and may
   also serve short-link redirects.
2. **Content origins** serve user-uploaded HTML, CSS, and JavaScript. Public
   sites have stable origins; every private preview gets a fresh origin.

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
route names before they can become public links. Destinations must be absolute
HTTP or HTTPS URLs, may not contain embedded credentials, and are validated
again during resolution so corrupted storage cannot inject an unsafe
navigation target. A link is either a single editable `302` redirect, a public
index of up to 25 ordered destinations, or an open-all page. Open-all first
attempts to create blank tabs, severs each tab's opener, and then navigates it;
blocked destinations remain behind an explicit retry button and a normal list.

Private titles and notes are selected only by management queries. Public
resolution does not load them from SQLite, so landing-page templates cannot
accidentally expose them. Destination labels are explicitly public. Expired,
disabled, retired, unknown, and invalid links share the same public `404`
response.

Users can list and mutate only their own links. Superusers can list and mutate
all links. Ownership predicates are part of the same SQL statement as each
mutation, rather than a separate check vulnerable to a time-of-check/time-of-use
race. All unsafe requests retain the application origin and CSRF requirements.
Cross-owner changes by a superuser are recorded atomically without storing
destinations or private notes. Retiring a link preserves its name as a
tombstone, preventing an old shared URL from being claimed by another user.

Public resolution is read-only. GET visits enter a bounded in-memory aggregate
and are flushed to UTC daily totals every five seconds and during graceful
shutdown; HEAD requests are not counted. The statistics tables contain only a
link ID, day, count, and most recent visit time—never client addresses,
referrers, or user agents. A crash may lose the most recent unflushed counts,
which is preferred to making public traffic contend with authentication and
management writes.

## Hosted sites

Hosted sites and short links use one transactional, deployment-wide public-name
registry. A site's name remains reserved to its original owner when the site is
disabled. The owner or a superuser can upload another release and republish the
same site, but the name cannot be reassigned. The application-origin `/<name>`
and `/<name>/...` aliases issue permanent redirects to the matching content
origin; they never serve uploaded bytes.

The only accepted workload is a pre-built static ZIP bundle. Archive ingestion
rejects traversal, absolute and non-canonical paths, backslashes, symlinks,
encrypted entries, case-insensitive path collisions, reserved `/_wispdeck/`
paths, missing root `index.html`, and configured size/count limit violations.
File and bundle digests are recalculated before storage. Releases and files are
immutable; publishing and rollback only switch the site's release pointer in a
transaction. There is no executable server-side site code or per-site idle
process.

Every hosted name has its own public content origin, and every preview grant has
a fresh unguessable content origin. The application, public content, and preview
host routers are separated before application authentication or route handling,
and unrecognised hosts receive `421 Misdirected Request`. Application cookies
and preview cookies are host-only `__Host-` cookies in production. Hosted content
does not receive the application CSP, because its scripts and styles are the
payload, but it also cannot access application responses through the same-origin
policy. Application mutations continue to require exact-origin validation and a
session-bound CSRF token; sibling subdomains are not trusted merely because
they are same-site.

Uploads begin as drafts. An unauthenticated public site origin exposes only a
generic login gate. Preview authorization crosses origins through a two-minute,
single-use random grant; its digest is stored, and exchanging it on a fresh
origin beneath the configured preview domain creates an eight-hour host-only
preview session. The grant URL is immediately cleaned. The fresh origin prevents
a service worker or browser storage installed by a public release or older draft
from controlling a new preview. Preview responses are private and non-cacheable.
Publishing a draft invalidates its preview sessions because no draft remains.
Preview responses also deny framing and cross-origin resource use so another
content origin cannot embed a private draft. If a published release and a new
draft both exist, ordinary visitors receive only the published release while an
authorized preview can switch between Current and Draft.

The preview toolbar is convenience UI injected into previewed HTML. It is not a
security boundary: uploaded HTML can restyle, remove, or imitate it. The toolbar
therefore contains no publication capability. Its Publish link returns the user
to the trusted application origin, where the normal session, origin, CSRF, and
ownership checks apply. The complete hosting and deployment contract is in
`hosting.md`.

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
- Data API authorization
- Server-side site code, build execution, and runtime sandboxing
- Custom domains
- Per-owner storage quotas and automated abuse controls
- Email or support-mediated account recovery
- Distributed rate limiting
- Configurable audit-log retention policy

These are not assumed safe by the authentication implementation and must be
designed before their corresponding feature is exposed.
