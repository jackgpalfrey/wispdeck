# Static site hosting

Status: v1 implementation contract, 2026-07-13.

## Product behaviour

Wispdeck hosts pre-built static browser applications. Creating `notes` reserves
that public name permanently for its owner. With an application origin of
`https://example.com` and `--site-domain example.com`:

- the dashboard and short links use `https://example.com`;
- the site uses `https://notes.example.com`;
- `https://example.com/notes` and every nested alias below it issue a `308`
  redirect to the corresponding site path; and
- no short link can also be named `notes`.

Creating a site does not start a process. Its files are stored with the control
database and read only in response to a request. Uploading a ZIP creates an
immutable release and selects it as the draft. It never changes the public
release. Publishing and rollback are atomic pointer changes, so a visitor sees
one complete release or another rather than a partially deployed directory.
Before the first upload, the reserved public origin shows a non-indexable
Wispdeck placeholder with a route back to site management.

The first draft is private. Its public origin shows a Wispdeck draft gate and
offers the owner a sign-in path. Once a release has been published, ordinary
visitors continue to see that release while a replacement draft is prepared.
An authorized preview defaults to Draft and offers Current/Draft controls. The
actual publication action always happens back on the trusted dashboard.

Disabling a site returns `404` from both its content origin and application
alias. It does not release the name or delete releases. Re-enabling it restores
the selected public release.

## Bundle contract

Uploads must be ZIP archives with `index.html` at the archive root. Directory
URLs such as `/guide/` resolve to `/guide/index.html`. Wispdeck does not run a
package manager, build command, function, CGI program, or arbitrary backend.

Current limits are:

- 20 MiB compressed upload;
- 50 MiB expanded content;
- 500 files; and
- 10 MiB per file.

Paths must be canonical relative UTF-8 paths. Absolute paths, `..`, backslashes,
control characters, symlinks, encrypted entries, case-insensitive duplicates,
and the reserved `_wispdeck` and `_wispist` trees are rejected. Content types
are derived from file extensions and responses use
`X-Content-Type-Options: nosniff`.

## Wispist data

A release may place `wispist.json` at the archive root to declare
browser-visible document collections. Wispdeck validates the declaration during
upload and rejects the complete release if it is malformed, ambiguous,
unsupported, or raises an installation limit. A release without the file has no
accessible collections.

Wispdeck inserts the Wispist bootstrap before site-authored elements in every
served HTML `head`, so site JavaScript can use `globalThis.wispist` without a
connection step or API key. The complete data and client contract is in
[`wispist.md`](wispist.md). `/_wispist/` is a platform route on every content
origin and can never be supplied by an uploaded file.

Public releases use the site's stable `live` data namespace. Draft previews use
a separate stable `draft` namespace. Publishing or rolling back switches code
and policy but does not copy, replace, or delete live documents. The Current
selection on a preview origin reads live data with an unconditional server-side
read-only override.

## Origin and preview boundary

Uploaded HTML, CSS, and JavaScript are untrusted. Content hosts are routed before
the application router, and application pages are never available from them.
The dashboard session cookie is host-only. Each preview receives a fresh random
origin beneath the configured preview domain. Its cookie is also host-only and
is valid only for the origin and site named in its server-side session. A public
release's service worker, cache, local storage, and DOM therefore cannot observe
or control a new preview; older previews use different origins as well.

Clicking Preview on the dashboard creates a two-minute random, single-use
handoff and a fresh 128-bit preview-origin label. Only the grant's SHA-256 digest
is stored. The preview host consumes the grant, sets an opaque eight-hour
preview cookie, applies `Referrer-Policy: no-referrer`, and redirects immediately
to remove the grant from the URL. Draft responses use
`Cache-Control: private, no-store`, vary on cookies, and deny framing and
cross-origin resource use. Public files use ETags and revalidation.

Sibling subdomains are separate origins but are normally the same browser site.
Consequently `SameSite` is not treated as CSRF protection: every application
mutation still requires an exact application `Origin` (or the narrowly defined
same-origin browser fallback) and the authenticated session's CSRF token.
Application responses deny framing and cross-origin resource use.

The preview toolbar is deliberately not trusted. A site can hide or spoof
anything injected into its own DOM, and a site's own CSP meta tag may prevent
the toolbar style from applying. The bar carries no mutation token and cannot
publish. Follow its Publish link to verify the action and release on the trusted
dashboard origin.

## Production deployment

The reverse proxy or ingress must:

1. terminate HTTPS for the exact application hostname, the wildcard public
   content hostname, and the wildcard preview hostname;
2. route all three host patterns to the same Wispdeck server;
3. preserve the original `Host` header;
4. forward client-address headers only from proxy addresses listed with
   `--trusted-proxy`; and
5. enforce request-body limits at least as strict as Wispdeck's upload limit,
   allowing a small allowance for multipart framing.

Example for `jgp.sh` and `*.jgp.sh`:

```sh
./wispdeck serve \
  --app-origin https://jgp.sh \
  --site-domain jgp.sh \
  --preview-domain preview.jgp.sh \
  --trusted-proxy 127.0.0.1/32
```

Wildcard DNS must point both `*.jgp.sh` and `*.preview.jgp.sh` at the ingress.
Certificates must cover `jgp.sh`, `*.jgp.sh`, and `*.preview.jgp.sh`. If public
content should instead live beneath `*.sites.jgp.sh`, set `--site-domain
sites.jgp.sh`; the default preview domain then becomes `preview.sites.jgp.sh`.
Provision both matching wildcards. Do not rewrite content or preview hosts onto
the application hostname.

Development mode defaults the site suffix to the application hostname. A local
server at `http://localhost:8080` therefore serves `notes` from
`http://notes.localhost:8080`; each preview uses a random host beneath
`preview.localhost`. Development mode is loopback-only; use an SSH port forward
when testing from another machine.

## Persistence and operations

Site metadata, release manifests, and file bodies live in the control SQLite
database. Wispist keeps one separate SQLite file per stable site ID beneath
`data/wispist/` by default. Back up that directory with `data/wispdeck.db` and
`data/auth.key` as one offline archive using the commands in
[`operations.md`](operations.md). Control and Wispist schema migrations are
independent and atomic. Releases are intentionally immutable.
An owner may delete an older release only when it is neither the current public
release nor the selected draft. Release version numbers remain monotonic after
cleanup.

The site Data page exposes logical document usage for the live and draft
namespaces. Owners and superusers can inspect paginated collections, export one
consistent JSON snapshot containing both namespaces, replace a document with
its current revision, delete a document, or clear a collection. These are
trusted application-origin operations and are not added to the public site API.
Collection clearing emits ordinary delete changes so connected sites reconcile
normally.

“Erase site contents” disables the site, invalidates previews, deletes all
release bodies, and then hard-purges live and draft Wispist documents plus
retained mutation history. The control-plane step happens first so no public or
preview request can race new data into the purge. The `sites` row and
`public_names` reservation remain: only the original owner can upload and
republish that address later.

Both SQLite layers enable secure deletion so removed document and release
payloads are overwritten when their database cells are deleted. Freed pages are
reused by later writes; the physical database file is not promised to shrink
immediately. An operator can perform an offline SQLite vacuum when returning
filesystem space matters.

Default control-plane limits are:

- 1,000 permanently reserved short-link names per user;
- 100 hosted sites per user;
- 25 retained releases per site; and
- 1 GiB of retained release content per user.

Operators configure those limits with `--max-links-per-user`,
`--max-sites-per-user`, `--max-releases-per-site`, and
`--max-site-storage-mib-per-user`. Checks run inside the same SQLite transaction
as name reservation or upload, so concurrent requests cannot overrun a limit.

This design has no per-site idle compute cost: there is one Wispdeck process and
site work happens only while serving an upload, management action, or viewer
request. It is not a scale-to-zero application runtime; the small Wispdeck
control process and its SQLite storage remain running.
