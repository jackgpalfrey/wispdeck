# Wispdeck

Wispdeck is a self-hosted home for links and lightweight websites that wake on
demand.

The implemented control plane includes production-oriented local authentication,
user and superuser management, owner-scoped short links, static site hosting,
and Wispist shared data for hosted sites. Users can choose a custom short name
or generate one, update destinations, set expiry times, disable links, and see
privacy-preserving daily visit totals. Sites are uploaded as ZIP bundles, begin
as private drafts, and publish or roll back with an atomic release switch. Each
site has an owner-only Wispist data console for usage, JSON export,
revision-safe document repair, collection clearing, and permanent cleanup.
Retained releases and per-user resources are bounded by configurable
installation limits. Superusers can manage every user's links and sites, and
can customise the instance name, public tagline, accent colour, and whether
signed-out visitors see a landing page from Settings without restarting the
server. See
[`docs/security-model.md`](docs/security-model.md),
[`docs/authentication.md`](docs/authentication.md), and
[`docs/hosting.md`](docs/hosting.md) for the contracts that shape it. The Wispist
engine and browser protocol are specified in [`docs/wispist.md`](docs/wispist.md).
Signed tagged updates, release identity, health checks, and offline recovery are covered by
[`docs/operations.md`](docs/operations.md).

Links have three modes: an editable `302 Found` redirect to one destination, a
public index of several destinations, or an open-all page that attempts to open
several tabs and falls back to a user-clicked button when the browser blocks
them. Names are deployment-wide, case-insensitive, and permanently reserved
once created so an old shared URL cannot later be claimed by someone else. Only
absolute HTTP and HTTPS destinations are accepted. Links and hosted sites share
the same permanent public-name namespace, so `/notes` and `notes.example.com`
cannot refer to different resources.

## Development

The supported toolchain is Go 1.26.5 or newer. Earlier Go 1.26 patch releases
contain standard-library vulnerabilities reachable by an HTTP application.

```sh
go test ./...
go vet ./...
```

Build and start a fresh development instance directly:

```sh
go build -o wispdeck ./cmd/wispdeck
./wispdeck serve \
  --development \
  --offline-password-check \
  --app-origin http://localhost:8080
```

When no control database or authentication key exists, `serve` creates both,
prints a six-character setup code, and redirects the browser to
`/onboarding`. Enter that code to create the first superuser; the browser then
continues into passkey, authenticator-app, or explicit password-only setup. The
`auth-key generate` and `admin create` commands remain available for operators
who prefer an entirely local bootstrap.

Use `wispdeck backup create` while the server is stopped to back up
`data/auth.key`, `data/wispdeck.db`, and every Wispist database as one verified
archive. The control database alone cannot decrypt passkeys or
authenticator-app seeds, verify recovery codes, or verify peppered password
hashes. See [`docs/operations.md`](docs/operations.md) for backup, restore,
release metadata, and `/healthz`. New passwords are screened against a built-in
blocklist and the padded Have I Been Pwned range API.
`--skip-compromised-password-check` is an explicit offline override for local
CLI operations.

For a production deployment, terminate TLS at a reverse proxy that preserves
the original `Host` header, then provide the exact public application origin.
After bootstrapping state locally and before exposing the service publicly, run
the production preflight with the same paths and origin flags:

```sh
./wispdeck doctor \
  --app-origin https://wispdeck.example.com \
  --site-domain wispdeck.example.com \
  --preview-domain preview.wispdeck.example.com \
  --trusted-proxy 127.0.0.1/32
```

Then start the service:

```sh
./wispdeck serve \
  --app-origin https://wispdeck.example.com \
  --site-domain wispdeck.example.com \
  --preview-domain preview.wispdeck.example.com \
  --trusted-proxy 127.0.0.1/32
```

The default resource ceilings are 1,000 permanently reserved link names and
100 sites per user, 25 retained releases per site, and 1 GiB of retained
release content per user.
They can be changed with `--max-links-per-user`, `--max-sites-per-user`,
`--max-releases-per-site`, and `--max-site-storage-mib-per-user`. Wispist's
separate live and draft document quotas are shown in the management interface.
Authentication audit events default to 90 days and 100,000 records. The
updater retains the newest three pre-update backups and three verified
downloads. Those bounds are configurable; see
[`docs/operations.md`](docs/operations.md) for the corresponding flags and the
complete preflight contract.

Only configure a trusted proxy range that is under your control; forwarding
headers from every other peer are ignored. The proxy must preserve the original
`Host` header. Configure wildcard DNS and certificates for
`*.wispdeck.example.com` and `*.preview.wispdeck.example.com`; a site named
`notes` is then served from `notes.wispdeck.example.com`, while `/notes`
permanently redirects there. To use
origins such as `notes.sites.example.com`, set `--site-domain sites.example.com`
instead. The application origin may serve the management interface and
short-link redirects, but never serves hosted user content.

For local browser testing, the default site domain follows the application
hostname, so `--app-origin http://localhost:8080 --development` serves a site
named `notes` at `http://notes.localhost:8080`. Private previews use a fresh
origin beneath `preview.localhost`. See
[`docs/hosting.md`](docs/hosting.md) before exposing site hosting publicly.

The upload-ready [`examples/wispdeck-demo-site.zip`](examples/wispdeck-demo-site.zip)
contains a shared Wispist checklist. Upload it, publish it, and open the site in
two browsers to exercise persistence and live updates.

`--development` permits HTTP and insecurely transported cookies for local
testing, forces a loopback listener, and must not be used as a production
configuration. `--offline-password-check` disables the online breached-password
check for password changes and is likewise an explicit availability/security
tradeoff.

Local recovery deliberately revokes remote authentication state:

```sh
./wispdeck admin reset-mfa --username admin --yes
./wispdeck admin reset-password --username admin --yes
```
