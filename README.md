# Wispdeck

Wispdeck is a self-hosted home for links and lightweight websites that wake on
demand.

The implemented control plane includes production-oriented local authentication,
user and superuser management, owner-scoped short links, and static site
hosting. Users can choose a custom short name or generate one, update
destinations, set expiry times, disable links, and see privacy-preserving daily
visit totals. Sites are uploaded as ZIP bundles, begin as private drafts, and
publish or roll back with an atomic release switch. Superusers can manage every
user's links and sites. See
[`docs/security-model.md`](docs/security-model.md),
[`docs/authentication.md`](docs/authentication.md), and
[`docs/hosting.md`](docs/hosting.md) for the contracts that shape it.

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

Generate the installation authentication key before creating the first local
superuser. Neither operation puts a secret in shell history:

```sh
go build -o wispdeck ./cmd/wispdeck
./wispdeck auth-key generate
./wispdeck admin create --username admin
```

Back up both `data/auth.key` and `data/wispdeck.db`. The database alone cannot
decrypt passkeys or authenticator-app seeds, verify recovery codes, or verify
peppered password hashes. New passwords are screened against a built-in
blocklist and the padded Have I Been Pwned range API.
`--skip-compromised-password-check` is an explicit offline override for local
CLI operations.

For a production deployment, terminate TLS at a reverse proxy that preserves
the original `Host` header, then provide the exact public application origin:

```sh
./wispdeck serve \
  --app-origin https://wispdeck.example.com \
  --site-domain wispdeck.example.com \
  --preview-domain preview.wispdeck.example.com \
  --trusted-proxy 127.0.0.1/32
```

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
