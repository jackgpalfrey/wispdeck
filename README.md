# Wispdeck

Wispdeck is a self-hosted home for links and lightweight websites that wake on
demand.

The implemented control plane includes production-oriented local authentication,
user and superuser management, and owner-scoped short links. Users can choose a
custom short name or generate one, update destinations, disable links, and see
redirect counts. Superusers can manage every user's links. See
[`docs/security-model.md`](docs/security-model.md) and
[`docs/authentication.md`](docs/authentication.md) for the contracts that shape
it.

Short links use editable `302 Found` redirects. Names are deployment-wide,
case-insensitive, and permanently reserved once created so an old shared URL
cannot later be claimed by someone else. Only absolute HTTP and HTTPS
destinations are accepted.

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
  --trusted-proxy 127.0.0.1/32
```

Only configure a trusted proxy range that is under your control; forwarding
headers from every other peer are ignored. The proxy must preserve the original
`Host` header. The application origin may serve the management interface and
short-link redirects, but must never serve hosted user content.

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
