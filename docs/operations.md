# Operations

Status: v1 operations contract, 2026-07-22.

## Release identity

Every release binary carries its tagged version, source commit, and UTC build
time. Operators and the updater inspect the same stable
metadata in human-readable or JSON form:

```sh
./wispdeck version
./wispdeck version --json
```

Development builds report `dev` and `unknown` values. A release build injects
metadata through Go's linker:

```sh
VERSION=v0.1.0
COMMIT=$(git rev-parse HEAD)
BUILT_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
UPDATE_MANIFEST=https://downloads.example.com/wispdeck/stable.json
UPDATE_PUBLIC_KEY=$(tr -d '\n' < release.pub)
go build -trimpath \
  -ldflags "-s -w \
    -X github.com/wispdeck/wispdeck/internal/buildinfo.version=$VERSION \
    -X github.com/wispdeck/wispdeck/internal/buildinfo.commit=$COMMIT \
    -X github.com/wispdeck/wispdeck/internal/buildinfo.builtAt=$BUILT_AT \
    -X github.com/wispdeck/wispdeck/internal/buildinfo.updateManifestURL=$UPDATE_MANIFEST \
    -X github.com/wispdeck/wispdeck/internal/buildinfo.updatePublicKey=$UPDATE_PUBLIC_KEY" \
  -o wispdeck ./cmd/wispdeck
```

Only exact stable tags in the form `vMAJOR.MINOR.PATCH` participate in updates.
Development builds, prereleases, build metadata, and downgrades are rejected.

## GitHub release automation

Pushing an annotated stable tag starts `.github/workflows/release.yml`. The
workflow rejects tags that do not use the exact `vMAJOR.MINOR.PATCH` form or
whose commit is not reachable from `main`. It verifies dependencies, runs the
test suite, vet, and the race detector, then builds static Linux binaries for
amd64 and arm64 with the tag, source commit, UTC build time, stable manifest
URL, and committed release public key embedded.

The workflow reads the private half of that key from the
`WISPDECK_RELEASE_PRIVATE_KEY` GitHub Actions secret. It generates release
notes, signs `stable.json`, verifies the resulting envelope against
`release/release.pub`, and calculates `SHA256SUMS`. A GitHub Release is
published only after all four assets have been attached to a draft release.
Configure a new repository once before its first tag:

```sh
./wispdeck-release keygen \
  --private "$HOME/.local/share/wispdeck-release/release.key" \
  --public release/release.pub
gh secret set WISPDECK_RELEASE_PRIVATE_KEY \
  < "$HOME/.local/share/wispdeck-release/release.key"
```

Never commit the private key. Keep a separate encrypted backup because a lost
key requires a deliberate transition release before existing installations can
trust a replacement. The public key is deliberately committed and distributed
inside every release binary.

Create and push a release tag from a clean `main` checkout:

```sh
git tag -a v0.2.0 -m "Wispdeck v0.2.0"
git push origin v0.2.0
```

The latest published release exposes its signed manifest at
`https://github.com/OWNER/REPOSITORY/releases/latest/download/stable.json`.
Release binaries use that URL by default, while `--update-manifest-url` and
`--update-public-key-file` remain available for independently hosted release
streams.

## Production preflight

Run `doctor` as the same service account, with the same paths and origin flags
that `serve` will use, after initial state has been bootstrapped and before the
first public start, and again after changing the deployment layout:

```sh
./wispdeck doctor \
  --app-origin https://wispdeck.example.com \
  --site-domain wispdeck.example.com \
  --preview-domain preview.wispdeck.example.com \
  --trusted-proxy 127.0.0.1/32 \
  --database /var/lib/wispdeck/wispdeck.db \
  --wispist-data /var/lib/wispdeck/wispist \
  --auth-key /var/lib/wispdeck/auth.key \
  --update-data /var/lib/wispdeck/updates
```

The command rejects development or incompletely identified binaries, HTTP
origins, invalid origin boundaries, unsafe trusted-proxy entries, state parents
writable by other users, unsafe state files, incompatible or corrupt SQLite
databases, overlapping update storage, incomplete signing configuration, and
executables that cannot be atomically replaced. It reads SQLite state in
query-only mode.
The update activation check creates, exchanges, and removes two temporary files
beside the configured executable; this deliberately tests the real filesystem
and service-account permissions.

Warnings do not make the command fail. A missing Wispist directory is a warning
because it is created on first use, and omitting trusted proxies is valid when
Wispdeck is directly exposed. `--json` provides a stable machine-readable
report. `doctor` does not make network requests and therefore does not replace
checks for DNS, certificates, reverse-proxy routing, manifest availability, or
the live `/healthz` endpoint.

## Fresh-install bootstrap

If both the configured control database and authentication key are absent,
`serve` creates them with service-account-only permissions. It logs an initial
setup URL and a random six-character setup code, and the application origin
redirects to that wizard until the first superuser is created. The code changes
when an uninitialized server restarts. Treat it as a password and do not forward
startup logs to an audience that should not control the installation.

The key is generated only when the database path is absent. If a database
exists without its original key, startup fails and requires restoration of a
complete backup. This prevents a missing key from silently making encrypted
credentials and peppered password hashes unusable. Operators who do not want a
browser bootstrap can continue to run `auth-key generate` and `admin create`
before `serve`.

## Tagged updates

The default policy is **Notify me**. Wispdeck checks 15 seconds after a healthy
start and every six hours thereafter. A superuser sees an **Update available**
banner and can review, install, or skip that version under **Settings →
Updates**. **Automatic** installs a discovered stable release; **Disabled**
makes no release-source requests. Policy and skipped-version changes survive
restarts. A superuser can also request an immediate check. Ordinary users do
not see or control update state.

The release source is provider-independent: an HTTPS URL serves a small JSON
envelope containing an exact signed manifest. The embedded Ed25519 public key
authenticates the manifest; each platform asset is then authenticated by its
signed byte length and SHA-256 digest. Redirects remain HTTPS and are bounded.
Before activation, Wispdeck runs the staged binary's `version --json` command
with a minimal environment and requires it to identify as the signed version.

An installation can supply configuration at runtime instead of embedding it:

```sh
./wispdeck serve \
  --app-origin https://wispdeck.example.com \
  --update-manifest-url https://downloads.example.com/wispdeck/stable.json \
  --update-public-key-file /etc/wispdeck/release.pub
```

The manifest URL and public key must be configured together. The public-key
file must be a small regular file. HTTP release URLs are accepted only in
loopback-only `--development` mode. `--update-data` defaults to `updates`
beside the control database and cannot overlap the database, authentication
key, or Wispist state.

### Activation and rollback

Installing an update performs these steps:

1. Gracefully stop accepting requests and close all databases.
2. Take an owner-only, verified backup of the complete installation state.
3. Copy the verified candidate beside the running executable and atomically
   exchange the two files on Linux.
4. Replace the current process with the new binary, preserving its arguments
   and environment.
5. Probe the new listener's `/healthz` locally. Only then remove the recovery
   marker and prior executable.

Any ordinary startup or readiness failure restores both the prior executable
and the pre-update state, then starts the prior version. A machine or process
crash during activation leaves a durable recovery marker. Configure the
service manager to restart Wispdeck after failure: the next start either
finishes verification or rolls back. Recovery explicitly handles a crash on
either side of the atomic exchange. Pre-update archives are retained beneath
`--update-data`. Wispdeck keeps the newest three verified pre-update backups and
the newest three verified platform downloads by default. Configure the limits
with `--retained-update-backups` and `--retained-update-downloads` (each accepts
1 through 100). Cleanup runs on a normal startup and after a successful update.
Incomplete download files older than 24 hours are removed; unrecognized files
are left untouched.

Activation currently requires Linux, a filesystem that supports atomic
`RENAME_EXCHANGE`, and write permission in the executable's parent directory.
Keep the executable on a normal local filesystem and run one Wispdeck process
per installation. The installation lock prevents update backup/restore from
racing another server or an offline administrative command.

### Signing a release

Build the release helper and create a signing key once. Neither output may
already exist:

```sh
go build -trimpath -o wispdeck-release ./cmd/wispdeck-release
install -d -m 700 release-secrets release-out
./wispdeck-release keygen \
  --private release-secrets/release.key \
  --public release-out/release.pub
```

Keep `release.key` offline or in a protected CI secret; never place it in the
repository or on a Wispdeck server. The public key is safe to distribute and
must be embedded in, or configured for, every binary that trusts the release
stream.

Build every advertised asset with identical version metadata, upload the
assets to their final HTTPS URLs, write UTF-8 release notes, and create the
signed stable manifest:

```sh
./wispdeck-release manifest \
  --private-key release-secrets/release.key \
  --version v0.2.0 \
  --notes release-notes.txt \
  --asset linux/amd64,release-out/wispdeck-linux-amd64,https://downloads.example.com/wispdeck/v0.2.0/wispdeck-linux-amd64 \
  --asset linux/arm64,release-out/wispdeck-linux-arm64,https://downloads.example.com/wispdeck/v0.2.0/wispdeck-linux-arm64 \
  --output release-out/stable.json
```

Publish `stable.json` at the configured manifest URL only after every asset is
available. The helper rejects non-stable versions, insecure asset URLs,
duplicate platforms, unsuitable files, oversized notes/assets, and a signing
key readable by group or other users. It refuses to overwrite a manifest.

Key rotation needs two manifest URLs because v1 trusts one key at a time. Keep
the old URL signed by the old key and make it offer a transition release. That
release must embed both the new public key and a new manifest URL. Publish later
releases at the new URL under the new key, while retaining the old stream and
transition assets for installations that were offline during the rotation.

## Health check

`GET /healthz` and `HEAD /healthz` return `200 OK` with `ok` after Wispdeck has
loaded its installation key, opened and migrated the control database,
initialized Wispist, and bound the HTTP listener. The response contains no
deployment details and is never cacheable.

The endpoint is recognized on the configured application host and on direct
loopback hosts such as `127.0.0.1`. This permits both an ingress check and a
local post-update check:

```sh
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
```

A hosted site's `/healthz` remains ordinary site content. `healthz` is a
reserved public name, so a short link or site cannot shadow the application
endpoint.

## State retention

Wispdeck runs maintenance transactionally at startup and every six hours. It
removes expired sessions, login transactions, WebAuthn ceremonies, TOTP
enrollments, user-setup tokens, and site-preview grants and sessions.
Authentication audit events are retained for 90 days and capped at the newest
100,000 records by default. Use `--auth-event-retention-days` (1 through 3,650)
and `--max-auth-events` (1 through 10,000,000) to change those bounds.

Failed sign-ins for real accounts remain audit events. Attempts against unknown
usernames follow the same dummy-password verification path and generic response
but are not persisted, so the unauthenticated login endpoint cannot be used to
grow the database with arbitrary account names.

## Offline backup and restore

Wispdeck's state is one unit: the control database, the installation
authentication key, and every Wispist database must be preserved together.
The built-in backup format records SHA-256 digests for every file and includes
SQLite WAL files when present.

Stop Wispdeck, then create an owner-only archive at a new path:

```sh
./wispdeck backup create --output /srv/backups/wispdeck-2026-07-22.tar.gz
```

The command refuses to overwrite an existing archive. The server holds an
exclusive installation lock for its lifetime, so backup, restore, and local
account-recovery commands fail rather than racing live database activity.

To restore, stop Wispdeck and provide explicit destructive confirmation:

```sh
./wispdeck backup restore \
  --input /srv/backups/wispdeck-2026-07-22.tar.gz \
  --yes
```

Restore extracts into a private staging directory and validates the complete
manifest, checksums, authentication key, SQLite integrity, foreign keys, and
schema compatibility before changing installation state. It stages all
replacement files beside their destinations and retains the prior state for
automatic rollback if an ordinary replacement operation fails. Start Wispdeck
and verify `/healthz` after the restore.

If state paths were customized when serving, pass the same `--database`,
`--wispist-data`, and `--auth-key` values to both backup and restore. Keep
archives encrypted at rest and access-controlled: they contain password hashes,
account metadata, hosted content, shared site data, and the key that protects
authentication secrets.
