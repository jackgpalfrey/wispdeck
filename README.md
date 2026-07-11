# Wispdeck

Wispdeck is a self-hosted home for links and lightweight websites that wake on
demand.

The project is at the beginning of its implementation. The first implemented
slice is the administrative authentication boundary. See
[`docs/security-model.md`](docs/security-model.md) for the assumptions that
shape it.

## Development

The supported toolchain is Go 1.26.5 or newer. Earlier Go 1.26 patch releases
contain standard-library vulnerabilities reachable by an HTTP application.

```sh
go test ./...
go vet ./...
```

Create the first local administrator without putting a password in shell
history:

```sh
go build -o wispdeck ./cmd/wispdeck
./wispdeck admin create --username admin
```

For a production deployment, terminate TLS at a reverse proxy that preserves
the original `Host` header, then provide the exact public admin origin:

```sh
./wispdeck serve --admin-origin https://admin.example.com
```

The admin origin must not serve hosted user content. `--development` permits
HTTP and insecurely transported cookies for local testing and must never be
enabled on a public listener.
