# Install the CLI

The `scopuli` CLI talks to your vault: login, create secrets, issue agent keys, read the audit log. Prebuilt binaries are published for macOS and Linux on every release.

## One-liner (macOS / Linux)

```bash
curl -sSL https://lucaspdude.github.io/scopuli/install.sh | bash
```

The script:

1. Detects your OS and architecture (`uname -s` / `uname -m`).
2. Downloads the matching `scopuli-{os}-{arch}.tar.gz` from the [latest release](https://github.com/lucaspdude/scopuli/releases/latest).
3. **Verifies the SHA-256 checksum** published alongside the tarball.
4. Installs to `/usr/local/bin` (with `sudo` if needed), falling back to `~/.local/bin`.

Re-running the script upgrades in place.

### Options

| Environment variable | Default | Purpose |
|---|---|---|
| `SCOPULI_VERSION` | `latest` | Install a specific tag, e.g. `SCOPULI_VERSION=v0.1.2` |
| `SCOPULI_DEST` | `/usr/local/bin` or `~/.local/bin` | Install directory |

```bash
# example: pin a version into a custom dir
SCOPULI_VERSION=v0.1.2 SCOPULI_DEST=~/bin \
  curl -sSL https://lucaspdude.github.io/scopuli/install.sh | bash
```

!!! note "~/.local/bin not found?"
    If the script installs to `~/.local/bin`, make sure it's on your `PATH`:
    `export PATH="$HOME/.local/bin:$PATH"` (add to your shell profile).

## Manual download

Grab the tarball for your platform from the [latest release](https://github.com/lucaspdude/scopuli/releases/latest):

| OS | Arch | Asset |
|---|---|---|
| Linux | amd64 | `scopuli-linux-amd64.tar.gz` |
| Linux | arm64 | `scopuli-linux-arm64.tar.gz` |
| macOS | amd64 (Intel) | `scopuli-darwin-amd64.tar.gz` |
| macOS | arm64 (Apple Silicon) | `scopuli-darwin-arm64.tar.gz` |

```bash
# example: macOS Apple Silicon
tar xzf scopuli-darwin-arm64.tar.gz
sudo mv scopuli-darwin-arm64 /usr/local/bin/scopuli
```

Every asset has a `.sha256` sidecar — verify before installing:

```bash
sha256sum -c scopuli-darwin-arm64.tar.gz.sha256   # macOS: shasum -a 256 -c
```

## Build from source

Requires Go (see `go.mod` for the toolchain version):

```bash
git clone https://github.com/lucaspdude/scopuli
cd scopuli
make build           # ./bin/scopuli
make smoke           # end-to-end test against the local binary
```

## Verify it works

```bash
scopuli version
```

Next: [deploy the vault locally](deploy-local.md) or [on a VPS](deploy-vps.md).
