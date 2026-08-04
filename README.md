# scopuli

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Latest release](https://img.shields.io/github/v/release/lucaspdude/scopuli)](https://github.com/lucaspdude/scopuli/releases/latest)
[![Docs](https://img.shields.io/badge/docs-lucaspdude.github.io%2Fscopuli-blue)](https://lucaspdude.github.io/scopuli/)

> Self-hosted credential vault for sharing scoped secrets with agents and humans.

**Documentation: <https://lucaspdude.github.io/scopuli/>** — CLI install, local Docker deploy, VPS deploy, and the security model.

## Install

### One-liner (macOS / Linux)

```bash
curl -sSL https://lucaspdude.github.io/scopuli/install.sh | bash
```

Detects your OS/arch, verifies the SHA-256 checksum, and installs the latest `scopuli` release into `/usr/local/bin` (or `~/.local/bin` if no sudo). Re-running upgrades in place.

### Manual download

Grab the tarball that matches your OS/arch from the [latest release](https://github.com/lucaspdude/scopuli/releases/latest):

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
scopuli version
```

### Docker

Pull the prebuilt image and run the server:

```bash
docker pull ghcr.io/lucaspdude/scopuli:latest
docker run -d \
  --name scopuli \
  -e MASTER_PASSWORD=$(openssl rand -hex 32) \
  -v scopuli-data:/data \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/lucaspdude/scopuli:latest
```

On first boot the server prints the operator token to logs — capture it once:

```bash
docker logs scopuli | grep scot_live_
scopuli login http://127.0.0.1:8080 --token scot_live_...
```

For an always-on setup behind HTTPS, see the [VPS deploy guide](https://lucaspdude.github.io/scopuli/deploy-vps/).

### Build from source

```bash
git clone https://github.com/lucaspdude/scopuli
cd scopuli
make build           # ./bin/scopuli
make smoke           # end-to-end test against a local binary
make smoke-docker    # end-to-end test against a built Docker image
```

## What it does

A single Go binary (CLI + daemon + MCP server) backed by a SQLCipher-encrypted SQLite database. You set a master password via `MASTER_PASSWORD` env var, create secrets over the CLI, issue scoped revocable API keys to your agents, and agents pull secrets via the CLI or as MCP tools. Every read/write/deny is recorded in a tamper-evident audit log.

Highlights:

- **Encrypted secrets** with per-key AES-256-GCM, KEK derived from a master password via Argon2id.
- **Scoped, revocable agent keys** — each key only sees secrets inside its glob scope.
- **Tags + descriptions + structured metadata** on keys and secrets, so LLM agents understand context before reaching for a value.
- **Full-text search** over descriptions and metadata (SQLite FTS5).
- **MCP server** exposing the vault as JSON-RPC 2.0 tools over stdio.
- **Append-only audit log** with SHA-256 hash chain + HMAC-SHA-256, signed by a master-password-derived key.
- **`pi-coding-agent` extension** under `extensions/pi/` (status bar in V0 of the extension).

## Built with AI

scopuli is openly **vibe-coded**: most of the code was written by LLM coding agents working from human-written design docs (threat model, architecture, delivery plan). The design decisions, security posture, and review are human-owned. The planning docs are kept outside the public repo; the [security model](https://lucaspdude.github.io/scopuli/security/) documents the guarantees the code must uphold — audit accordingly.

## Releases

This project uses [release-please](https://github.com/googleapis/release-please)-style auto-releases via GitHub Actions:

- Merge a PR to `main` with `[release]` in the merge commit → auto-creates a release (bumps patch by default).
- Use `[release minor]` or `[release major]` for non-patch bumps.
- Use `[release vX.Y.Z]` for an explicit version.
- The release publishes the multi-arch Docker image to `ghcr.io/lucaspdude/scopuli` and attaches CLI binaries for macOS and Linux to the release.

## Security

See [SECURITY.md](./SECURITY.md) for the disclosure policy and the [security model](https://lucaspdude.github.io/scopuli/security/) for the threat model in plain terms. Only the latest release receives security fixes.
