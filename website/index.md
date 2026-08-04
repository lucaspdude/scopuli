# scopuli

**Self-hosted credential vault for sharing scoped secrets with agents and humans.**

A single Go binary (CLI + daemon + MCP server) backed by a SQLCipher-encrypted SQLite database. You set a master password, create secrets over the CLI, issue scoped revocable API keys to your agents, and agents pull secrets via the CLI or as MCP tools. Every read, write, and denial is recorded in a tamper-evident audit log.

## Highlights

- **Encrypted secrets** — per-secret AES-256-GCM, key-encryption-key derived from your master password via Argon2id.
- **Scoped, revocable agent keys** — each key only sees secrets inside its glob scope, with `read` or `manage` permission.
- **Tags, descriptions, structured metadata** — so LLM agents understand context before reaching for a value.
- **Full-text search** over descriptions and metadata (SQLite FTS5).
- **MCP server** exposing the vault as JSON-RPC 2.0 tools over stdio.
- **Tamper-evident audit log** — append-only, SHA-256 hash chain + HMAC-SHA-256, verifiable with `scopuli audit verify`.

## Get started

- [Install the CLI](install.md) — one-liner for macOS and Linux.
- [Deploy locally (Docker)](deploy-local.md) — vault on your own machine in two minutes.
- [Deploy on a VPS](deploy-vps.md) — always-on vault behind HTTPS with Caddy.

Quick taste:

```bash
# 1. Install the CLI
curl -sSL https://lucaspdude.github.io/scopuli/install.sh | bash

# 2. Run the vault
docker run -d --name scopuli \
  -e MASTER_PASSWORD=$(openssl rand -hex 32) \
  -v scopuli-data:/data \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/lucaspdude/scopuli:latest

# 3. Capture the operator token (printed once, on first boot)
docker logs scopuli | grep scot_live_

# 4. Log in and store your first secret
scopuli login http://127.0.0.1:8080 --token scot_live_...
scopuli secret set example/hello --value world --description "my first secret"
```

## Built with AI

scopuli was **entirely architected and built with AI** — design, threat model, code, tests, and these docs were produced by LLM coding agents under human direction and review. This is disclosed deliberately. The planning docs are kept private; treat the [security model](security.md) as the contract and audit the code accordingly.

## Project status

Pre-1.0. The V0 feature set is complete and covered by end-to-end smoke tests; expect breaking CLI changes before 1.0. Releases are automated from `main` and published on [GitHub Releases](https://github.com/lucaspdude/scopuli/releases).
