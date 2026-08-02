# scopuli

> Self-hosted credential vault for sharing scoped secrets with agents and humans.

**Status: planning phase. No code yet.**

Read the planning docs in [`docs/`](./docs/) — start with [`docs/PLAN.md`](./docs/PLAN.md), then answer the open questions in [`docs/DECISIONS.md`](./docs/DECISIONS.md).

## TL;DR

A single Docker container (Go binary + SQLCipher-encrypted SQLite) that you run on your homelab LXC. You set a master password via `MASTER_PASSWORD` env var, create secrets over a CLI (or a barebones web UI), issue scoped revocable API keys to your agents, and agents pull secrets via the CLI or as MCP tools. Every read/write/deny is recorded in a tamper-evident audit log.

```
# not yet runnable; this is what the first run will look like
docker run -d \
  -e MASTER_PASSWORD=... \
  -v scopuli-data:/data \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/lucaspdude/scopuli:v0
```

See [`docs/`](./docs/) for the full plan. The plan covers:

- **Encrypted secrets** with per-key AES-256-GCM, KEK derived from a master password via Argon2id.
- **Scoped, revocable agent keys** — each key only sees secrets inside its glob scope.
- **Tags + descriptions + structured metadata** on keys and secrets, so LLM agents understand context before reaching for a value.
- **Full-text search** over descriptions and metadata (SQLite FTS5).
- **MCP server** exposing the vault as JSON-RPC 2.0 tools over stdio.
- **Append-only audit log** with SHA-256 hash chain + HMAC-SHA-256, signed by a master-password-derived key.
- **`pi-coding-agent` extension** under `extensions/pi/` (status bar in V0 of the extension). See [`docs/PI-EXTENSION.md`](./docs/PI-EXTENSION.md).