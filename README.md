# cred-share

> Self-hosted credential vault for sharing scoped secrets with agents and humans.

**Status: planning phase. No code yet.**

Read the planning docs in [`docs/`](./docs/) — start with [`docs/PLAN.md`](./docs/PLAN.md), then answer the open questions in [`docs/DECISIONS.md`](./docs/DECISIONS.md).

## TL;DR

A single Docker container (Go binary + SQLCipher-encrypted SQLite) that you run on your homelab LXC. You set a master password via `MASTER_PASSWORD` env var, create secrets over a CLI (or a barebones web UI), issue scoped revocable API keys to your agents, and agents pull secrets via the CLI or as MCP tools. Every read/write/deny is recorded in a tamper-evident audit log.

```
# not yet runnable; this is what the first run will look like
docker run -d \
  -e MASTER_PASSWORD=... \
  -v cred-share-data:/data \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/lucaspdude/cred-share:v0
```

See [`docs/`](./docs/) for the full plan.