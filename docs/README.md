# scopuli — planning docs

This folder is the planning + research artifact for the V0 (MVP) of `scopuli`.

> No code yet. We're in the **research & planning phase**. Once you've reviewed these docs and answered the decisions in [`DECISIONS.md`](./DECISIONS.md), we'll start implementation.

| File | Purpose |
|---|---|
| [`PLAN.md`](./PLAN.md) | MVP plan: what V0 is, what it isn't, must-haves, user flows, delivery plan. |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | How V0 is built: components, request flows, schema, deployment, config. |
| [`SECURITY.md`](./SECURITY.md) | Threat model, cryptographic design, audit chain, hardening checklist. |
| [`RESEARCH.md`](./RESEARCH.md) | Working notes from the research phase — sources read and why we picked what we picked. |
| [`DECISIONS.md`](./DECISIONS.md) | Decision log: every decision made during planning, with rationale. |
| [`PI-EXTENSION.md`](./PI-EXTENSION.md) | Plan for the `pi-coding-agent` extension (@scopuli/pi-extension). Status bar in V0 of the extension. |

## What's here

| Doc | What it covers |
|---|---|
| [`PLAN.md`](./PLAN.md) | MVP scope, must-haves, non-goals, user flows, delivery plan. The starting point. |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | Components, request flows, data model, deployment topology, config reference. |
| [`SECURITY.md`](./SECURITY.md) | Threat model, cryptographic design, key hierarchy, auth, audit log integrity, hardening checklist, rotation, backup/recovery. |
| [`RESEARCH.md`](./RESEARCH.md) | Working notes from the research phase — sources read and why we picked what we picked. |
| [`DECISIONS.md`](./DECISIONS.md) | The questions you need to answer before code is written. |

## Recommended reading order

1. [`PLAN.md`](./PLAN.md) — get the scope.
2. [`DECISIONS.md`](./DECISIONS.md) — flag anything you want to change.
3. [`ARCHITECTURE.md`](./ARCHITECTURE.md) — how the thing is built.
4. [`SECURITY.md`](./SECURITY.md) — why the crypto choices are what they are.
5. [`RESEARCH.md`](./RESEARCH.md) — only if you want the citations.

## TL;DR

- Single Docker container, Go binary, SQLCipher-encrypted SQLite.
- Master password via env var (`MASTER_PASSWORD`); Argon2id KDF on boot.
- AES-256-GCM for every secret value, keyed off the master-derived KEK.
- Agent API keys are scoped (`aws/dev/*` globs) and revocable; stored as SHA-256 hash only.
- Every read/write/deny is appended to a hash-chained + HMAC-signed audit log.
- Agents consume secrets via a CLI that doubles as an MCP server over stdio (so Claude Code / Cursor / OpenHands can call tools natively).
- Barebones web UI is optional — see D2.