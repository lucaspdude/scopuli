# scopuli — MVP Plan (V0)

> **Status:** research + planning phase (decisions taken inline via `grill-with-docs`).
> **Reading order:** [`PLAN.md`](./PLAN.md) → [`ARCHITECTURE.md`](./ARCHITECTURE.md) → [`SECURITY.md`](./SECURITY.md) → [`RESEARCH.md`](./RESEARCH.md). Decisions are recorded in `DECISIONS.md`.

---

## 1. Problem statement

Build a self-hostable service that lets a single operator store credentials ("secrets") and share subsets of them with autonomous agents, with:

- A **master password** held by the operator (env var, never sent over the wire).
- An **operator token** (the actual auth credential) used by the CLI from any host.
- **Scoped, revocable agent keys** — each key can only see / mutate secrets within its scope.
- An **append-only audit log** of every secret read, write, deny, and key event.
- Two ways for agents to consume secrets: a **CLI** and an **MCP server** (same binary, stdio transport).
- Safe to expose to any network — LAN or public — because the auth model never depends on the master password crossing the boundary.

## 2. Non-goals (V0)

Anything below is **not** in V0. If we add them, they go on the V1 list.

| Out of scope (V0) | Why |
|---|---|
| Web UI / session cookies | Operator uses the CLI. Web UI is V1 if at all. |
| Multi-user / RBAC matrix | Single operator; everywhere else is an agent. |
| Secret versioning, history, rollback | Audit log gives "who read what" but not "what did the secret used to be". Description change trivially re-encrypts (new AAD), so accidental description edits are recoverable from the audit log. |
| Replication, HA, clustering | Single-instance homelab target. |
| HSM / KMS / Shamir shards | Master password is the root key. Auto-unseal is V1. |
| Dynamic secrets | Static creds only. |
| Secret rotation policies / auto-expiry | Manual rotation in V0. |
| OAuth / OIDC / SSO | Single-operator auth. |
| 2FA / passkeys | V1. |
| TLS termination in the Go server | Operator runs a reverse proxy (Caddy / Nginx) in front. Documented but not in the binary. |
| Streamable HTTP MCP | V0 is stdio MCP, with the CLI binary local to each host that wants to use it. Remote / multi-host MCP is V1. |
| Webhooks for revocation events | Manual `scopuli keys revoke` for now. |
| pi extension `v0.1` features (slash commands, tools) | V0 of the extension is status-bar only. |
| pi extension: `secret set` / `key create` from agent | The extension is read-mostly; mutation goes through the CLI. |

## 3. MVP must-haves

1. **Runs with `docker run` or `docker compose up`.** Single container, SQLite database file persisted on a volume.
2. **Master password via environment variable** (`MASTER_PASSWORD`). Used at boot to derive the KEK. Never sent over the wire.
3. **Operator token** generated at first boot, printed once to stdout, stored as SHA-256 hash in the DB. The CLI uses this token for all operator actions.
4. **Encrypted-at-rest SQLite database.** SQLCipher. KEK derived from the master password; secrets are encrypted before being written.
5. **CLI** (`scopuli …`) for the operator. Day-to-day management is via the CLI.
6. **Scoped, revocable agent keys.** Create a key, name it, grant a scope (slash-path globs like `aws/dev/*`) and a permission (`read` or `manage`). Optional expiry.
7. **Server-side scope enforcement.** Every secret request checks the key's scope against the target path. Deny is logged.
8. **Per-key audit view.** Each agent key can see its own activity (read/write/error counts, recent requests). The operator sees the full log.
9. **Append-only audit log** with SHA-256 hash chain + HMAC-SHA-256, signed by a key derived from the master password. `scopuli audit verify` walks the chain.
10. **Keys can be revoked instantly.** The next request from a revoked key returns 401.
11. **Agents consume secrets via CLI or MCP.** The CLI binary is local to each host that wants to use it. The MCP server (`scopuli mcp-serve`) speaks JSON-RPC 2.0 over stdio, exposing `list_secrets`, `get_secret`, `set_secret`, `delete_secret`, `search_secrets`, `search_keys`, `list_keys`, `annotate_secret`, `annotate_key` as tools.
12. **Encrypted export bundle.** `scopuli snapshot --out bundle.age` produces an `age`-encrypted backup. `scopuli restore --in bundle.age` restores it.
13. **Metadata on keys and secrets.** Every resource carries `tags` (CSV, ≤20 entries, 64 chars each), `description` (Markdown, ≤8 KB), and `metadata` (JSON object, ≤32 pairs, key 64 chars, value 256 chars). Set on create/update; edit incrementally via `scopuli secret annotate` / `scopuli keys update`. Metadata is always included in MCP tool responses so LLM agents get context, not just values.
14. **Full-text search.** SQLite FTS5 (`unicode61` tokenizer, BM25 ranking). Indexes `description` and flattened metadata. `scopuli secret search <q>`, `scopuli keys search <q>`, plus the equivalent MCP tools. Triggers keep the FTS tables in sync.
15. **pi-coding-agent extension (status bar only).** TypeScript package `@scopuli/pi-extension` installs into the pi UI and surfaces a status bar item such as `🔒 scopuli: up · 4 keys · scope read`. No slash commands, no tools exposed to the agent in V0. Credentials auto-detected from `SCOPULI_URL` / `SCOPULI_KEY` env vars or macOS Keychain. See [`docs/PI-EXTENSION.md`](./PI-EXTENSION.md).

## 4. User flows

### 4.1 First boot

```
docker run -d \
  -e MASTER_PASSWORD=<long-random-string> \
  -v scopuli-data:/data \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/lucaspdude/scopuli:v0
```

Server logs include exactly once:

```
[INFO]  vault initialized
[INFO]  operator token (save to your password manager): scot_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

The hash is stored in the `operators` table; the plaintext is never written again.

### 4.2 Operator: log in from the Mac

```bash
scopuli login https://vault.example.com --token scot_live_…
# stores token in macOS Keychain / Linux secret service
```

### 4.3 Operator: create a secret

```bash
echo "sk_live_…" | scopuli secret set aws/prod/stripe_key \
  --value-from-stdin \
  --label "Stripe production key" \
  --tag aws --tag prod --tag stripe \
  --description "Production Stripe secret key. Used by the checkout API." \
  --meta owner_email=billing@example.com \
  --meta cost_center=eng-42

scopuli secret set github/lucas/pat --value-from-file ~/.pat
scopuli secret list                   # paths + labels + tags + description
scopuli secret get aws/prod/stripe_key
```

### 4.3.1 Operator: annotate a secret (incremental metadata edit)

```bash
scopuli secret annotate aws/prod/stripe_key \
  --add-tag deprecated \
  --remove-tag prod \
  --description "ROTATED 2025-08-15. Use aws/prod/stripe_key_v2 instead." \
  --set-meta rotated_at=2025-08-15 \
  --unset-meta cost_center
# AAD re-computes (description changed), version is bumped, ciphertext re-stored.
# Audit row: secret.annotate path=aws/prod/stripe_key fields=[…]
```

### 4.3.2 Operator: search

```bash
scopuli secret search "rotated stripe"            # BM25 across description + metadata
scopuli keys search "linus"                       # BM25 across name + description + metadata
scopuli secret list --tag aws --tag prod          # filter by ALL tags (AND)
scopuli keys list --tag oncall --query "prod"     # tag filter + FTS query
```

### 4.4 Operator: create a scoped agent key

```bash
scopuli keys create linus-dev \
  --scope "aws/dev/*,github/lucas/pat" \
  --permission read \
  --tag dev --tag linus \
  --description "Dev key for Linus's sandbox builds. Scoped to non-prod AWS + Lucas's personal GitHub." \
  --meta owner_email=lucas@example.com
# prints: sk_live_<base62 body>_<sRC4k1 checksum>
# shown ONCE — operator copies it into the agent's env
```

### 4.4.1 Operator: update a key's metadata

```bash
scopuli keys update linus-dev \
  --add-tag oncall \
  --description "Now also covers oncall rotation. Scope unchanged."
scopuli keys update linus-dev --permission manage       # promote: read → manage
scopuli keys update linus-dev --expires-in 90d           # extend expiry
scopuli keys update linus-dev --scope "aws/dev/*,aws/staging/*"  # widen scope
```

### 4.5 Agent: read a secret

```bash
# On the agent's host
export SCOPULI_URL=https://vault.example.com
export SCOPULI_KEY=sk_live_<…>_sRC4k1
STRIPE_KEY=$(scopuli get aws/dev/stripe_key)
```

Or via MCP:

```jsonc
// tool call from the LLM runtime
{"tool": "get_secret", "args": {"path": "aws/dev/stripe_key"}}
```

### 4.6 Operator: revoke a key

```bash
scopuli keys revoke linus-dev
# Server marks the key revoked. The next request from that key returns 401.
# Audit log records the revoke event with the operator's session.
```

### 4.7 Operator: rotate the operator token (if lost)

```bash
# Inside the LXC
docker exec -it scopuli scopuli operator rotate --from-env MASTER_PASSWORD
# prints the new token (and instructs the operator to re-login on every host)
```

### 4.8 Operator: encrypted backup

```bash
scopuli snapshot --out /backups/vault-2025-01-01.age
# prompts for an age passphrase; writes the bundle
```

Restore is a separate environment (new container) running:

```bash
scopuli restore --in /backups/vault-2025-01-01.age --into /data/vault.db
```

## 5. Component overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                       Operator's Mac (or any host)                       │
│   ┌────────────────────────────┐                                         │
│   │  scopuli CLI / MCP      │                                         │
│   │  (reads token from Keychain│                                         │
│   │   or secret service)       │                                         │
│   └─────────────┬──────────────┘                                         │
└─────────────────┼────────────────────────────────────────────────────────┘
                  │ HTTPS over Caddy/Nginx (TLS terminated by reverse proxy)
                  │ X-Scopuli-Operator: scot_…
                  │   or X-Scopuli-Key: sk_live_…
┌─────────────────▼────────────────────────────────────────────────────────┐
│ scopuli container (Docker on LXC / VPS)                               │
│                                                                          │
│   ┌──────────────────────┐                                                │
│   │ HTTP layer (chi)     │                                                │
│   ├──────────────────────┤                                                │
│   │ Auth middleware      │                                                │
│   │   - operator token   │                                                │
│   │   - agent key        │                                                │
│   ├──────────────────────┤                                                │
│   │ Scope enforcer       │                                                │
│   ├──────────────────────┤                                                │
│   │ Audit logger         │                                                │
│   ├──────────────────────┤                                                │
│   │ Crypto module        │                                                │
│   │   - Argon2id (KEK)   │                                                │
│   │   - AES-256-GCM (AEAD│                                                │
│   │   - SHA-256 hash chain│                                              │
│   │   - HMAC-SHA-256     │                                                │
│   ├──────────────────────┤                                                │
│   │ SQLCipher repository │                                                │
│   └──────────┬───────────┘                                                │
│              │                                                            │
│   ┌──────────▼───────────┐                                                │
│   │ /data/vault.db       │                                                │
│   │ (SQLCipher, AES-256) │                                                │
│   └──────────────────────┘                                                │
└──────────────────────────────────────────────────────────────────────────┘
```

Three actors:
- **Operator** — owns the master password and the operator token. Creates secrets, creates/revokes agent keys, reads audit log.
- **Agent** — holds an API key, only sees secrets within scope. May be an LLM runtime, a cron job, or another tool.
- **Server** — holds the SQLCipher file, performs KDF + AEAD, enforces scope, logs every action.

## 6. Data model

| Table | Columns (abridged) |
|---|---|
| `meta` | `k TEXT PK, v BLOB` — `schema_version`, `kdf_salt`, `kdf_params`, `hmac_key_salt`, `hmac_key` (encrypted), `kek_check` |
| `operators` | `id INTEGER PK, name TEXT UNIQUE, hash TEXT, prefix TEXT, created_at, last_used_at` |
| `secrets` | `id INTEGER PK, path TEXT UNIQUE, label TEXT, ciphertext BLOB, nonce BLOB, aad BLOB, tags TEXT, description TEXT, metadata TEXT, created_at, updated_at, description_updated_at, metadata_updated_at, version` |
| `keys` | `id INTEGER PK, name TEXT UNIQUE, hash TEXT, prefix TEXT, scope TEXT, permissions TEXT, tags TEXT, description TEXT, metadata TEXT, created_at, expires_at, revoked_at, last_used_at, description_updated_at, metadata_updated_at` |
| `secrets_fts` (FTS5) | `path, description, metadata_text` (kept in sync by triggers) |
| `keys_fts` (FTS5) | `name, description, metadata_text` (kept in sync by triggers) |
| `audit` | `id INTEGER PK, ts INTEGER, actor_kind TEXT, actor_id INTEGER, action TEXT, path TEXT, result TEXT, prev_hash BLOB, hash BLOB, hmac BLOB` |

Full schema, indexes, and SQLCipher pragmas: see `ARCHITECTURE.md` §4.

`actor_kind` is `'operator'` or `'key'`. The `audit` view for an agent key filters by `actor_kind='key' AND actor_id=<self>`.

## 7. Delivery plan (V0)

Each step is independently demoable.

1. **Scaffolding.** Repo, Dockerfile, docker-compose, CI smoke test that boots the container with a master password, exposes `/healthz`, exits cleanly when password is missing.
2. **Storage + crypto.** SQLCipher integration. `secrets` table CRUD. Argon2id KDF, AES-256-GCM per-secret encryption. Unit tests with a fixed test vector.
3. **First-boot + operator token.** Detect fresh DB, generate operator token, print to stdout, store hash. `scopuli login` on the CLI uses the keychain/secret-service backend.
4. **HTTP API + scope enforcement.** Master session via operator token. `/api/secrets` endpoints with scope check on every request. Audit log row appended for every action.
5. **Agent keys.** `keys` table CRUD, key generation, hash+prefix storage, `X-Scopuli-Key` auth middleware, scope check.
6. **CLI.** Single Go binary. `login`, `secret get/set/list/delete/search/annotate`, `keys create/list/revoke/get/update/search`, `operator rotate`, `audit list/verify`, `snapshot`, `restore`, `mcp-serve`.
7. **MCP server mode.** `scopuli mcp-serve` starts an MCP server over stdio exposing the same tools as the CLI subcommands. JSON-RPC 2.0 per the [MCP spec](https://modelcontextprotocol.io/specification/2025-06-18/server/tools).
8. **Encrypted export.** `snapshot` and `restore` using `age` (filippo.io/age) with a passphrase-derived key.
9. **Documentation.** `README.md` with quickstart, `docs/OPERATIONS.md` covering backup / restore / key rotation / token rotation.
10. **Hardening pass.** Run through the `SECURITY.md` checklist. Add rate limiting, lockout, request size limits, dependency audit in CI.
11. **Metadata + annotate.** Extend `secrets` and `keys` tables with `tags` / `description` / `metadata`. `set_secret` and `keys create` accept these fields. `scopuli secret annotate` and `scopuli keys update` provide incremental edits. Re-encrypt on description change (AAD includes description). Validation per D18/D19/D20.
12. **FTS5 search.** Add `secrets_fts` and `keys_fts` virtual tables with `unicode61` tokenizer and insert/update/delete triggers. `scopuli secret search`, `scopuli keys search`, `search_secrets`, `search_keys` tools. BM25 ranking. Flatten metadata JSON into the index (`k1=v1; k2=v2`).
13. **pi extension (status bar v0).** New `extensions/pi/` package `@scopuli/pi-extension`. README + tsconfig + package.json + activate function. Status bar item showing `🔒 scopuli: up · <key_count> keys · scope <read/manage>`. Auto-detect auth via env vars → macOS Keychain → interactive prompt. No slash commands, no tools in V0 of the extension.

## 8. Out-of-V0 ideas (parking lot)

- Web UI for the operator.
- Multi-host streamable HTTP MCP.
- Per-secret ACL (read allowed by these keys, manage by those keys).
- Path-based policy DSL (`allow` / `deny` rules, IP allowlists for keys).
- Webhook on key revocation.
- Backup without age passphrase (re-encrypt the bundle with the master password derived key).
- 2FA / passkeys.
- LDAP / OIDC for the operator.
- Multi-operator (TOTP-based unseal coordination).

---

## 9. Decisions taken

The full decision log is in [`DECISIONS.md`](./DECISIONS.md). Summary:

- **D1.** Language: **Go**.
- **D2.** Client surface: **CLI only, no web UI**.
- **D3.** Network exposure: **safe to expose to any network** (LAN or public). Bound to `127.0.0.1:8080` by default; operator overrides when putting a reverse proxy in front.
- **D4.** Scope syntax: **slash paths with `*` glob**.
- **D5.** Master password source: **`MASTER_PASSWORD` env var**, used only at boot to derive the KEK. Never sent over the wire.
- **D6.** Key expiry: **hard expiry + audit row**.
- **D7.** Default expiry: **no default** (operator sets it).
- **D8.** Audit retention: **keep all rows indefinitely**.
- **D9.** Image registry: **GHCR**.
- **D10.** Backup: **encrypted export bundle (age)**.
- **D11.** First boot: **operator token printed to stdout**.
- **D12.** Operator tokens: **one per operator**.
- **D13.** Operator token storage: **macOS Keychain / Linux secret service**.
- **D14.** MCP transport: **stdio, CLI binary is local to each host**.
- **D15.** Operator visibility: **single operator (no multi-user in V0)**.
- **D16.** Permissions: **`read` or `manage`**.
- **D17.** Per-agent audit visibility: **keys see their own activity only**.