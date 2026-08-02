# cred-share — Architecture (V0)

> Companion to [`PLAN.md`](./PLAN.md). Reads left-to-right with `PLAN.md` first.
> Goal of this doc: explain **how the thing is built** — components, request flows, data model, deployment topology. Security choices are justified in [`SECURITY.md`](./SECURITY.md).

---

## 1. High-level topology

```
                ┌────────────────────────────┐
                │   Operator's workstation   │
                │   cred-share CLI / web UI  │
                └─────────────┬──────────────┘
                              │ HTTPS (LAN) or unix socket (local)
                ┌─────────────▼──────────────┐
                │ cred-share server (Docker)│
                │  on LXC / VPS / NAS       │
                │                            │
                │  ┌──────────────────────┐  │
                │  │ HTTP layer (chi)     │  │
                │  ├──────────────────────┤  │
                │  │ Auth middleware      │  │
                │  │   - master session   │  │
                │  │   - X-Cred-Share-Key │  │
                │  ├──────────────────────┤  │
                │  │ Scope enforcer       │  │
                │  ├──────────────────────┤  │
                │  │ Audit logger         │  │
                │  ├──────────────────────┤  │
                │  │ Crypto module        │  │
                │  │   - Argon2id (KEK)   │  │
                │  │   - AES-256-GCM (DEK)│  │
                │  ├──────────────────────┤  │
                │  │ SQLCipher repository │  │
                │  └──────────┬───────────┘  │
                │             │              │
                │  ┌──────────▼───────────┐  │
                │  │ /data/vault.db       │  │
                │  │ (SQLCipher, AES-256) │  │
                │  └──────────────────────┘  │
                └────────────────────────────┘
                  ▲                       ▲
                  │ HTTPS / unix socket    │ stdio (MCP)
                  │                       │
         ┌────────┴────────┐     ┌─────────┴─────────┐
         │ Web UI (browser)│     │ Agent runtime     │
         └─────────────────┘     │ (Claude Code, etc)│
                                  └───────────────────┘
```

Three actors:
- **Operator** — owns the master password, creates secrets, creates/revokes agent keys, reads audit log.
- **Agent / team member** — holds an API key, only sees secrets within scope.
- **Server** — holds the SQLCipher file, performs KDF + AEAD, enforces scope, logs every action.

---

## 2. Components

### 2.1 Server (Go binary in a single container)

Process responsibilities:

| Module | Responsibility |
|---|---|
| `cmd/server` | Wires everything together, owns the HTTP server and the DB pool. |
| `internal/auth` | Login (master password → session cookie), API-key middleware, logout. |
| `internal/scope` | Path matcher (glob → set of paths), `IsAllowed(scope, action, path)` decision. |
| `internal/audit` | Append entries to `audit` table with hash chain + HMAC; verify chain on demand. |
| `internal/crypto` | Argon2id KDF, AES-256-GCM seal/open, random nonce/IV generation. |
| `internal/store` | SQLCipher-backed repository: CRUD for secrets, keys, sessions, audit. |
| `internal/api` | HTTP handlers for `/api/*` and the front-end routes. |
| `internal/web` | Server-rendered HTML pages (htmx-based, plain `html/template`). |

### 2.2 CLI (same Go binary, subcommand dispatch)

```
cred-share login     <url> [--master-password-stdin | --from-env]
cred-share secret    get <path>
cred-share secret    set <path> --value <v> | --value-from-stdin | --value-from-file <f>
cred-share secret    list [--prefix <p>]
cred-share secret    delete <path>
cred-share keys      create <name> --scope <csv> --permission read|manage --expires-in <dur>
cred-share keys      list
cred-share keys      revoke <name>
cred-share audit     list [--since <dur>] [--key <name>] [--limit <n>]
cred-share audit     verify
cred-share mcp-serve                                # starts the MCP server over stdio
```

The CLI is thin: it serializes commands into HTTP requests and prints responses. **No local DB access.** This keeps the surface area tiny and means the CLI works exactly the same as the web UI from an audit-log perspective.

### 2.3 MCP server mode (`cred-share mcp-serve`)

Speaks JSON-RPC 2.0 over stdio per the [MCP spec](https://modelcontextprotocol.io/specification/2025-06-18/server/tools).

**Why stdio, not Streamable HTTP, as the default?**
- Agents in this homelab use-case are local subprocesses of the LLM runtime (e.g., Claude Code spawns MCP servers as children). stdio is the lowest-friction transport.
- It naturally enforces "agent is on the same host as the vault" — which is exactly the trust boundary we want for V0.
- Streamable HTTP stays on the roadmap for V1 (multiple agents on different hosts).

Tool surface (initial set):

| Tool name | Description | Inputs |
|---|---|---|
| `list_secrets` | List secrets the calling key can see (path + label only, never value) | `{prefix?: string}` |
| `get_secret` | Fetch the plaintext value of one secret | `{path: string}` |
| `set_secret` | Create or update a secret (requires `manage` permission) | `{path: string, value: string, label?: string}` |
| `delete_secret` | Delete a secret (requires `manage` permission) | `{path: string}` |

Tool annotations: `readOnlyHint` on `list_secrets` and `get_secret`, `destructiveHint` on `delete_secret`. Per the MCP spec, every tool call is authenticated with the operator's `CRED_SHARE_KEY` env var; unauthenticated calls fail with a protocol error.

### 2.4 Web UI (optional — see decision D2)

If included in V0: minimal HTML pages, `html/template` + a sprinkle of htmx, single CSS file. No JS framework, no build step. Routes:

- `GET  /`            → redirect to `/login` or `/secrets`
- `GET  /login`       → form (single field: master password)
- `POST /login`       → sets session cookie
- `POST /logout`      → clears session cookie
- `GET  /secrets`     → list (path + label only)
- `GET  /secrets/new` → create form
- `POST /secrets`     → create handler
- `GET  /secrets/{path...}` → reveal value (POST only — no GET with value in URL)
- `POST /secrets/{path...}` → update
- `POST /secrets/{path...}/delete`
- `GET  /keys`        → list
- `GET  /keys/new`    → create form
- `POST /keys`        → create handler (returns the plaintext key **once**)
- `POST /keys/{name}/revoke`
- `GET  /audit`       → paged log viewer

---

## 3. Request flows

### 3.1 Agent reads a secret

```
agent ──HTTP GET /api/secrets/aws/dev/stripe_key──▶ server
       header: X-Cred-Share-Key: csk_live_<…>_cRC4k1

server:
  1. auth middleware: HMAC-SHA256(key) → look up in keys table by hash
     - if revoked or expired → 401, audit("denied:revoked_or_expired")
     - if missing           → 401, no audit entry (don't leak whether a key exists)
  2. scope enforcer: glob match key.scope against "aws/dev/stripe_key"
     - if no match → 403, audit("denied:out_of_scope", path=…, scope=…)
  3. crypto: read ciphertext from secrets table, AES-256-GCM open
  4. audit: append (key_id, ts, "read", path, "ok", prev_hash, hash, hmac)
  5. respond 200 with {"path": …, "value": "sk_live_…"}
```

### 3.2 Operator creates a secret (CLI, master session)

```
cli ──POST /api/secrets──▶ server
    cookie: cred-share-session=<sid>
    body: {"path": "aws/prod/stripe_key", "value": "sk_live_…"}

server:
  1. session middleware: HMAC the sid, look up in sessions table
     - if invalid/expired → 401
     - if !is_master      → 403 (operator-only)
  2. crypto: AES-256-GCM seal(value) → ciphertext, nonce
  3. upsert secrets (path, ciphertext, nonce, …)
  4. audit: append (NULL key_id, ts, "write", path, "ok", …)
  5. respond 204
```

### 3.3 Operator creates an agent key

```
cli ──POST /api/keys──▶ server
    cookie: cred-share-session=<sid>
    body: {"name": "linus-dev", "scope": "aws/dev/*,github/lucas/*",
           "permissions": "read", "expires_in": "720h"}

server:
  1. session middleware (master)
  2. generate 32 random bytes → b64url("csk_live_" + base32(body) + "_" + crc4k1)
     body is base62 of the random bytes
     checksum = first 4 bytes of SHA-256(body), base62
  3. hash = hex(SHA-256(full_key)) — this is what we store
  4. insert keys (name, hash, prefix="csk_live_<first 8 of body>", scope, …)
  5. audit: append ("key.create", name=linus-dev, scope=…, permissions=…)
  6. respond 200 with {"key": "csk_live_…_cRC4k1"}  // shown ONCE
```

### 3.4 Audit verify

```
cli ──GET /api/audit/verify──▶ server (master only)

server:
  - walk audit table in id order
  - for each row: assert hash == SHA-256(prev_hash || canonical_json(row.without_hash))
  - assert hmac   == HMAC-SHA256(audit_hmac_key, hash)
  - respond 200 {"ok": true, "checked": <n>} or
           207 {"ok": false, "broken_at_id": <id>, "expected": …, "got": …}
```

---

## 4. Data model

### 4.1 Schema (SQLCipher-encrypted SQLite)

```sql
-- meta: bootstrap parameters needed to open the vault
CREATE TABLE meta (
  k TEXT PRIMARY KEY,
  v BLOB NOT NULL                -- ciphertext (GCM-sealed) or raw, depending on k
);
-- rows:
--   k = "schema_version",   v = X'01'            (plain)
--   k = "kdf_salt",         v = 16 random bytes  (plain, public)
--   k = "kdf_params",       v = JSON             (plain, public)
--   k = "hmac_key_salt",    v = 16 random bytes  (plain)
--   k = "hmac_key",         v = HMAC key (raw,    -- lives ONLY in this row
--                              must be wiped on master pw change)
--   k = "kek_check",        v = AES-GCM("ok")    (proves the KEK is correct)

CREATE TABLE secrets (
  id          INTEGER PRIMARY KEY,
  path        TEXT NOT NULL UNIQUE,
  label       TEXT,
  ciphertext  BLOB NOT NULL,        -- AES-256-GCM(plaintext)
  nonce       BLOB NOT NULL,        -- 12 bytes
  aad         BLOB NOT NULL,        -- binds ciphertext to the path
  created_at  INTEGER NOT NULL,     -- unix seconds
  updated_at  INTEGER NOT NULL,
  version     INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX secrets_path_idx ON secrets(path);

CREATE TABLE keys (
  id           INTEGER PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  hash         TEXT NOT NULL,       -- hex(SHA-256(full_key))
  prefix       TEXT NOT NULL,       -- "csk_live_<first 8 of body>" — display only
  scope        TEXT NOT NULL,       -- CSV of globs
  permissions  TEXT NOT NULL,       -- 'read' | 'manage'  (V0: a single permission per key)
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER,             -- NULL = no expiry
  revoked_at   INTEGER,
  last_used_at INTEGER
);
CREATE INDEX keys_hash_idx ON keys(hash);

CREATE TABLE sessions (
  id          TEXT PRIMARY KEY,     -- random 32 bytes, hex
  is_master   INTEGER NOT NULL,     -- 1 = operator session, 0 = (unused in V0)
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX sessions_expires_idx ON sessions(expires_at);

CREATE TABLE audit (
  id         INTEGER PRIMARY KEY,
  ts         INTEGER NOT NULL,
  key_id     INTEGER,               -- NULL for operator actions
  action     TEXT NOT NULL,         -- "read" | "write" | "delete" | "denied:<reason>" | "key.create" | "key.revoke" | "auth.fail" | "auth.success"
  path       TEXT,                  -- the secret path or key name
  result     TEXT NOT NULL,         -- "ok" | "denied" | "error:<code>"
  prev_hash  BLOB NOT NULL,         -- 32 bytes, hash of the previous row
  hash       BLOB NOT NULL,         -- 32 bytes, SHA-256(canonical_json(row minus hash))
  hmac       BLOB NOT NULL          -- 32 bytes, HMAC-SHA-256(audit_hmac_key, hash)
);
CREATE INDEX audit_ts_idx ON audit(ts);
CREATE INDEX audit_key_idx ON audit(key_id);
```

### 4.2 SQLCipher pragmas (per-connection)

```sql
PRAGMA key = "x'<raw-kek-from-argon2id>'";   -- raw 32-byte key, not a password
PRAGMA cipher_page_size = 4096;
PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
PRAGMA kdf_iter = 1;                          -- we already did the KDF ourselves
PRAGMA cipher_memory_security = OFF;          -- homelab, single-user, low risk
PRAGMA busy_timeout = 5000;
```

### 4.3 Why raw-key SQLCipher + outer KDF

Default SQLCipher takes a passphrase and runs PBKDF2 (256k rounds) to derive the encryption key. We deliberately bypass that (`kdf_iter = 1`, `PRAGMA cipher_memory_security = OFF`) and feed it the raw Argon2id output. Two reasons:

1. We want a stronger KDF than PBKDF2-256k — Argon2id is OWASP's current recommendation.
2. We want to be able to rotate the master password without rewriting the whole DB. With raw key + outer encryption layer, we can re-derive and re-wrap the KEK in O(secrets-with-changed-scope), not O(secrets). See `SECURITY.md` §5 for the rotation design.

### 4.4 Secrets encryption (the AEAD layer)

For each secret value `v` at path `p`:

```
nonce   = 12 random bytes
aad     = SHA-256(path || label || version)
cipher  = AES-256-GCM-Encrypt(KEK, nonce, v, aad)
stored  = { ciphertext, nonce, aad, version }
```

This is **envelope encryption without a per-secret DEK** — simpler, fits V0. Trade-off: changing the master password means re-encrypting every secret (see `SECURITY.md` §5).

---

## 5. Deployment topology

### 5.1 Docker (single container)

```yaml
# docker-compose.yml (recommended)
services:
  cred-share:
    image: ghcr.io/<you>/cred-share:v0
    restart: unless-stopped
    environment:
      MASTER_PASSWORD:           # required, no default
        # sourced from .env, host secret manager, or systemd LoadCredential
      CRED_SHARE_BIND: "127.0.0.1:8080"
      CRED_SHARE_DB_PATH: "/data/vault.db"
      CRED_SHARE_LOG_LEVEL: "info"
      # V0: disable web UI by setting CRED_SHARE_WEB=off
      CRED_SHARE_WEB: "on"
    volumes:
      - cred-share-data:/data
    # no :8080 published by default — operator accesses via local port-forward
    # or behind a reverse proxy with TLS if LAN access is needed
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/healthz"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  cred-share-data:
```

The LXC container itself just needs:
- Docker installed (or a rootless alternative like `podman`).
- A persistent volume (LXC bind mount or a `zfs`/`btrfs` subvolume is fine).
- Backups of `/data` are just copies of `vault.db` — but **they are useless without the master password**. See `OPERATIONS.md` for the backup story.

### 5.2 Why no port publishing in the default compose

Two reasons:

1. **Agents are local subprocesses** of the LLM runtime on the same LXC. They talk to `127.0.0.1:8080`. No network exposure needed.
2. **If LAN exposure is wanted**, the operator should put it behind Caddy/Nginx with TLS + an allowlist — not publish the container port directly.

If the user wants remote agents (different hosts), Streamable HTTP MCP and a reverse-proxy story are V1 work.

### 5.3 Process model

- One process. No worker pool. SQLite serializes writes anyway.
- Long-lived DB connection. SQLCipher's KDF runs once on connection open; we already do the outer Argon2id on master-password entry, so we don't pay that cost twice.
- Graceful shutdown on SIGTERM: flush audit, close DB, exit.

---

## 6. Configuration reference (V0)

All settings come from env vars. No config file in V0 — single container, single binary, single source of truth is the env.

| Variable | Required | Default | Description |
|---|---|---|---|
| `MASTER_PASSWORD` | **yes** | — | Master password. Server exits on boot if missing/empty. |
| `CRED_SHARE_BIND` | no | `127.0.0.1:8080` | Listen address. `0.0.0.0` allowed but discouraged. |
| `CRED_SHARE_DB_PATH` | no | `/data/vault.db` | Path to the SQLCipher file. |
| `CRED_SHARE_WEB` | no | `on` | `off` disables the HTML front-end entirely. |
| `CRED_SHARE_LOG_LEVEL` | no | `info` | `debug` / `info` / `warn` / `error`. |
| `CRED_SHARE_SESSION_TTL` | no | `8h` | Master-password session cookie lifetime. |
| `CRED_SHARE_KEY_DEFAULT_TTL` | no | `720h` (30d) | Suggested default expiry on `keys create`. |
| `CRED_SHARE_RATE_LIMIT_RPS` | no | `20` | Per-token bucket for unauthenticated endpoints (`/login`, `/healthz`). |

---

## 7. Observability

V0 ships with:

- **Structured logs** (`slog` JSON) to stdout. Every request logs method, path, status, duration, `key_id` (if any), `session_kind`.
- **Audit log** in the database. Always on. Can't be disabled.
- **Healthcheck endpoint** `/healthz` — returns 200 if the process is up and the DB is unlocked.
- **No Prometheus endpoint in V0.** Add `/metrics` later if needed; we already log everything in JSON, so a sidecar log shipper covers 90% of cases.

---

## 8. Build & release

- `Dockerfile` based on `gcr.io/distroless/static-debian12` (no shell, no package manager, scratch-ish). Single Go binary copied in. ~15 MB image.
- Multi-stage build: `golang:1.23-alpine` → static binary → distroless.
- Reproducible builds via `-trimpath -buildvcs=true`.
- SBOM (`syft`) and image signing (`cosign`) are V1 work.
- CI: GitHub Actions, `go test ./...` + `docker build` smoke test + `govulncheck`.

---

## 9. Why this shape and not something else (rationale log)

| Choice | Considered | Picked | Reason |
|---|---|---|---|
| Single binary server | Server + worker, microservices | **Single binary** | One container, one DB, one process. SQLite hates concurrency anyway. |
| Go | Rust, Node, Python, Elixir | **Go** | Static binary, fast cold start, mature crypto stdlib, official MCP SDK, single-file deploy. |
| SQLCipher | Plain SQLite + column encryption, BadgerDB, BoltDB | **SQLCipher** | Whole-file AES-256, mature, simple backup story (it's just one file). |
| AES-256-GCM | XChaCha20-Poly1305, AES-256-CBC | **AES-256-GCM** | AEAD, hardware-accelerated everywhere, included in Go's stdlib. |
| Argon2id | scrypt, PBKDF2-SHA512 | **Argon2id** | OWASP's top recommendation, memory-hard, resists GPU/ASIC attacks. |
| stdio MCP | Streamable HTTP MCP | **stdio (V0)** | Agents are local. HTTP is V1. |
| Path globs for scope | RegEx, ACL matrices, OPA | **Path globs** | One-operator mental model. Easy to reason about. |
| Hash-chained audit log | Merkle tree, external ledger | **Hash chain + HMAC** | Cheap, in-SQLite, no external dependency. |
| Barebones web UI (htmx) | React/Vue SPA, no UI | **htmx** if D2 says yes, otherwise skip | One CSS file, server-rendered, no build step. |

The decisions that need a human answer are in [`DECISIONS.md`](./DECISIONS.md).