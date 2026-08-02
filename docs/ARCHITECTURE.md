# cred-share — Architecture (V0)

> Reads with [`PLAN.md`](./PLAN.md). Explains **how** the thing is built. **Why** the crypto choices are what they are is in [`SECURITY.md`](./SECURITY.md). Domain terms are in [`CONTEXT.md`](../CONTEXT.md).

---

## 1. High-level topology

```
                ┌────────────────────────────┐
                │  Operator's Mac            │
                │  cred-share CLI / MCP      │  (token in Keychain)
                └─────────────┬──────────────┘
                              │ HTTPS over reverse proxy
                              │ X-Cred-Share-Operator: csot_…
                              │   or X-Cred-Share-Key: csk_live_…
                ┌─────────────▼──────────────┐
                │ cred-share container      │
                │ on LXC / VPS               │
                │                            │
                │  ┌──────────────────────┐  │
                │  │ HTTP layer (chi)     │  │
                │  ├──────────────────────┤  │
                │  │ Auth middleware      │  │
                │  │  - operator token    │  │
                │  │  - agent key         │  │
                │  ├──────────────────────┤  │
                │  │ Scope enforcer       │  │
                │  ├──────────────────────┤  │
                │  │ Audit logger         │  │
                │  ├──────────────────────┤  │
                │  │ Crypto module        │  │
                │  │  - Argon2id (KEK)    │  │
                │  │  - AES-256-GCM (AEAD)│  │
                │  │  - SHA-256 chain     │  │
                │  │  - HMAC-SHA-256      │  │
                │  ├──────────────────────┤  │
                │  │ SQLCipher repository │  │
                │  └──────────┬───────────┘  │
                │             │              │
                │  ┌──────────▼───────────┐  │
                │  │ /data/vault.db       │  │
                │  │ (SQLCipher, AES-256) │  │
                │  └──────────────────────┘  │
                └────────────────────────────┘
```

Three actors:
- **Operator** — owns the master password and the operator token. Creates secrets, creates/revokes agent keys, reads the audit log.
- **Agent** — holds an agent key. Only sees secrets within scope.
- **Server** — holds the SQLCipher file, performs KDF + AEAD, enforces scope, logs every action.

## 2. Components

### 2.1 Server (Go binary in a single container)

| Module | Responsibility |
|---|---|
| `cmd/server` | Wires everything together; owns the HTTP server and the DB pool. |
| `internal/auth` | Operator-token + agent-key middleware. Login is implicit (you log in once on the CLI). |
| `internal/scope` | Path matcher (glob → set of paths); `IsAllowed(scope, action, path)` decision. |
| `internal/audit` | Append entries to `audit` table with hash chain + HMAC; verify chain on demand. |
| `internal/crypto` | Argon2id KDF, AES-256-GCM seal/open, random nonce/IV generation, HMAC for audit chain. |
| `internal/store` | SQLCipher-backed repository: CRUD for secrets, keys, operators, audit. |
| `internal/api` | HTTP handlers for `/api/*`. |
| `internal/backup` | age-encrypted export / import. |
| `internal/keyring` | macOS Keychain / Linux secret service backend for the operator token. |

### 2.2 CLI (same Go binary, subcommand dispatch)

```
cred-share login                <url> --token <token>
cred-share login                --show                   # show the URL the CLI is configured for
cred-share secret    get        <path>
cred-share secret    set        <path> --value <v> | --value-from-stdin | --value-from-file <f>
cred-share secret    list       [--prefix <p>]
cred-share secret    delete     <path>
cred-share keys      create     <name> --scope <csv> --permission read|manage [--expires-in <dur>]
cred-share keys      list
cred-share keys      get        <name>                   # show prefix + scope + permissions + expiry, never the hash
cred-share keys      revoke     <name>
cred-share operator  rotate     --from-env MASTER_PASSWORD
cred-share audit     list       [--since <dur>] [--key <name>] [--limit <n>]
cred-share audit     verify
cred-share snapshot              --out <file.age>
cred-share restore               --in <file.age> --into <path>
cred-share mcp-serve                                      # MCP over stdio
cred-share version
```

The CLI is thin: it serializes commands into HTTP requests and prints responses. **No local DB access.** This keeps the surface area tiny and means the CLI is exactly the same shape as the API from an audit-log perspective.

### 2.3 MCP server mode (`cred-share mcp-serve`)

Speaks JSON-RPC 2.0 over **stdio** per the [MCP spec](https://modelcontextprotocol.io/specification/2025-06-18/server/tools).

**Why stdio, not Streamable HTTP, as the default?**
- The LLM runtime spawns the MCP server as a child process. stdio is the lowest-friction transport.
- The CLI binary is local to each host that wants to use it. The MCP server talks to the vault over the network using the auth token from the keychain or env var.
- Streamable HTTP would mean exposing a remote MCP endpoint from the vault server itself — V1 work.

Tool surface (initial set):

| Tool name | Description | Inputs |
|---|---|---|
| `list_secrets` | List secrets the calling key can see (path + label only, never value) | `{prefix?: string}` |
| `get_secret` | Fetch the plaintext value of one secret | `{path: string}` |
| `set_secret` | Create or update a secret (requires `manage` permission) | `{path: string, value: string, label?: string}` |
| `delete_secret` | Delete a secret (requires `manage` permission) | `{path: string}` |

Tool annotations: `readOnlyHint: true` on `list_secrets` and `get_secret`; `destructiveHint: true` on `delete_secret`. Per the MCP spec, every tool call is authenticated with the operator's `CRED_SHARE_KEY` env var (or the operator token from the keychain); unauthenticated calls fail with a protocol error.

### 2.4 Web UI

**Not in V0.** The operator uses the CLI. Section §2.4 is reserved for V1.

---

## 3. Request flows

### 3.1 Operator reads a secret

```
cli ──HTTP GET /api/secrets/aws/prod/stripe_key──▶ server
     header: X-Cred-Share-Operator: csot_…

server:
  1. auth middleware: SHA-256(token) → look up in operators table
     - if missing → 401, no audit entry (don't leak operator existence)
  2. (no scope check for the operator; they see everything)
  3. crypto: read ciphertext from secrets table, AES-256-GCM open
  4. audit: append (actor_kind='operator', actor_id, ts, "read", path, "ok", prev_hash, hash, hmac)
  5. respond 200 with {"path": …, "value": "sk_live_…"}
```

### 3.2 Operator creates a secret

```
cli ──POST /api/secrets──▶ server
    header: X-Cred-Share-Operator: csot_…
    body: {"path": "aws/prod/stripe_key", "value": "sk_live_…", "label": "Stripe production"}

server:
  1. auth middleware (operator token)
  2. crypto: AES-256-GCM seal(value) → ciphertext, nonce
  3. upsert secrets (path, ciphertext, nonce, …)
  4. audit: append (actor_kind='operator', actor_id, ts, "write", path, "ok", …)
  5. respond 204
```

### 3.3 Operator creates an agent key

```
cli ──POST /api/keys──▶ server
    header: X-Cred-Share-Operator: csot_…
    body: {"name": "linus-dev", "scope": "aws/dev/*,github/lucas/pat",
           "permissions": "read"}

server:
  1. auth middleware (operator token)
  2. generate 32 random bytes
     key = "csk_live_" + base62(body) + "_" + base62(sha256(body)[:4])
  3. hash = hex(SHA-256(full_key))
  4. insert keys (name, hash, prefix="csk_live_<first 8 of body>", scope, permissions, expires_at=NULL)
  5. audit: append ("key.create", name=linus-dev, scope=…, permissions=…)
  6. respond 200 with {"key": "csk_live_…_cRC4k1"}  // shown ONCE
```

### 3.4 Agent reads a secret (bad path)

```
agent ──HTTP GET /api/secrets/aws/prod/stripe_key──▶ server
       header: X-Cred-Share-Key: csk_live_<…>_cRC4k1   (scope aws/dev/*)

server:
  1. auth middleware: SHA-256(key) → look up in keys table
     - if revoked / expired / unknown → 401, audit("denied:revoked_or_expired")
  2. scope enforcer: glob match key.scope against "aws/prod/stripe_key"
     - no match → 403, audit("denied:out_of_scope", path=…, scope=…)
  3. (never reach crypto)
  4. respond 403
```

### 3.5 Agent reads a secret (good path)

```
agent ──HTTP GET /api/secrets/aws/dev/stripe_key──▶ server
       header: X-Cred-Share-Key: csk_live_<…>_cRC4k1

server:
  1. auth middleware: ok
  2. scope enforcer: "aws/dev/*" matches "aws/dev/stripe_key" → ok
  3. crypto: read ciphertext, AES-256-GCM open
  4. audit: append (actor_kind='key', actor_id, ts, "read", path, "ok", prev_hash, hash, hmac)
  5. respond 200 with {"path": …, "value": "sk_live_…"}
```

### 3.6 Audit verify

```
cli ──GET /api/audit/verify──▶ server (operator token)

server walks audit table in id order:
  for each row:
    assert hash == SHA-256(prev_hash || canonical_json(row.without_hash))
    assert hmac  == HMAC-SHA-256(AUDIT_HMAC_KEY, hash)

respond 200 {"ok": true, "checked": <n>}
       or 207 {"ok": false, "broken_at_id": <id>, "expected": …, "got": …}
```

## 4. Data model

### 4.1 Schema (SQLCipher-encrypted SQLite)

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE meta (
  k TEXT PRIMARY KEY,
  v BLOB NOT NULL                -- ciphertext (GCM-sealed) or raw, depending on k
);
-- rows:
--   k = "schema_version",   v = X'01'                             (plain)
--   k = "kdf_salt",         v = 16 random bytes                   (plain)
--   k = "kdf_params",       v = JSON                              (plain)
--   k = "hmac_key_salt",    v = 16 random bytes                   (plain)
--   k = "hmac_key",         v = AES-GCM KEK-sealed HMAC key (32B) (encrypted)
--   k = "kek_check",        v = AES-GCM("ok") using KEK          (encrypted)
--   k = "first_boot_done",  v = X'01'                             (plain)

CREATE TABLE operators (
  id           INTEGER PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,    -- always 'primary' in V0
  hash         TEXT NOT NULL,           -- hex(SHA-256(operator_token))
  prefix       TEXT NOT NULL,           -- "csot_live_<first 8 of body>" — display only
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE INDEX operators_hash_idx ON operators(hash);

CREATE TABLE secrets (
  id          INTEGER PRIMARY KEY,
  path        TEXT NOT NULL UNIQUE,
  label       TEXT,
  ciphertext  BLOB NOT NULL,
  nonce       BLOB NOT NULL,            -- 12 bytes
  aad         BLOB NOT NULL,            -- SHA-256(path || label || version)
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  version     INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX secrets_path_idx ON secrets(path);

CREATE TABLE keys (
  id           INTEGER PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  hash         TEXT NOT NULL,           -- hex(SHA-256(full_key))
  prefix       TEXT NOT NULL,           -- "csk_live_<first 8 of body>"
  scope        TEXT NOT NULL,           -- CSV of glob patterns
  permissions  TEXT NOT NULL,           -- 'read' | 'manage'
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER,                 -- NULL = no expiry
  revoked_at   INTEGER,
  last_used_at INTEGER
);
CREATE INDEX keys_hash_idx ON keys(hash);

CREATE TABLE audit (
  id          INTEGER PRIMARY KEY,
  ts          INTEGER NOT NULL,
  actor_kind  TEXT NOT NULL,            -- 'operator' | 'key'
  actor_id    INTEGER NOT NULL,
  action      TEXT NOT NULL,            -- 'read' | 'write' | 'delete' | 'denied:<reason>' | 'key.create' | 'key.revoke' | 'audit.verify' | 'snapshot' | 'restore' | 'operator.rotate'
  path        TEXT,                     -- the secret path or key name
  result      TEXT NOT NULL,            -- 'ok' | 'denied' | 'error:<code>'
  prev_hash   BLOB NOT NULL,            -- 32 bytes
  hash        BLOB NOT NULL,            -- 32 bytes
  hmac        BLOB NOT NULL             -- 32 bytes
);
CREATE INDEX audit_ts_idx ON audit(ts);
CREATE INDEX audit_actor_idx ON audit(actor_kind, actor_id);
```

### 4.2 SQLCipher pragmas (per-connection)

```sql
PRAGMA key = "x'<raw-kek-from-argon2id>'";   -- raw 32-byte key, not a passphrase
PRAGMA cipher_page_size = 4096;
PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
PRAGMA kdf_iter = 1;                          -- we already did the KDF ourselves
PRAGMA cipher_memory_security = OFF;          -- homelab, single-user, low risk
PRAGMA busy_timeout = 5000;
PRAGMA journal_mode = WAL;                    -- for concurrent readers
PRAGMA synchronous = NORMAL;                  -- WAL default; safer than OFF
```

### 4.3 Why raw-key SQLCipher + outer KDF

Default SQLCipher takes a passphrase and runs PBKDF2 (256k rounds) to derive the encryption key. We bypass that (`kdf_iter = 1`) and feed it the raw Argon2id output. Two reasons:

1. We want a stronger KDF than PBKDF2-256k — Argon2id is OWASP's current recommendation.
2. We want to be able to rotate the master password without rewriting the whole DB. With raw key + outer encryption layer, we can re-derive and re-wrap the KEK in O(secrets), not O(rows). See `SECURITY.md` §5 for the rotation design.

### 4.4 Secret encryption (the AEAD layer)

For each secret value `v` at path `p`:

```
nonce   = 12 random bytes from crypto/rand
aad     = SHA-256(path || label || uint64_be(version))
cipher  = AES-256-GCM-Encrypt(KEK, nonce, plaintext, aad)
stored  = { ciphertext, nonce, aad, version }
```

The AAD binds the ciphertext to the path and version. An attacker who swaps ciphertexts between two rows can't get away with it — the AAD won't match on decrypt.

### 4.5 Audit chain

```
canonical(entry) = stable JSON of {ts, actor_kind, actor_id, action, path, result}
                   with sorted keys, explicit types
hash             = SHA-256(prev_hash || canonical(entry))
hmac             = HMAC-SHA-256(AUDIT_HMAC_KEY, hash)

INSERT: prev_hash = previous row's hash (or 32 zero bytes for id=1)
```

The HMAC key is derived from the master password via a separate Argon2id salt (`hmac_key_salt`). Stored in `meta.hmac_key` (encrypted by SQLCipher). Re-derived on every boot.

## 5. Deployment topology

### 5.1 Docker (single container)

```yaml
# docker-compose.yml
services:
  cred-share:
    image: ghcr.io/lucaspdude/cred-share:v0
    restart: unless-stopped
    environment:
      MASTER_PASSWORD:                # required, no default
      CRED_SHARE_BIND: "127.0.0.1:8080"
      CRED_SHARE_DB_PATH: "/data/vault.db"
      CRED_SHARE_LOG_LEVEL: "info"
      CRED_SHARE_KEY_DEFAULT_TTL: ""  # blank = no default
    volumes:
      - cred-share-data:/data
    # no :8080 published by default — operator puts a reverse proxy in front
    # or runs the CLI from the LXC host
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/healthz"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  cred-share-data:
```

### 5.2 Reverse proxy (LAN / public exposure)

Operator runs Caddy or Nginx in front. Example Caddyfile:

```
vault.example.com {
  reverse_proxy 127.0.0.1:8080
}
```

`CRED_SHARE_BIND` is set to `0.0.0.0:8080` in the container (or `127.0.0.1` if the reverse proxy runs on the same host in a separate container).

### 5.3 Process model

- One process. No worker pool. SQLite serializes writes anyway.
- Long-lived DB connection. SQLCipher's KDF runs once on connection open; we already do the outer Argon2id on master-password entry, so we don't pay that cost twice.
- Graceful shutdown on SIGTERM: drain in-flight requests, flush audit, close DB, exit.

## 6. Configuration reference (V0)

All settings come from env vars. No config file in V0.

| Variable | Required | Default | Description |
|---|---|---|---|
| `MASTER_PASSWORD` | **yes** | — | Master password. Server exits on boot if missing/empty. |
| `CRED_SHARE_BIND` | no | `127.0.0.1:8080` | Listen address. Set to `0.0.0.0:8080` when a reverse proxy is in front. |
| `CRED_SHARE_DB_PATH` | no | `/data/vault.db` | Path to the SQLCipher file. |
| `CRED_SHARE_LOG_LEVEL` | no | `info` | `debug` / `info` / `warn` / `error`. |
| `CRED_SHARE_KEY_DEFAULT_TTL` | no | `""` (no default) | Suggested default expiry on `keys create`. Accepts Go duration strings. |
| `CRED_SHARE_RATE_LIMIT_RPS` | no | `20` | Per-token bucket for unauthenticated endpoints. |
| `CRED_SHARE_AGENT_KEY_RPS` | no | `100` | Per-agent-key token bucket. |

## 7. Observability

- **Structured logs** (`slog` JSON) to stdout. Every request logs method, path, status, duration, actor (`operator`/`key:<id>`).
- **Audit log** in the database. Always on. Can't be disabled.
- **Healthcheck endpoint** `/healthz` — returns 200 if the process is up and the DB is unlocked.
- **No Prometheus endpoint in V0.** Add `/metrics` later if needed; structured JSON logs cover most cases.

## 8. Build & release

- `Dockerfile` based on `gcr.io/distroless/static-debian12`. Single Go binary. ~15 MB image.
- Multi-stage build: `golang:1.23-alpine` → static binary → distroless.
- Reproducible builds via `-trimpath -buildvcs=true`.
- CI: GitHub Actions, `go test ./...` + `docker build` smoke test + `govulncheck`.
- Image: `ghcr.io/lucaspdude/cred-share:v0`, `v0.0.1`, `latest`.

## 9. Why this shape and not something else (rationale log)

| Choice | Considered | Picked | Reason |
|---|---|---|---|
| Single binary server | Server + worker, microservices | **Single binary** | One container, one DB, one process. SQLite serializes writes. |
| Go | Rust, Node, Python, Elixir | **Go** | Static binary, fast cold start, mature crypto stdlib, official MCP SDK. |
| SQLCipher | Plain SQLite + column encryption, BadgerDB, BoltDB | **SQLCipher** | Whole-file AES-256, mature, simple backup story. |
| AES-256-GCM | XChaCha20-Poly1305, AES-256-CBC | **AES-256-GCM** | AEAD, hardware-accelerated, in stdlib. |
| Argon2id | scrypt, PBKDF2-SHA512 | **Argon2id** | OWASP's top recommendation, memory-hard, resists GPU/ASIC. |
| Operator token | Master password over wire | **Operator token** | Master password never leaves the container. |
| stdio MCP | Streamable HTTP MCP | **stdio (V0)** | CLI binary is local to each host. HTTP is V1. |
| Path globs for scope | RegEx, ACL matrices, OPA | **Path globs** | One-operator mental model. Easy to reason about. |
| Hash-chained audit log | Merkle tree, external ledger | **Hash chain + HMAC** | Cheap, in-SQLite, no external dependency. |
| macOS Keychain / Linux secret service | Plaintext config file | **Keychain** | Better UX, no plaintext file to leak. |
| age-encrypted export | Manual file copy | **age export** | Encrypted backups for untrusted cloud storage. |