# scopuli — Architecture (V0)

> Reads with [`PLAN.md`](./PLAN.md). Explains **how** the thing is built. **Why** the crypto choices are what they are is in [`SECURITY.md`](./SECURITY.md). Domain terms are in [`CONTEXT.md`](../CONTEXT.md).

---

## 1. High-level topology

```
                ┌────────────────────────────┐
                │  Operator's Mac            │
                │  scopuli CLI / MCP      │  (token in Keychain)
                └─────────────┬──────────────┘
                              │ HTTPS over reverse proxy
                              │ X-Scopuli-Operator: scot_…
                              │   or X-Scopuli-Key: sk_live_…
                ┌─────────────▼──────────────┐
                │ scopuli container      │
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
| `internal/fts` | FTS5 helpers: search wrappers, trigger registration, schema migration. |
| `internal/metadata` | Validate tags / description / metadata JSON; enforce D18–D20 limits. |

### 2.2 CLI (same Go binary, subcommand dispatch)

```
scopuli login                <url> --token <token>
scopuli login                --show                   # show the URL the CLI is configured for
scopuli secret    get        <path>
scopuli secret    set        <path> --value <v> | --value-from-stdin | --value-from-file <f>
                                       [--label <l>] [--tag <t>...] [--description <md>]
                                       [--meta k=v]...
scopuli secret    list       [--prefix <p>] [--tag <t>] [--query <q>]
scopuli secret    search     <query>                    # FTS5 search across path, description, metadata
scopuli secret    delete     <path>
scopuli secret    annotate   <path> [--add-tag <t>] [--remove-tag <t>] [--description <md>]
                                       [--set-meta k=v] [--unset-meta <k>]
scopuli keys      create     <name> --scope <csv> --permission read|manage [--expires-in <dur>]
                                       [--tag <t>...] [--description <md>] [--meta k=v]...
scopuli keys      list       [--tag <t>] [--query <q>]
scopuli keys      search     <query>
scopuli keys      get        <name>                   # show prefix + scope + permissions + expiry, never the hash
scopuli keys      update     <name> [--scope <csv>] [--permission read|manage] [--expires-in <dur>]
                                       [--add-tag <t>] [--remove-tag <t>] [--description <md>]
                                       [--set-meta k=v] [--unset-meta <k>]
scopuli keys      revoke     <name>
scopuli operator  rotate     --from-env MASTER_PASSWORD
scopuli audit     list       [--since <dur>] [--key <name>] [--limit <n>]
scopuli audit     verify
scopuli snapshot              --out <file.age>
scopuli restore               --in <file.age> --into <path>
scopuli mcp-serve                                      # MCP over stdio
scopuli version
```

The CLI is thin: it serializes commands into HTTP requests and prints responses. **No local DB access.** This keeps the surface area tiny and means the CLI is exactly the same shape as the API from an audit-log perspective.

### 2.3 MCP server mode (`scopuli mcp-serve`)

Speaks JSON-RPC 2.0 over **stdio** per the [MCP spec](https://modelcontextprotocol.io/specification/2025-06-18/server/tools).

**Why stdio, not Streamable HTTP, as the default?**
- The LLM runtime spawns the MCP server as a child process. stdio is the lowest-friction transport.
- The CLI binary is local to each host that wants to use it. The MCP server talks to the vault over the network using the auth token from the keychain or env var.
- Streamable HTTP would mean exposing a remote MCP endpoint from the vault server itself — V1 work.

Tool surface (initial set):

| Tool name | Description | Inputs |
|---|---|---|
| `list_secrets` | List secrets the calling key can see (path, label, tags, description, metadata; never value) | `{prefix?: string, tag?: string, query?: string}` |
| `get_secret` | Fetch the plaintext value of one secret (with description + metadata) | `{path: string}` |
| `set_secret` | Create or update a secret (requires `manage` permission). Re-encrypts if description changes (AAD includes description). | `{path: string, value: string, label?: string, tags?: string[], description?: string, metadata?: object}` |
| `delete_secret` | Delete a secret (requires `manage` permission) | `{path: string}` |
| `search_secrets` | Full-text search via FTS5 across path, description, metadata. BM25 ranked. | `{query: string, limit?: number}` |
| `search_keys` | Full-text search across name, description, metadata. | `{query: string, limit?: number}` |
| `annotate_secret` | Update tags / description / metadata on a secret (requires `manage` permission). Incremental: pass only the fields you want to change. | `{path: string, add_tags?: string[], remove_tags?: string[], description?: string, set_metadata?: object, unset_metadata?: string[]}` |
| `annotate_key` | Same as `annotate_secret` but for a key. | `{name: string, add_tags?: string[], remove_tags?: string[], description?: string, set_metadata?: object, unset_metadata?: string[]}` |
| `list_keys` | List keys the caller can see (filtered by scope for non-operator callers). | `{tag?: string, query?: string}` |

Tool annotations: `readOnlyHint: true` on `list_secrets`, `get_secret`, `list_keys`, `search_secrets`, `search_keys`; `destructiveHint: true` on `delete_secret`; `idempotentHint: true` on `set_secret`. Per the MCP spec, every tool call is authenticated with the operator's `SCOPULI_KEY` env var (or the operator token from the keychain); unauthenticated calls fail with a protocol error.

**Why include description / metadata in `list_secrets` and `get_secret` responses?** LLM agents do not just need the *value* of a secret — they need to know *what* it is and *when* to use it. Tags + description are first-class fields in the response so the agent can reason about the right resource before fetching.

### 2.4 Web UI

**Not in V0.** The operator uses the CLI. Section §2.4 is reserved for V1.

---

## 3. Request flows

### 3.1 Operator reads a secret

```
cli ──HTTP GET /api/secrets/aws/prod/stripe_key──▶ server
     header: X-Scopuli-Operator: scot_…

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
    header: X-Scopuli-Operator: scot_…
    body: {"path": "aws/prod/stripe_key", "value": "sk_live_…",
           "label": "Stripe production",
           "tags": ["aws", "prod", "stripe"],
           "description": "Production Stripe secret key. Used by the checkout API.",
           "metadata": {"owner_email": "alice@example.com", "cost_center": "eng-42"}}

server:
  1. auth middleware (operator token)
  2. validate metadata (D18/D19/D20): tag count, description length, metadata JSON shape
  3. crypto: AES-256-GCM seal(value) → ciphertext, nonce; AAD = SHA-256(path || description || version)
  4. upsert secrets (path, ciphertext, nonce, aad, tags, description, metadata, …)
  5. audit: append (actor_kind='operator', actor_id, ts, "write", path, "ok", …)
  6. respond 204
```

### 3.2.1 Operator annotates a secret (idempotent)

```
cli ──POST /api/secrets/{path}/annotate──▶ server
    header: X-Scopuli-Operator: scot_…
    body: {"add_tags": ["deprecated"], "remove_tags": ["prod"],
           "description": "ROTATED 2025-08-15. Use aws/prod/stripe_key_v2 instead.",
           "set_metadata": {"rotated_at": "2025-08-15"}, "unset_metadata": ["cost_center"]}

server:
  1. auth middleware (operator token)
  2. load existing row; merge tags; validate metadata (D18/D19/D20)
  3. if description changed: re-encrypt with new AAD, bump version
  4. update row; FTS triggers fire automatically
  5. audit: append ("secret.annotate", path=…, fields=[…], ok)
  6. respond 204
```

An `annotate` that only changes tags / metadata does **not** re-encrypt (description unchanged). The version field is only incremented on description change.

### 3.3 Operator creates an agent key

```
cli ──POST /api/keys──▶ server
    header: X-Scopuli-Operator: scot_…
    body: {"name": "linus-dev", "scope": "aws/dev/*,github/lucas/pat",
           "permissions": "read"}

server:
  1. auth middleware (operator token)
  2. generate 32 random bytes
     key = "sk_live_" + base62(body) + "_" + base62(sha256(body)[:4])
  3. hash = hex(SHA-256(full_key))
  4. insert keys (name, hash, prefix="sk_live_<first 8 of body>", scope, permissions, expires_at=NULL)
  5. audit: append ("key.create", name=linus-dev, scope=…, permissions=…)
  6. respond 200 with {"key": "sk_live_…_sRC4k1"}  // shown ONCE
```

### 3.4 Agent reads a secret (bad path)

```
agent ──HTTP GET /api/secrets/aws/prod/stripe_key──▶ server
       header: X-Scopuli-Key: sk_live_<…>_sRC4k1   (scope aws/dev/*)

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
       header: X-Scopuli-Key: sk_live_<…>_sRC4k1

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

### 3.7 Search (FTS5)

```
cli ──GET /api/secrets/search?q=stripe+production&limit=10──▶ server

server:
  1. SELECT id, path, label, tags FROM secrets
     JOIN secrets_fts ON secrets_fts.rowid = secrets.id
     WHERE secrets_fts MATCH ?
     ORDER BY rank
     LIMIT ?;
  2. (no scope check for operator; for agent keys, post-filter by scope)
  3. audit: append ("search", query=…, kind="secrets", result_count=…)
  4. respond 200 [{path, label, tags, description, metadata, _score}]
```

The same shape runs for `keys` searching. FTS5 returns BM25-ranked results; we expose `_score` to the caller so the CLI can show ordering.

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
  prefix       TEXT NOT NULL,           -- "scot_live_<first 8 of body>" — display only
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE INDEX operators_hash_idx ON operators(hash);

CREATE TABLE secrets (
  id                       INTEGER PRIMARY KEY,
  path                     TEXT NOT NULL UNIQUE,
  label                    TEXT,
  ciphertext               BLOB NOT NULL,
  nonce                    BLOB NOT NULL,            -- 12 bytes
  aad                      BLOB NOT NULL,            -- SHA-256(path || description || uint64_be(version))
  tags                     TEXT NOT NULL DEFAULT '',  -- CSV, max 20 entries, 64 chars each
  description              TEXT NOT NULL DEFAULT '',  -- Markdown, max 8 KB
  metadata                 TEXT NOT NULL DEFAULT '{}',-- JSON object, max 32 pairs (k:64, v:256)
  created_at               INTEGER NOT NULL,
  updated_at               INTEGER NOT NULL,
  description_updated_at   INTEGER,
  metadata_updated_at      INTEGER,
  version                  INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX secrets_path_idx ON secrets(path);
CREATE INDEX secrets_tags_idx ON secrets(tags);

CREATE TABLE keys (
  id                       INTEGER PRIMARY KEY,
  name                     TEXT NOT NULL UNIQUE,
  hash                     TEXT NOT NULL,           -- hex(SHA-256(full_key))
  prefix                   TEXT NOT NULL,           -- "sk_live_<first 8 of body>"
  scope                    TEXT NOT NULL,           -- CSV of glob patterns
  permissions              TEXT NOT NULL,           -- 'read' | 'manage'
  tags                     TEXT NOT NULL DEFAULT '',  -- CSV, max 20 entries, 64 chars each
  description              TEXT NOT NULL DEFAULT '',  -- Markdown, max 8 KB
  metadata                 TEXT NOT NULL DEFAULT '{}',-- JSON object, max 32 pairs
  created_at               INTEGER NOT NULL,
  expires_at               INTEGER,                 -- NULL = no expiry
  revoked_at               INTEGER,
  last_used_at             INTEGER,
  description_updated_at   INTEGER,
  metadata_updated_at      INTEGER
);
CREATE INDEX keys_hash_idx ON keys(hash);
CREATE INDEX keys_tags_idx ON keys(tags);

-- V0 V0: FTS5 search across description + flattened metadata.
-- Triggers below keep these in sync.
CREATE VIRTUAL TABLE secrets_fts USING fts5(
  path,
  description,
  metadata_text,
  tokenize='unicode61 remove_diacritics 2'
);
CREATE VIRTUAL TABLE keys_fts USING fts5(
  name,
  description,
  metadata_text,
  tokenize='unicode61 remove_diacritics 2'
);

-- Triggers (kept inline so the schema is self-documenting)
CREATE TRIGGER secrets_ai AFTER INSERT ON secrets BEGIN
  INSERT INTO secrets_fts(rowid, path, description, metadata_text)
    VALUES (new.id, new.path, new.description,
            json_flatten(new.metadata));
END;
CREATE TRIGGER secrets_au AFTER UPDATE ON secrets BEGIN
  INSERT INTO secrets_fts(secret_fts, rowid, path, description, metadata_text)
    VALUES ('delete', old.id, old.path, old.description, json_flatten(old.metadata));
  INSERT INTO secrets_fts(rowid, path, description, metadata_text)
    VALUES (new.id, new.path, new.description, json_flatten(new.metadata));
END;
CREATE TRIGGER secrets_ad AFTER DELETE ON secrets BEGIN
  INSERT INTO secrets_fts(secret_fts, rowid, path, description, metadata_text)
    VALUES ('delete', old.id, old.path, old.description, json_flatten(old.metadata));
END;
-- (same shape for keys_fts triggers)

CREATE TABLE audit (
  id          INTEGER PRIMARY KEY,
  ts          INTEGER NOT NULL,
  actor_kind  TEXT NOT NULL,            -- 'operator' | 'key'
  actor_id    INTEGER NOT NULL,
  action      TEXT NOT NULL,            -- 'read' | 'write' | 'delete' | 'denied:<reason>' | 'key.create' | 'key.revoke' | 'key.update' | 'secret.annotate' | 'key.audit' | 'audit.verify' | 'search' | 'snapshot' | 'restore' | 'operator.rotate'
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
aad     = SHA-256(path || description || uint64_be(version))
cipher  = AES-256-GCM-Encrypt(KEK, nonce, plaintext, aad)
stored  = { ciphertext, nonce, aad, version }
```

The AAD binds the ciphertext to the path, **description**, and version. An attacker who swaps ciphertexts between two rows can't get away with it — the AAD won't match on decrypt. **The description participates in the AAD** so that a description edit cannot be rolled back without re-encrypting (this is the desired property: editing a description is a write to the secret, recorded in audit).

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
  scopuli:
    image: ghcr.io/lucaspdude/scopuli:v0
    restart: unless-stopped
    environment:
      MASTER_PASSWORD:                # required, no default
      SCOPULI_BIND: "127.0.0.1:8080"
      SCOPULI_DB_PATH: "/data/vault.db"
      SCOPULI_LOG_LEVEL: "info"
      SCOPULI_KEY_DEFAULT_TTL: ""  # blank = no default
    volumes:
      - scopuli-data:/data
    # no :8080 published by default — operator puts a reverse proxy in front
    # or runs the CLI from the LXC host
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/healthz"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  scopuli-data:
```

### 5.2 Reverse proxy (LAN / public exposure)

Operator runs Caddy or Nginx in front. Example Caddyfile:

```
vault.example.com {
  reverse_proxy 127.0.0.1:8080
}
```

`SCOPULI_BIND` is set to `0.0.0.0:8080` in the container (or `127.0.0.1` if the reverse proxy runs on the same host in a separate container).

### 5.3 Process model

- One process. No worker pool. SQLite serializes writes anyway.
- Long-lived DB connection. SQLCipher's KDF runs once on connection open; we already do the outer Argon2id on master-password entry, so we don't pay that cost twice.
- Graceful shutdown on SIGTERM: drain in-flight requests, flush audit, close DB, exit.

## 6. Configuration reference (V0)

All settings come from env vars. No config file in V0.

| Variable | Required | Default | Description |
|---|---|---|---|
| `MASTER_PASSWORD` | **yes** | — | Master password. Server exits on boot if missing/empty. |
| `SCOPULI_BIND` | no | `127.0.0.1:8080` | Listen address. Set to `0.0.0.0:8080` when a reverse proxy is in front. |
| `SCOPULI_DB_PATH` | no | `/data/vault.db` | Path to the SQLCipher file. |
| `SCOPULI_LOG_LEVEL` | no | `info` | `debug` / `info` / `warn` / `error`. |
| `SCOPULI_KEY_DEFAULT_TTL` | no | `""` (no default) | Suggested default expiry on `keys create`. Accepts Go duration strings. |
| `SCOPULI_RATE_LIMIT_RPS` | no | `20` | Per-token bucket for unauthenticated endpoints. |
| `SCOPULI_AGENT_KEY_RPS` | no | `100` | Per-agent-key token bucket. |

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
- Image: `ghcr.io/lucaspdude/scopuli:v0`, `v0.0.1`, `latest`.

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