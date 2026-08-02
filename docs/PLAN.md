# cred-share — MVP Plan (V0)

> **Status:** research + planning phase. No code yet.
> **Goal of this doc:** spell out the smallest thing we can ship that meets the user's stated requirements, and surface the decisions we need before writing code.

---

## 1. Problem statement

Build a self-hostable service that lets a single operator store credentials ("secrets") and share subsets of them with autonomous agents and humans, with:

- A single master credential known to the operator (no per-user account system in V0).
- Scoped, revocable API keys for agents/humans. A key can only see / mutate secrets inside its scope.
- An audit trail of every secret read and write, tagged with the key that did it.
- A way for agents to actually pull secrets: either from a CLI they can shell out to, or via MCP (Model Context Protocol) so LLM-based agents can call tools directly.
- Runs in a Docker container on a homelab LXC. SQLite-class storage. No managed services.

## 2. Non-goals (explicitly out of scope for V0)

Anything below is **not** in V0. If we add them, they go on the V1 list.

| Out of scope (V0) | Why |
|---|---|
| Multi-user accounts / RBAC matrix beyond "owner" and "key" | User is the only human; over-engineering it now creates attack surface. |
| Secret versioning, history, rollback | Audit log gives us "who read what" but not "what did the secret used to be". Fine for V0. |
| Replication, HA, clustering | Single-LXC homelab target. |
| Hardware security modules (HSM), auto-unseal, Shamir shards | User explicitly said master password can be an env var. KISS. |
| Dynamic secrets (DB creds that rotate on demand) | Out of scope; static creds only. |
| Secret rotation policies, expiry automation | Manual rotation in V0. |
| Web UI for fancy things (search, sharing, org charts) | Barebones list/create/edit/delete only — or even none, if CLI suffices. |
| Built-in OAuth/OIDC provider for the front-end | No third-party IdP integration. Front-end uses session cookie + the master password. |
| Cryptographic secret sharding across multiple operators | One-operator homelab. |

## 3. MVP must-haves

These map 1:1 to the requirements in the prompt.

1. **Runs with `docker run` or `docker compose up`.** Single container, SQLite database file persisted on a volume.
2. **Master password via environment variable** (`MASTER_PASSWORD`) — set in the container's environment. The server requires it on boot; if missing, the container exits loudly.
3. **Encrypted-at-rest SQLite database.** SQLCipher. Master password is used to derive an in-memory key (KEK) on boot; all secrets are encrypted before being written.
4. **Two ways to manage secrets** — pick at least one, ship both if time allows:
   - **CLI** (`cred-share secret set/get/list/delete`) that talks to the running server over HTTP (localhost or LAN).
   - **Barebones web UI** (login → list/create/edit/delete secrets → manage keys → view audit log).
5. **Scoped agent keys.** Operator creates a key, names it (e.g., `linus-dev`), grants:
   - A scope — a set of labels/paths the key can act on (e.g., `aws/dev/*`, `github/lucas/*`).
   - Permissions — at minimum `read` and `manage` (manage = create/edit/delete within scope).
   - An expiry (optional, recommended).
6. **Scope enforcement is server-side and unconditional.** Every request checks: does this key's scope intersect the target secret's path? If not, 403, with an audit log entry tagged `denied`.
7. **Every read/write/deny is logged.** Audit log is append-only and tamper-evident (hash chain + HMAC).
8. **Keys can be revoked.** Revocation is immediate; subsequent requests with the revoked key get 401. The revoked key record + revocation timestamp is kept for audit (no hard delete in V0).
9. **Agents consume secrets** via:
   - **CLI** (`cred-share get aws/dev/stripe_key` → prints the plaintext value to stdout, designed to be piped into other tools).
   - **MCP server mode** (`cred-share mcp-serve` exposes `list`, `get`, `set`, `delete` as MCP tools over stdio, so agents like Claude Code / Cursor / OpenHands can call them without shelling out).

## 4. User flows (V0)

### 4.1 Operator: first boot

```
docker run -d \
  -e MASTER_PASSWORD=<long-random-string-from-password-manager> \
  -v cred-share-data:/data \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/<you>/cred-share:v0
```

Server logs `vault unlocked` and binds to `127.0.0.1:8080`. No admin user — anyone who can reach the port and knows the master password is admin in V0.

### 4.2 Operator: create a secret via CLI

```bash
cred-share login http://127.0.0.1:8080 --master-password-stdin
cred-share secret set aws/prod/stripe_key --value-from-stdin
cred-share secret set github/lucas/pat --value-from-stdin
```

### 4.3 Operator: create a scoped agent key

```bash
cred-share keys create linus-dev \
  --scope "aws/dev/*,github/lucas/*" \
  --permission read \
  --expires-in 30d
# prints: csk_live_<base62>_cRC4k1
# (only shown once — operator copies it into the agent's env)
```

### 4.4 Agent: read a secret

```bash
# In the agent's runtime
export CRED_SHARE_URL=http://127.0.0.1:8080
export CRED_SHARE_KEY=csk_live_<...>_cRC4k1
STRIPE_KEY=$(cred-share get aws/dev/stripe_key)
```

Or via MCP:

```jsonc
// tool call from agent runtime
{"tool": "get_secret", "args": {"path": "aws/dev/stripe_key"}}
```

### 4.5 Operator: revoke a key

```bash
cred-share keys revoke linus-dev
# Server marks the key revoked. The next request from that key returns 401.
# Audit log records the revoke event with the operator's session.
```

### 4.6 Operator: review the audit log

```bash
cred-share audit list --since 24h --key linus-dev
cred-share audit verify           # recomputes hash chain + HMAC; reports any gap
```

## 5. Component overview

```
┌────────────────────────────────────────────────────────────────────┐
│                       cred-share container                         │
│                                                                    │
│   ┌────────────┐    HTTP /api/*    ┌──────────────────────────┐    │
│   │ Web UI     │◀────────────────▶│  Server (Go)             │    │
│   │ (htmx-ish) │                   │  ├─ Auth middleware       │    │
│   └────────────┘                   │  ├─ Scope enforcer        │    │
│                                    │  ├─ Audit logger (chain)  │    │
│   ┌────────────┐    HTTP /api/*    │  ├─ Crypto module         │    │
│   │ CLI / MCP  │◀────────────────▶│  └─ SQLCipher repository  │    │
│   │ (single    │    stdio MCP      │                          │    │
│   │  binary)   │                   └──────────┬───────────────┘    │
│   └────────────┘                              │                    │
│                                    ┌──────────▼───────────────┐    │
│                                    │  /data/vault.db          │    │
│                                    │  (SQLCipher, AES-256)    │    │
│                                    └──────────────────────────┘    │
└────────────────────────────────────────────────────────────────────┘
```

Detailed component responsibilities and request flows live in [`ARCHITECTURE.md`](./ARCHITECTURE.md). The crypto design + threat model live in [`SECURITY.md`](./SECURITY.md).

## 6. Data model (sketch)

| Table       | Columns (abridged)                                                                                                |
|-------------|-------------------------------------------------------------------------------------------------------------------|
| `meta`      | `k TEXT PRIMARY KEY, v BLOB` — holds `kdf_params`, `schema_version`, `hmac_key_salt` etc.                          |
| `secrets`   | `id INTEGER PK, path TEXT UNIQUE, label TEXT, ciphertext BLOB, nonce BLOB, aad BLOB, created_at, updated_at, version` |
| `keys`      | `id INTEGER PK, name TEXT UNIQUE, hash TEXT, prefix TEXT, scope TEXT, permissions TEXT, created_at, expires_at, revoked_at, last_used_at` |
| `audit`     | `id INTEGER PK, ts INTEGER, key_id INTEGER NULL, action TEXT, path TEXT, result TEXT, prev_hash BLOB, hash BLOB, hmac BLOB` |
| `sessions`  | `id TEXT PK, created_at, expires_at, is_master INTEGER` — front-end session cookies.                               |

Full schema, indexes, and SQLCipher pragmas: see `ARCHITECTURE.md` §4.

## 7. Delivery plan (V0 only)

Roughly ordered so each step is independently demoable.

1. **Scaffolding.** Repo, Dockerfile, docker-compose, CI smoke test that boots the container with a master password, exposes `/healthz`, exits cleanly when password is missing.
2. **Storage + crypto.** SQLCipher integration. `secrets` table CRUD. Argon2id KDF, AES-256-GCM per-secret encryption. Unit tests with a fixed test vector.
3. **HTTP API + master-password auth.** `POST /api/login`, session cookie, `/api/secrets` endpoints with the master session.
4. **Scoped agent keys.** `keys` table CRUD, key generation, hash+prefix storage, `X-Cred-Share-Key` auth middleware, scope check on every secret endpoint.
5. **Audit log.** Append-only `audit` table with SHA-256 hash chain + HMAC, `/api/audit/list`, `/api/audit/verify`.
6. **Barebones web UI.** Login → secrets list → secret create/edit/delete → keys list/create/revoke → audit viewer. Server-rendered HTML with htmx for interactivity. One CSS file. No JS framework.
7. **CLI.** Single Go binary that wraps the HTTP API. `login`, `secret get/set/list/delete`, `keys create/list/revoke`, `audit list/verify`, `mcp-serve`.
8. **MCP server mode.** `cred-share mcp-serve` starts an MCP server over stdio exposing the same tools as the CLI subcommands. Speaks JSON-RPC 2.0 per the [MCP spec](https://modelcontextprotocol.io/specification/2025-06-18/server/tools).
9. **Documentation.** `README.md` with quickstart (docker run), `docs/OPERATIONS.md` covering backup/restore (just `cp` the .db file + remember the master password) and key rotation.
10. **Hardening pass.** Run through [`SECURITY.md`](./SECURITY.md) checklist. Add rate limiting, lockout, request size limits, dependency audit in CI.

## 8. Out-of-V0 ideas (parking lot)

- Per-secret ACL (read allowed by these keys, manage by those keys). The scope model already covers most of this.
- Path-based policy DSL (`allow` / `deny` rules, IP allowlists for keys).
- Webhook on key revocation to nudge the agent owner.
- Optional encryption-at-rest for secrets beyond what SQLCipher gives us (defense in depth — wrap the ciphertext blob in another AES layer keyed off an HMAC derived from the path + nonce).
- Backup export → encrypted bundle (e.g., `age`).
- LDAP / OIDC for the front-end (multi-operator teams).

---

## 9. Open decisions for the user

These are blocking. See [`DECISIONS.md`](./DECISIONS.md) for the questionnaire.

- **D1.** Language/runtime for the server (recommendation: **Go** — single static binary, great crypto stdlib, official MCP SDK).
- **D2.** Client surface for V0 (recommendation: **CLI + MCP, skip the web UI for V0.5** — web UI is nice-to-have, not load-bearing for an agent-first homelab).
- **D3.** Network exposure (recommendation: **bind 127.0.0.1 only**, agents on the same host talk to it directly; LAN exposure only behind a reverse proxy with TLS).
- **D4.** Scope syntax (recommendation: **slash-paths with glob** — `aws/dev/*`, `github/lucas/pat`).
- **D5.** Master password source (recommendation: **env var only** — what the user asked for; CLI can read it interactively too if the operator prefers).