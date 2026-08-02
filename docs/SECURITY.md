# cred-share — Security Design (V0)

> Companion to [`PLAN.md`](./PLAN.md) and [`ARCHITECTURE.md`](./ARCHITECTURE.md).
> Goal of this doc: define the **threat model**, justify every cryptographic choice, and document the security-relevant behaviors that must hold for V0 to ship.

---

## 1. Threat model

We are explicit about what we're defending against and what we are **not**. This is a single-operator, homelab-LXC secret manager — not a multi-tenant SaaS.

### 1.1 In scope (must defend)

| Attacker | Capability | What they get |
|---|---|---|
| Disk thief | Pulls the LXC's disk or a backup of `/data` | A SQLCipher file. No master password. |
| Compromised agent key holder | Has a valid `csk_live_…` key | Access **only** to secrets inside their scope, **only** with their permission. Every access is logged. Key can be revoked instantly. |
| Curious operator's roommate | Local network access, can hit `127.0.0.1:8080` from inside the LXC | Nothing if they don't know the master password. (See §1.3.) |
| Misconfigured backup | The vault file lands in an off-host location | Still useless without the master password. |
| Insider tampering | Someone with read access to the .db tries to rewrite audit entries | Hash chain + HMAC detects it. `audit verify` flags the gap. |
| Replay attack on the API | Old request, replayed | Stateless endpoints + session cookies with `HttpOnly`, `Secure`, `SameSite=Lax` make this benign. |

### 1.2 In scope (defense-in-depth, not load-bearing for V0)

- **Rate limiting** on `/login` and the master-password endpoints. Bucket per IP, default 20 RPS, with backoff.
- **Request body size cap** (256 KB default).
- **TLS** when bound to anything other than `127.0.0.1`. We don't terminate TLS in the container in V0; the operator is expected to put a reverse proxy in front if LAN-exposed.
- **Minimal HTTP headers** — no referrer leak, no Server banner revealing version.

### 1.3 Out of scope (V0, acknowledged)

- **Cold-boot / RAM scraping** of a running vault process. The KEK and the audit HMAC key live in process memory. If the attacker can read process memory, we lose. We mitigate by using `madvise(MADV_DONTDUMP)` and `mlock` (where available) for sensitive buffers — but we are not betting on it.
- **Compromise of the LXC's root user / container escape.** Root in the container can read the master password env var and the DB file. That's the trust boundary; we assume the operator keeps the LXC hardened.
- **Side-channel attacks on AES-GCM.** No exotic mitigations (constant-time nonce generation isn't a thing for AES-GCM anyway since the nonce is just a counter / random).
- **Quantum**. AES-256 has effectively no quantum speedup below Grover; not a V0 concern.
- **Coercion / rubber-hose.** Out of scope of crypto entirely.
- **Multi-operator concurrent use.** Single-operator model; no sharing of the master password, no split-knowledge unseal. (Shamir shards / auto-unseal are parked for V1.)
- **Server-side compromise while running.** A 0-day in the server binary or its deps would expose in-memory plaintext during a request. V0 ships no W^X mitigations beyond the default Go runtime.

### 1.4 Trust boundary diagram

```
┌──────────────────────────────────────────────────────────────┐
│ TRUSTED                    │ cred-share process                │
│  ┌──────────────────────┐  │                                  │
│  │ Master password (env)│──┼──▶ Argon2id → KEK (32B) in RAM   │
│  └──────────────────────┘  │      │                            │
│  ┌──────────────────────┐  │      ▼                            │
│  │ /data/vault.db       │──┼──▶ SQLCipher (raw-key) + AEAD    │
│  │ (SQLCipher-encrypted)│  │      │                            │
│  └──────────────────────┘  │      ▼                            │
│  ┌──────────────────────┐  │  ┌──────────────────────────┐    │
│  │ Agent API key (HTTP) │──┼──▶│ Auth + scope check       │    │
│  └──────────────────────┘  │  └──────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
                              │
UNTRUSTED (LAN / internet)    │  (if reverse proxy + TLS)
                              │
```

Everything inside the trust boundary is at the mercy of whoever controls the LXC root. Everything outside it sees ciphertext or nothing.

---

## 2. Cryptographic design

### 2.1 Primitives (V0)

| Purpose | Algorithm | Source |
|---|---|---|
| Master-password KDF | **Argon2id** (m=64 MiB, t=3, p=1) | `golang.org/x/crypto/argon2` |
| Per-secret AEAD | **AES-256-GCM** | `crypto/aes` + `crypto/cipher` |
| Agent-key hash | **SHA-256** | `crypto/sha256` |
| Audit chain | **SHA-256 hash chain + HMAC-SHA-256** | `crypto/sha256`, `crypto/hmac` |
| Random | **`crypto/rand`** (os-specific CSPRNG) | stdlib |
| Token encoding | **base64url** (no padding) for KEK/HMAC keys; **base62** for API key body | hand-rolled base62 |
| SQLCipher page encryption | **AES-256-CBC** (SQLCipher default), fed raw-key | SQLCipher |

#### 2.1.1 Why Argon2id with these parameters

OWASP [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) recommends Argon2id with a minimum of `m=19 MiB, t=2, p=1`. We pick `m=64 MiB, t=3, p=1` because:

- A single-operator homelab has effectively one login per (re)boot of the container. We can afford ~200ms of KDF work.
- 64 MiB resists GPU attacks better than 19 MiB without making the boot painful.
- `t=3` (vs the minimum `t=2`) adds a ~50% margin against future hash-rate improvements.

Worst-case boot delay on the operator's hardware: ~250–400 ms. Acceptable.

#### 2.1.2 Why AES-256-GCM, not XChaCha20-Poly1305

Both are AEAD. AES-GCM wins for V0 because:

- Hardware acceleration (AES-NI) is everywhere; XChaCha20 is software-only.
- Go's stdlib has `crypto/aes` + `crypto/cipher.NewGCM`. Zero external deps for the AEAD path.
- The 96-bit nonce is fine here because we use **random** nonces from `crypto/rand`, not counters. Birthday-bound collision probability for a single secret is negligible (12 bytes × 2^32 random nonces → ~2^-32 chance).

#### 2.1.3 Why we feed SQLCipher a raw key instead of a passphrase

SQLCipher's default PBKDF2 is fine, but we already have Argon2id going on — running two KDFs is wasteful and complicates master-password rotation (we'd have to re-encrypt with the new derived key **and** tell SQLCipher to re-derive its own key from the new passphrase). With a raw-key approach, the SQLCipher KDF is bypassed (`PRAGMA kdf_iter = 1`) and we own the rotation end-to-end. Trade-off: the on-disk format leaks that the SQLCipher key is "high-entropy, not a passphrase" — fine for our threat model, since the SQLCipher file is never exposed without the KEK layer on top.

### 2.2 Key hierarchy

```
MASTER_PASSWORD (env var)
  │
  │ Argon2id(salt_A, m=64M, t=3, p=1)
  ▼
KEK (32B, lives in process memory only)
  │
  │ AES-256-GCM(kek_check = "ok", nonce_zero, aad = "kek-check-v1")
  ▼
KEK self-test row in meta table
  │ (loaded at boot, verified before accepting any request)
  │
  │ AES-256-GCM(plaintext, nonce_random, aad = SHA256(path||label||version))
  ▼
Stored ciphertext for each secret

MASTER_PASSWORD (env var)
  │
  │ HKDF(salt_B, info = "audit-hmac-v1")
  ▼
AUDIT_HMAC_KEY (32B, lives in process memory only)
  │
  │ HMAC-SHA-256(prev_hash || canonical_json(entry_without_mac))
  ▼
Audit chain MAC per row
```

Two keys derived from one master password via two distinct salts (`salt_A` for the KEK, `salt_B` for the audit HMAC). Salts are stored in `meta.kdf_salt` and `meta.hmac_key_salt` — they don't need to be secret.

### 2.3 Secret encryption (write)

```text
plaintext  = UTF-8 bytes of the secret value (e.g., "sk_live_…")
path       = the secret's path (e.g., "aws/dev/stripe_key")
label      = optional human-readable label
version    = monotonic integer, bumped on every write

nonce      = 12 random bytes from crypto/rand
aad        = SHA-256( path || "\x00" || label || "\x00" || uint64_be(version) )

ciphertext, tag = AES-256-GCM-Encrypt( KEK, nonce, plaintext, aad )

INSERT INTO secrets (path, label, ciphertext, nonce, aad, version, …) VALUES (…)
```

Binding the AAD to `path` and `version` means an attacker who swaps ciphertexts between two rows can't get away with it — the AAD won't match.

### 2.4 Secret decryption (read)

Symmetric to 2.3. On a mismatch (wrong path in AAD, wrong version, GCM tag failure) the server returns 500 with no detail and logs `audit("error:decrypt_failed", path, key_id)`. We **never** leak whether the failure was a tag mismatch, an AAD mismatch, or a missing row — same error code for all three.

### 2.5 Agent key design

#### 2.5.1 Token format

```
csk_live_<base62 of 24 random bytes>_<base62 of first 4 bytes of SHA-256(body)>
└─┬─┘└─┬──┘ └───────────────────┬─────────────────────┘ └─────────┬──────────────┘
  │    │                       │                                  │
  │    │                       │                                  └─ checksum (offline
  │    │                       │                                     validity check, like
  │    │                       │                                     credit card Luhn)
  │    │                       └─ body: the actual secret material
  │    └─ env: "live" only in V0 (no test mode)
  └─ service prefix: "cred-share key"

Total: ~45 characters. Plenty of entropy (24 bytes ≈ 192 bits) plus a 4-byte
checksum. Birthday-bound collisions on 192 bits: never.
```

Stored form:
- `keys.hash`     = `hex(SHA-256(full_key))` — never reversible, used for lookups.
- `keys.prefix`   = `"csk_live_" + first 8 chars of body` — used in the listing UI so the operator can tell keys apart.

The plaintext key is shown to the operator **exactly once** (the `POST /keys` response). It is never logged, never stored, never displayed again. Loss of the key = revoke + re-create.

#### 2.5.2 Scope check

```text
key.scope     = "aws/dev/*,github/lucas/pat"   (CSV of glob patterns)
target.path   = "aws/dev/stripe_key"            (the secret being requested)
action        = "read" | "manage"

allowed = any glob in key.scope matches target.path
if action == "manage" and key.permissions == "read":
    allowed = false   # read-only keys can never write/delete
if !allowed:
    audit("denied:out_of_scope", path, key_id)
    respond 403
```

Glob matching: implementation is `path.Match` (Go) with `*` wildcards. No `**`, no character classes, no regex. Keep the mental model small.

### 2.6 Audit log integrity

Append-only table with hash chain + per-row HMAC. The HMAC key lives in `meta.hmac_key` (encrypted by SQLCipher at rest) and is re-derived from the master password on every boot.

```text
row(id, ts, key_id, action, path, result, prev_hash, hash, hmac)

canonical(entry) = stable JSON of {ts, key_id, action, path, result} with sorted keys
hash             = SHA-256(prev_hash || canonical(entry))
hmac             = HMAC-SHA-256(AUDIT_HMAC_KEY, hash)

INSERT: prev_hash = previous row's hash (or 32 zero bytes for id=1)
```

Verification walks the table in `id` order and asserts:

1. `hash == SHA-256(prev_hash || canonical(row))`
2. `hmac == HMAC-SHA-256(AUDIT_HMAC_KEY, hash)`

If either fails, return the broken row id and stop. The HMAC step is what catches a **delete-and-rewrite**: an attacker who can read the SQLCipher file but doesn't have the master password (and therefore not the HMAC key) can't forge a valid `hmac` for a tampered row.

### 2.7 What happens when the master password leaks

Two paths:

- **Path A — leak suspected, operator still has the password.** Rotate the master password. See §5. Rotation re-derives both the KEK and the audit HMAC key, and re-encrypts every secret's ciphertext (the audit HMAC key change invalidates all historical HMACs, but the chain hashes themselves are independent of the key, so the chain is preserved — we just record a "rotated at row N" event).
- **Path B — leak confirmed, attacker has the password AND a copy of the .db.** Game over. The attacker can derive the KEK and decrypt everything. Mitigations are operational: keep `MASTER_PASSWORD` out of shell history, out of process listings, only in the container's env (use Docker secrets or systemd `LoadCredential`).

V0 does **not** support Shamir / split-knowledge unseal. That is parked for V1 (see `PLAN.md` §2).

---

## 3. Authentication

### 3.1 Master password

- Single endpoint `POST /login` taking the master password in a JSON body.
- Server derives the KEK with Argon2id, opens the SQLCipher file, verifies `kek_check`, and creates a session row.
- Session cookie: 32 random bytes (hex), `HttpOnly`, `Secure` (when bound non-loopback), `SameSite=Lax`, lifetime `CRED_SHARE_SESSION_TTL` (default 8h).
- Rate limit: 5 attempts per IP per minute, exponential backoff after the third failure within 5 minutes.

### 3.2 Agent API keys

- Header: `X-Cred-Share-Key: csk_live_…_cRC4k1`
- Server validates format → looks up by SHA-256 hash → checks expiry and revocation.
- No session row created — each request is self-authenticating. (This is deliberate: an agent might use the key from many different processes.)
- Constant-time comparison via `subtle.ConstantTimeCompare` on the hash lookup result.
- Per-key rate limit: 100 RPS default, configurable later.

### 3.3 What's not in V0

- 2FA for the operator. (Single master password is V0's explicit ask.)
- Per-key IP allowlists. V1 candidate.
- OAuth/OIDC integration.

---

## 4. Hardening checklist (must-pass before V0 ships)

These are the things the code review / security review must verify. They are not tests in the literal sense — they are the list of claims the security doc makes about the system.

- [ ] `MASTER_PASSWORD` is read from env at boot; missing → process exits with non-zero code and a loud log line.
- [ ] Argon2id parameters match §2.1.1 and are stored in `meta.kdf_params`.
- [ ] SQLCipher is opened with the **raw** KEK bytes, not a passphrase (`PRAGMA key = "x'…'"`).
- [ ] Every secret write uses a fresh 12-byte random nonce from `crypto/rand`.
- [ ] AES-256-GCM tag failures are not distinguishable from "not found" in API responses.
- [ ] Every read/write/deny is appended to `audit` **before** the HTTP response is sent (best-effort; if the append fails, the request fails).
- [ ] `audit verify` recomputes the hash chain + HMAC and flags the first broken row.
- [ ] Agent keys are stored as SHA-256 only; the plaintext key is never logged, never written to disk.
- [ ] Session cookies have `HttpOnly`, `SameSite=Lax`, and `Secure` when not bound to loopback.
- [ ] Rate limits exist on `/login` and on API-key-authenticated endpoints.
- [ ] All dependencies pinned in `go.mod`; `govulncheck` is clean in CI.
- [ ] No use of `math/rand`, `crypto/sha1`, `crypto/md5`, `crypto/rc4`, `crypto/des`, or `crypto/tls` with insecure curves.
- [ ] Docker image is distroless / scratch — no shell, no package manager.
- [ ] Process drops to non-root UID (UID 65532) inside the container.
- [ ] No `O_CREATE` on DB files without mode `0600`.

---

## 5. Master-password rotation (operator flow, V0)

> V0 supports rotation. It's a little heavy (re-encrypts every secret) but it's the right thing for a single-operator system.

```
1.  Operator changes MASTER_PASSWORD in their secret manager.
2.  Operator restarts the container with the new password.
3.  Server boots with the new password, runs Argon2id, gets new_KEK.
4.  Server reads every secret's old ciphertext, decrypts with old_KEK,
    re-encrypts with new_KEK, writes the new ciphertext.
5.  Server writes the new kdf_salt + hmac_key_salt.
6.  Server derives a new AUDIT_HMAC_KEY from the new master password.
7.  Server appends an audit row: action="master.rotate", hmac=new HMAC over
    the hash, prev_hash=last pre-rotation row. Pre-rotation HMACs are now
    unverifiable; that's fine — `audit verify` reports "ok from rotation
    row forward" and the operator can document the rotation point.
8.  Keys table unchanged (the key hash doesn't depend on the master password).
```

Recovery if the operator forgets the master password: **none**. The KEK is gone. The audit log is gone. We document this in the README and the web UI login page.

---

## 6. Backup and recovery

**Backups** = a copy of `vault.db`. They're useless without the master password.

**Recommended backup flow:**

1. Take a hot copy of `/data/vault.db` (SQLite's `.backup` command, or just `cp` while the server is briefly paused — but the file is SQLCipher-encrypted so a hot copy is fine).
2. Store the copy somewhere off-host (rsync to NAS, `restic` to B2, whatever).
3. Store the master password in a separate system (password manager, paper in a safe, etc.).

**Restore** = `cp vault.db /data/vault.db && docker compose up -d`. No special tooling.

**No `pg_dump` equivalent needed** because the .db is a single file and is already encrypted.

---

## 7. References (research notes)

- OWASP [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — Argon2id parameter guidance.
- [Model Context Protocol — Tools spec](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) — tool definition requirements.
- [Model Context Protocol — Transports spec](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports) — stdio / Streamable HTTP.
- SQLCipher [performance guide](https://www.zetetic.net/sqlcipher/performance/) — pragmas and key-derivation caveats.
- [Designing API keys](https://vjay15.github.io/blog/apikeys/) (vjaylakshman, 2026) — prefix + body + checksum patterns, SHA-256-at-rest.
- [Bitwarden end-to-end encryption for secrets](https://bitwarden.com/blog/why-end-to-end-encryption-is-crucial-for-developer-secrets-management/) — reference architecture for a zero-knowledge vault.
- [HashiCorp Vault seal/unseal](https://developer.hashicorp.com/vault/docs/concepts/seal) — reference for what a "master key" means in a vault (we deliberately don't ship Shamir-shard unseal in V0).
- [Compliance by Design — tamper-proof audit logs](https://mattermost.com/blog/compliance-by-design-18-tips-to-implement-tamper-proof-audit-logs/) — patterns for append-only logs.
- [Building a tamper-evident audit log with SHA-256 hash chains](https://dev.to/veritaschain/building-a-tamper-evident-audit-log-with-sha-256-hash-chains-zero-dependencies-h0b) — practical implementation reference.