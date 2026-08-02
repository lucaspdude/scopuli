# cred-share — Security Design (V0)

> Reads with [`PLAN.md`](./PLAN.md) and [`ARCHITECTURE.md`](./ARCHITECTURE.md). Defines the threat model, justifies every cryptographic choice, and lists the security behaviors that must hold for V0 to ship.

---

## 1. Threat model

We are explicit about what we're defending against and what we are **not**. This is a single-operator, homelab-LXC-but-may-be-public secret manager.

### 1.1 In scope (must defend)

| Attacker | Capability | What they get |
|---|---|---|
| Disk thief | Pulls the LXC's disk or a backup of `/data` | A SQLCipher file. No master password. No KEK. |
| Compromised agent key holder | Has a valid `csk_live_…` key | Access **only** to secrets inside their scope, **only** with their permission. Every access is logged. Key can be revoked instantly. |
| Internet attacker (VPS deployment) | Reaches the public port | Can't authenticate without an operator token or agent key. Rate-limited. Every request is logged. |
| LAN attacker | Reaches the LAN port | Same posture as internet attacker — the auth model is the same. |
| Misconfigured backup | The vault file lands in an untrusted location | Useless without the master password OR the operator token. |
| Insider tampering | Someone with read access to the .db rewrites audit entries | Hash chain + HMAC detects it. `audit verify` flags the gap. |
| Coerced disclosure of operator token | Token is leaked | Operator rotates; old token is no longer valid. |
| Compromised CLI host | Attacker reads the local keychain | They get the operator token. Operator rotates after the incident. |

### 1.2 In scope (defense-in-depth, not load-bearing)

- **Rate limiting.** Per-IP on unauthenticated endpoints; per-token on authenticated endpoints. Backoff on repeated failures.
- **Request body size cap.** 256 KB default.
- **TLS.** Mandatory when bound to anything other than `127.0.0.1`. The Go server doesn't terminate TLS in V0; the operator runs a reverse proxy (Caddy / Nginx).
- **Minimal HTTP headers.** No referrer leak, no Server banner revealing version.

### 1.3 Out of scope (V0, acknowledged)

- **Cold-boot / RAM scraping** of a running vault process. The KEK and the audit HMAC key live in process memory. If the attacker can read process memory, we lose. We mitigate by using `madvise(MADV_DONTDUMP)` and `mlock` where available — but we are not betting on it.
- **Compromise of the LXC's root user / container escape.** Root in the container can read `MASTER_PASSWORD` and the DB file. That's the trust boundary; we assume the operator keeps the LXC hardened.
- **Side-channel attacks on AES-GCM.** No exotic mitigations.
- **Quantum.** AES-256 has effectively no quantum speedup below Grover; not a V0 concern.
- **Coercion / rubber-hose.** Out of scope of crypto entirely.
- **Split-knowledge unseal (Shamir shards).** Single-operator; one master password. Auto-unseal is V1.
- **Server-side compromise while running.** A 0-day in the server binary or its deps would expose in-memory plaintext during a request. V0 ships no W^X mitigations beyond the default Go runtime.

### 1.4 Trust boundary diagram

```
┌──────────────────────────────────────────────────────────────┐
│ TRUSTED                        │ cred-share process          │
│  ┌───────────────────────────┐ │                             │
│  │ MASTER_PASSWORD (env)    ─┼─▶ Argon2id → KEK (32B in RAM) │
│  └───────────────────────────┘ │      │                      │
│  ┌───────────────────────────┐ │      ▼                      │
│  │ /data/vault.db           ─┼─▶ SQLCipher (raw-key) + AEAD  │
│  │ (SQLCipher-encrypted)     │ │      │                      │
│  └───────────────────────────┘ │      ▼                      │
│  ┌───────────────────────────┐ │  ┌──────────────────────┐  │
│  │ Operator token (Keychain) │ │  │ Auth + scope check   │  │
│  │   or Agent key (env)     ─┼─▶│                      │  │
│  └───────────────────────────┘ │  └──────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                                │
UNTRUSTED (LAN / internet)      │  (if reverse proxy + TLS)
                                │
```

Everything inside the trust boundary is at the mercy of whoever controls the LXC root. Everything outside it sees ciphertext or nothing.

## 2. Cryptographic design

### 2.1 Primitives (V0)

| Purpose | Algorithm | Source |
|---|---|---|
| Master-password KDF | **Argon2id** (m=64 MiB, t=3, p=1) | `golang.org/x/crypto/argon2` |
| Operator-token / agent-key KDF | **SHA-256** (these are high-entropy already) | `crypto/sha256` |
| Per-secret AEAD | **AES-256-GCM** | `crypto/aes` + `crypto/cipher` |
| Audit chain | **SHA-256 hash chain + HMAC-SHA-256** | `crypto/sha256`, `crypto/hmac` |
| Random | **`crypto/rand`** (CSPRNG) | stdlib |
| Token encoding | **base64url** for operator token; **base62** for agent-key body | hand-rolled base62 |
| Backup encryption | **age** (X25519 + ChaCha20-Poly1305) | `filippo.io/age` |
| SQLCipher page encryption | **AES-256-CBC** (SQLCipher default), fed raw-key | SQLCipher |

### 2.2 Why Argon2id with these parameters

OWASP [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) recommends Argon2id with a minimum of `m=19 MiB, t=2, p=1`. We pick `m=64 MiB, t=3, p=1` because:

- A single-operator vault has effectively one Argon2id invocation per boot of the container. We can afford ~250–400 ms of KDF work.
- 64 MiB resists GPU attacks better than 19 MiB without making the boot painful.
- `t=3` (vs the minimum `t=2`) adds a ~50% margin against future hash-rate improvements.

Worst-case boot delay: ~250–400 ms. Acceptable.

### 2.3 Why AES-256-GCM, not XChaCha20-Poly1305

Both are AEAD. AES-GCM wins for V0 because:

- Hardware acceleration (AES-NI) is everywhere; XChaCha20 is software-only.
- Go's stdlib has `crypto/aes` + `crypto/cipher.NewGCM`. Zero external deps for the AEAD path.
- The 96-bit nonce is fine here because we use **random** nonces from `crypto/rand`, not counters. Birthday-bound collision probability for a single secret is negligible (12 bytes × 2^32 random nonces → ~2^-32 chance).

### 2.4 Why we feed SQLCipher a raw key instead of a passphrase

SQLCipher's default PBKDF2 is fine, but we already have Argon2id going on — running two KDFs is wasteful and complicates master-password rotation. With a raw-key approach, the SQLCipher KDF is bypassed (`PRAGMA kdf_iter = 1`) and we own the rotation end-to-end. Trade-off: the on-disk format leaks that the SQLCipher key is "high-entropy, not a passphrase" — fine for our threat model, since the SQLCipher file is never exposed without the KEK layer on top.

### 2.5 Key hierarchy

```
MASTER_PASSWORD (env var)
  │
  │ Argon2id(salt_A, m=64M, t=3, p=1)
  ▼
KEK (32B, lives in process memory only)
  │
  │ AES-256-GCM("ok", nonce_zero, aad="kek-check-v1")
  ▼
KEK self-test row in meta table
  │ (verified at boot before accepting any request)
  │
  │ AES-256-GCM(plaintext, nonce_random, aad = SHA256(path||label||version))
  ▼
Stored ciphertext for each secret

MASTER_PASSWORD (env var)
  │
  │ Argon2id(salt_B, m=64M, t=3, p=1)
  ▼
AUDIT_HMAC_KEY (32B, lives in process memory only)
  │
  │ HMAC-SHA-256(prev_hash || canonical_json(entry_without_mac))
  ▼
Audit chain MAC per row
```

Two keys derived from one master password via two distinct salts (`salt_A` for the KEK, `salt_B` for the audit HMAC). Salts are stored in `meta.kdf_salt` and `meta.hmac_key_salt` — they don't need to be secret.

### 2.6 Secret encryption (write)

```text
plaintext   = UTF-8 bytes of the secret value (e.g., "sk_live_…")
path        = the secret's path (e.g., "aws/dev/stripe_key")
label       = optional human-readable label
version     = monotonic integer, bumped on every write

nonce       = 12 random bytes from crypto/rand
aad         = SHA-256( path || "\x00" || label || "\x00" || uint64_be(version) )

ciphertext, tag = AES-256-GCM-Encrypt( KEK, nonce, plaintext, aad )

INSERT INTO secrets (path, label, ciphertext, nonce, aad, version, …) VALUES (…)
```

Binding the AAD to `path` and `version` means an attacker who swaps ciphertexts between two rows can't get away with it — the AAD won't match.

### 2.7 Secret decryption (read)

Symmetric to 2.6. On a mismatch (wrong path in AAD, wrong version, GCM tag failure) the server returns 500 with no detail and logs `audit("error:decrypt_failed", path, key_id)`. We **never** leak whether the failure was a tag mismatch, an AAD mismatch, or a missing row — same error code for all three.

### 2.8 Agent key design

#### 2.8.1 Token format

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

Total: ~45 characters. 24 bytes ≈ 192 bits of entropy plus a 4-byte checksum.
```

Stored form:
- `keys.hash`    = `hex(SHA-256(full_key))` — never reversible, used for lookups.
- `keys.prefix`  = `"csk_live_" + first 8 chars of body` — used in the listing UI so the operator can tell keys apart.

The plaintext key is shown to the operator **exactly once** (the `POST /keys` response). It is never logged, never stored, never displayed again. Loss of the key = revoke + re-create.

#### 2.8.2 Operator token format

```
csot_live_<base64url of 32 random bytes>
```

- 32 bytes ≈ 256 bits of entropy.
- Stored as `hex(SHA-256(operator_token))` in the `operators` table.
- Printed to stdout exactly once on first boot.
- No checksum (operator token is rare and operator-typed; the cost of a typo is a re-login).

#### 2.8.3 Scope check

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

Glob matching: Go's `path.Match` with `*` wildcards. No `**`, no character classes, no regex. Keep the mental model small.

## 3. Authentication

### 3.1 Operator token

Single credential for the operator. Sent on every request:

```
X-Cred-Share-Operator: csot_live_…
```

Server validates by SHA-256-hashing the token and looking it up in the `operators` table. The CLI stores the token in macOS Keychain (via `github.com/zalando/go-keyring`) or Linux secret service. File-mode-locked fallback (`~/.config/cred-share/credentials`, mode 0600) if the keychain is unavailable.

### 3.2 Agent API keys

- Header: `X-Cred-Share-Key: csk_live_…_cRC4k1`
- Server validates format → looks up by SHA-256 hash → checks expiry and revocation.
- No session row created — each request is self-authenticating.
- Constant-time comparison via `subtle.ConstantTimeCompare` on the hash lookup result.
- Per-key rate limit: 100 RPS default.

### 3.3 What's not in V0

- 2FA for the operator.
- Per-key IP allowlists.
- OAuth/OIDC integration.

## 4. Hardening checklist (must-pass before V0 ships)

- [ ] `MASTER_PASSWORD` is read from env at boot; missing → process exits with non-zero code and a loud log line.
- [ ] Argon2id parameters match §2.2 and are stored in `meta.kdf_params`.
- [ ] SQLCipher is opened with the **raw** KEK bytes, not a passphrase (`PRAGMA key = "x'…'"`).
- [ ] Every secret write uses a fresh 12-byte random nonce from `crypto/rand`.
- [ ] AES-256-GCM tag failures are not distinguishable from "not found" in API responses.
- [ ] Every read/write/deny is appended to `audit` **before** the HTTP response is sent (within the same transaction where possible).
- [ ] `audit verify` recomputes the hash chain + HMAC and flags the first broken row.
- [ ] Agent keys are stored as SHA-256 only; the plaintext key is never logged, never written to disk.
- [ ] Operator token is stored as SHA-256 only; the plaintext is only printed once on first boot.
- [ ] Rate limits exist on unauthenticated endpoints and on agent-key-authenticated endpoints.
- [ ] All dependencies pinned in `go.mod`; `govulncheck` is clean in CI.
- [ ] No use of `math/rand`, `crypto/sha1`, `crypto/md5`, `crypto/rc4`, `crypto/des`, or `crypto/tls` with insecure curves.
- [ ] Docker image is distroless — no shell, no package manager.
- [ ] Process drops to non-root UID (UID 65532) inside the container.
- [ ] All files written by the server have mode `0600`.
- [ ] The CLI uses constant-time comparison for hash lookups.
- [ ] The CLI never logs the operator token or agent key (compile-time check or runtime scrubbing).

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
    row forward".
8.  Keys table unchanged (the key hash doesn't depend on the master password).
9.  Operator token is unchanged (its hash is independent of the master password).
```

Triggered via `cred-share operator rotate --from-env MASTER_PASSWORD` from inside the container. The CLI reads the new env var, prompts for the old master password (or reads it from a separate file), and triggers the rotation.

Recovery if the operator forgets the master password: **none**. The KEK is gone. The audit log is gone. We document this in the README.

## 6. Operator-token rotation

If the operator token is leaked (or the operator wants to retire a device):

```
docker exec -it cred-share cred-share operator rotate --from-env MASTER_PASSWORD
# prints the new operator token ONCE
```

The new token's hash is written to the `operators` table; the old token is gone. The operator updates the CLI on every host that uses the vault.

## 7. Backup and recovery

**Backups** = either an `age`-encrypted export bundle, or a raw copy of the SQLCipher file. Both are useless without the master password.

**`cred-share snapshot` flow:**

1. Server opens a SQLite read transaction.
2. Server emits the SQLCipher file contents (or a JSON-encoded snapshot) to a writer.
3. The writer encrypts the payload using `age` with a passphrase-derived X25519 key.
4. The output is a single `.age` file.

**`cred-share restore` flow:**

1. Operator stops the running container.
2. Operator runs `cred-share restore --in bundle.age --into /data/vault.db`.
3. The CLI decrypts the bundle with the passphrase, writes the SQLCipher file.
4. Operator starts the container with the master password.

**Plain file copy** is also fine for trusted destinations. The .db is already SQLCipher-encrypted.

**No `pg_dump` equivalent needed** because the .db is a single file and is already encrypted.

## 8. References (research notes)

- OWASP [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — Argon2id parameter guidance.
- [Model Context Protocol — Tools spec](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) — tool definition requirements.
- [Model Context Protocol — Transports spec](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports) — stdio / Streamable HTTP.
- SQLCipher [performance guide](https://www.zetetic.net/sqlcipher/performance/) — pragmas and key-derivation caveats.
- [Designing API keys](https://vjay15.github.io/blog/apikeys/) (vjaylakshman, 2026) — prefix + body + checksum patterns, SHA-256-at-rest.
- [Bitwarden end-to-end encryption for secrets](https://bitwarden.com/blog/why-end-to-end-encryption-is-crucial-for-developer-secrets-management/) — reference architecture for a zero-knowledge vault.
- [HashiCorp Vault seal/unseal](https://developer.hashicorp.com/vault/docs/concepts/seal) — reference for what a "master key" means in a vault.
- [Compliance by Design — tamper-proof audit logs](https://mattermost.com/blog/compliance-by-design-18-tips-to-implement-tamper-proof-audit-logs/) — patterns for append-only logs.
- [Building a tamper-evident audit log with SHA-256 hash chains](https://dev.to/veritaschain/building-a-tamper-evident-audit-log-with-sha-256-hash-chains-zero-dependencies-h0b) — practical implementation reference.
- [filippo.io/age](https://github.com/FiloSottile/age) — modern encryption library for backups.