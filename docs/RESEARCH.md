# scopuli — Research notes

> Working notes from the research phase. Not a spec; a digest of what we read and what we decided to keep / drop.

This document feeds [`PLAN.md`](./PLAN.md), [`ARCHITECTURE.md`](./ARCHITECTURE.md), and [`SECURITY.md`](./SECURITY.md). It exists so we can revisit *why* a choice was made without re-running the searches.

---

## R1. Key derivation

**Sources read:**
- OWASP [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- Bellator Cyber [Argon2id parameters](https://bellatorcyber.com/blog/best-password-hashing-algorithms-of-2023) (October 2025)
- arXiv ["Evaluating Argon2 Adoption and Effectiveness in Real-World Software"](https://arxiv.org/html/2504.17121v2) — notes 46.6% of real deployments use weaker-than-OWASP parameters

**Takeaways:**
- Argon2id is the OWASP top recommendation. Three OWASP-validated presets:
  - `m=47104 (46 MiB), t=1, p=1` (do not use with Argon2i)
  - `m=19456 (19 MiB), t=2, p=1` (minimum)
  - `m=12288 (12 MiB), t=3, p=1`
- We picked `m=64 MiB, t=3, p=1` (above minimum). Reasoning in `SECURITY.md` §2.1.1.
- `p=1` parallelism is intentional and matches OWASP guidance — Argon2's parallel parameter is mostly about resisting cache-timing, not about throughput.

**Dropped:**
- bcrypt (legacy only per OWASP)
- PBKDF2 (only if FIPS-140 compliance is needed; we don't need it)
- scrypt (fallback if Argon2id isn't available; not our case)

---

## R2. Symmetric encryption

**Sources read:**
- StackExchange / Reddit threads on AES-GCM vs alternatives
- libsodium / NaCl recommendations (`crypto_secretbox`, `crypto_aead`)
- HN ["Hell is overconfident developers writing encryption code"](https://news.ycombinator.com/item?id=42895332) — argues for using vetted libraries instead of hand-rolled AES

**Takeaways:**
- AES-256-GCM and XChaCha20-Poly1305 are both AEAD and both fine.
- XChaCha20 has the nonce-misuse advantage (24-byte nonce → safe with random even at high volumes), but we generate fresh random 12-byte nonces per secret from `crypto/rand`, so the GCM nonce collision bound (≈ 2^32 writes per secret) is fine.
- AES-256-GCM has hardware acceleration (AES-NI) on every modern x86/ARM64 — a real win for a server process.

**Picked:** AES-256-GCM via Go's `crypto/aes` + `crypto/cipher.NewGCM`.

**Dropped:**
- AES-CBC (no authentication — mustn't use without HMAC)
- XChaCha20-Poly1305 (no hardware acceleration; equivalent security for our use)
- libsodium wrappers (Go bindings add an unnecessary CGo dep)

---

## R3. Database encryption

**Sources read:**
- SQLCipher [performance guide](https://www.zetetic.net/sqlcipher/performance/)
- SQLCipher [GitHub README](https://github.com/sqlcipher/sqlcipher)
- StackOverflow ["how to improve performance of encrypted sqlite database"](https://stackoverflow.com/questions/52976097/python-sqlalchemy-how-to-improve-performance-of-encrypted-sqlite-database)

**Takeaways:**
- SQLCipher 4.x is a maintained SQLite fork with AES-256-CBC page encryption and HMAC-SHA-512 per-page integrity.
- Default PBKDF2 (256k iterations) for the SQLCipher key derivation is wasted work if we already have a stronger KDF upstream.
- Bypass SQLCipher's KDF with `PRAGMA kdf_iter = 1` + `PRAGMA key = "x'<raw-bytes>'"`.
- Performance gotchas: don't repeatedly open/close the connection (KDF is paid each time). For us, we run a long-lived pool, so this is fine.
- `cipher_memory_security` is OFF by default in 4.5.0+; leave it off in V0.

**Picked:** SQLCipher, raw-key mode, long-lived connection. See `ARCHITECTURE.md` §4.2.

---

## R4. Reference architectures

**Sources read:**
- HashiCorp Vault [seal/unseal docs](https://developer.hashicorp.com/vault/docs/concepts/seal)
- HashiCorp Vault [sealing best practices](https://developer.hashicorp.com/vault/docs/configuration/seal/seal-best-practices)
- Bitwarden [end-to-end encryption blog](https://bitwarden.com/blog/why-end-to-end-encryption-is-crucial-for-developer-secrets-management/)
- Bitwarden security fundamentals (linked from the above)

**Takeaways:**
- **Vault's pattern:** "barrier" encryption at rest (a single root key encrypts everything); unseal = bring the root key into RAM, possibly split via Shamir's Secret Sharing for quorum control. Vault's auto-unseal uses cloud KMS for the root key.
- **Bitwarden's pattern:** zero-knowledge / end-to-end. Master password → KDF (Argon2 / PBKDF2) → KEK. Per-item AES. Server never sees plaintext. No separate "unseal" step because the master password IS the root key, and the user types it on every login.
- We are closer to Bitwarden's model: master password env var = root key. No "seal/unseal" ceremony. Single operator, single password.
- Shamir / auto-unseal are explicitly V1+ — see `PLAN.md` §2 (out of scope).

**Dropped from Vault:**
- Storage backends (we want SQLite, not Consul/Raft)
- Policies / roles / auth methods (we have one role: the master; one secondary role: API keys)
- Token hierarchy (our "tokens" are simple scoped API keys)

**Dropped from Bitwarden:**
- Org / collection model (single operator)
- 2FA, TOTP, FIDO2 (V1 candidates)

---

## R5. MCP (Model Context Protocol)

**Sources read:**
- MCP spec — [Server Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- MCP spec — [Transports](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports)
- TrueFoundry [stdio vs Streamable HTTP](https://www.truefoundry.com/blog/mcp-stdio-vs-streamable-http-enterprise)
- Reddit / LinkedIn discussions on the same

**Takeaways:**
- Two official transports: **stdio** (local subprocess, JSON-RPC over stdin/stdout) and **Streamable HTTP** (POST/GET to a single endpoint, SSE for streaming).
- Tool definition: `name`, `description`, `inputSchema` (JSON Schema), optional `outputSchema`, optional `annotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`).
- Servers MUST: validate all inputs, implement access controls, rate-limit, sanitize outputs. Clients SHOULD: prompt for confirmation on sensitive ops, show tool inputs to the user before calling, validate results, implement timeouts, log tool usage.
- For our use case (homelab LXC, agents on the same host as the vault): **stdio is the right pick for V0.** Streamable HTTP would be needed for cross-host agents, but that adds TLS, auth-on-HTTP, DNS-rebinding mitigations, etc. — V1 work.

**Picked:** stdio MCP server, same Go binary as the server. Tool surface in `ARCHITECTURE.md` §2.3.

**Dropped for V0:**
- Streamable HTTP transport
- MCP `resources` and `prompts` capabilities (we don't need them yet)
- Custom transports

---

## R6. API key design

**Sources read:**
- vjay15 ["My adventure in designing API keys"](https://vjay15.github.io/blog/apikeys/) — comprehensive benchmark of storage formats
- Stripe / GitHub / Vercel public key format conventions
- LinkedIn / HN threads on the prefix convention

**Takeaways:**
- Industry pattern: `prefix_body_checksum`.
  - `prefix` identifies the service and the environment (`sk_live_…`).
  - `body` is the high-entropy secret material, generated from a CSPRNG.
  - `checksum` is a short hash of the body (e.g., first 4 bytes of SHA-256), enabling offline validity checks without hitting the DB.
- **Storage: hash only.** SHA-256 of the full key. Show prefix in listings so the operator can identify a key by its first ~12 characters.
- vjay15's benchmark: full SHA-256 hex stored in an indexed column is **as fast** as any truncated encoding, because B-Tree handles sortable strings well. So no need to truncate to save space.
- Decision: 24 random bytes for the body (≈ 192 bits of entropy) + 4-byte SHA-256 checksum. Stored as 64-char hex SHA-256 hash. Prefix in the DB for display.

**Picked:** format in `SECURITY.md` §2.5.1.

**Dropped:**
- Truncated-hash storage (no perf win)
- BigInt-base62 encoding of the hash (slower than direct hex, per vjay15's benchmarks)

---

## R7. Audit log integrity

**Sources read:**
- dev.to [Building a tamper-evident audit log with SHA-256 hash chains](https://dev.to/veritaschain/building-a-tamper-evident-audit-log-with-sha-256-hash-chains-zero-dependencies-h0b)
- Mattermost [Compliance by Design — 18 tips for tamper-proof audit logs](https://mattermost.com/blog/compliance-by-design-18-tips-to-implement-tamper-proof-audit-logs/)
- Pangea [A tamperproof logging implementation](https://pangea.cloud/blog/a-tamperproof-logging-implementation/)
- transparency.dev [Trillian / append-only ledgers](https://transparency.dev/)
- GitHub issue: [Hermes-agent — SHA-256 hash-chained action log](https://github.com/NousResearch/hermes-agent/issues/487)

**Takeaways:**
- Append-only + hash chain (each row's hash includes the previous row's hash) detects any insert / delete / reorder.
- HMAC over the chain with a server-side key makes the chain **forge-resistant** even against an attacker with read access to the .db but without the master password.
- The hash *input* must be canonical and deterministic across implementations — JSON with sorted keys, explicit types for integers, no locale-dependent formatting.
- Merkle trees / external transparency logs (Trillian, Sigstore Rekor) are overkill for V0.

**Picked:** SHA-256 hash chain + HMAC-SHA-256 with a key derived from the master password. Implementation in `ARCHITECTURE.md` §4.1 and `SECURITY.md` §2.6.

**Dropped:**
- External transparency log (Sigstore / Rekor)
- Merkle tree batching (overkill; linear chain is sufficient for our scale)
- Blockchain anchoring (lol no)

---

## R8. Agent runtime / "what counts as an agent"

Out of scope for the security design but worth pinning down: when we say "agent" in this project, we mean any long-running autonomous process that needs to call external APIs. Examples in your homelab might be:

- Claude Code / Cursor / OpenHands / Cline running on the LXC
- Custom scripts you've written to do CI/CD, RSS digesting, etc.
- Home automation controllers

All of them are "I have a process I trust with a key; it needs to call `scopuli get aws/dev/…` from time to time." The MCP integration is the killer feature here because modern LLM runtimes already speak MCP natively — no shell-out, no parsing.

**Implication for design:** the API key auth path is **stateless and self-authenticating** (no session cookie, every request carries the key). This is friendlier to long-lived agents than a session-based flow would be.

---

## R9. Things we explicitly chose not to research further

To keep this document bounded:

- TLS / mTLS termination details (V0 has no TLS termination; reverse proxy is the operator's job).
- WebAuthn / passkeys (V1+).
- KMS / HSM integration (V1+).
- Federated SSO (V1+).
- Compliance certifications (SOC2, ISO 27001) — out of scope for a homelab project.

---

## R10. Open research questions (non-blocking)

If we end up needing any of these later, the rabbit holes are:

- **Argon2id parameter tuning on the operator's specific hardware.** We picked reasonable defaults; once the binary exists, measure boot time and adjust `m` / `t` to hit a 250 ms target.
- **SQLite WAL mode under SQLCipher.** WAL is normally a perf win; with SQLCipher, the encrypted WAL adds overhead. We default to `journal_mode=WAL` and measure.
- **Constant-time logging.** Currently we log `key_id` and `path` for every request. If we ever log secret values by accident (we won't), that's the end of the project. Add a log-scrubbing test in CI.

---

## R11. FTS5 (full-text search) — chosen for V0

**Decision:** SQLite FTS5 with `unicode61 remove_diacritics 2` tokenizer. Two virtual tables: `secrets_fts(path, description, metadata_text)` and `keys_fts(name, description, metadata_text)`. Triggers keep the FTS tables in sync on insert/update/delete.

**Why FTS5 (not "filter by tag only"):** LLM agents need to *discover* the right secret. A `list --tag aws` dump is a haystack. FTS5 lets the agent query "rotated stripe production" and get BM25-ranked hits. With the corpus of a single operator (a few hundred secrets at most), the index is tiny and the search is sub-millisecond.

**Trade-offs accepted:**
- FTS5 in SQLCipher means the index is encrypted (good — no side-channel file). With a corpus of ~1000 secrets, the index is ~50-200 KB on disk. Negligible.
- `metadata` is flattened (`k1=v1; k2=v2`) into the FTS index. Operationally, this means changing a metadata key re-tokenizes the row. We accept the cost.
- FTS5 is part of the SQLite library since 3.9; the `mattn/go-sqlite3` driver we use ships with FTS5 enabled. No extra build flag.
- The `unicode61` tokenizer is locale-aware but not multi-language. Sufficient for English/Portuguese labels. If we need better stemming we can add `porter` or `trigram` later.

**Why not external (e.g., Meilisearch, Typesense):** Adds infrastructure. Single-operator, single-vault. The friction of running a sidecar search engine outweighs the marginal quality gain.

## R12. pi-coding-agent extension — chosen for V0

**Decision:** TypeScript package `@scopuli/pi-extension`, installed via `pi install npm:@scopuli/pi-extension`. V0 of the extension is **status bar only**. No slash commands, no tools exposed to the agent in V0. Roadmap v0.1 adds slash commands; v0.2 adds tools.

**Why status bar only in V0:** The MCP server (`scopuli mcp-serve`) already gives the agent access to secrets. Duplicating that as pi tools is a surface-area leak for little gain. The extension's job is to make the *operator* aware of the vault's state without leaving the agent UI. Slash commands and tools come when we have user feedback on what the operator actually wants from the extension.

**Why a separate npm package (not subdir in the binary):** The binary is Go; the extension is TypeScript. Two languages, two toolchains, two release cadences. Mixing them in one repo would force JavaScript-ecosystem tooling into the Go project (and vice versa). The extension is a sibling package.

**References:**
- [pi-coding-agent docs](https://github.com/lucaspdude/pi-coding-agent) — extension model, status bar API, slash command registration.
- [skills](https://github.com/lucaspdude/pi-coding-agent/blob/main/docs/skills.md) — alternative distribution mechanism; we chose `extensions/` because status bars and tools aren't a "skill" in the pi sense.