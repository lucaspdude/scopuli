# Security

scopuli is a single-operator vault designed to be safe to expose to any network — LAN or public internet — from day one. This page summarizes the security model; the repository's [SECURITY.md](https://github.com/lucaspdude/scopuli/blob/main/SECURITY.md) covers how to report vulnerabilities.

## How your secrets are protected

- **Encryption at rest.** Every secret value is encrypted with AES-256-GCM under a key-encryption-key (KEK) derived from your master password via **Argon2id** (64 MiB, t=3). The whole database file is additionally encrypted by SQLCipher. A stolen disk or backup yields ciphertext, nothing more.
- **The master password never leaves the container.** It is read once from the environment at boot to derive the KEK. It is never sent over the network and never stored. **If you lose it, the vault is unrecoverable — by design.**
- **Tamper binding.** Each secret's ciphertext is bound (via GCM additional authenticated data) to its path, description, and version. Swapping or editing rows out-of-band fails decryption.
- **Hash-only credentials.** Operator token and agent keys are stored as SHA-256 hashes. The plaintext operator token is printed exactly once on first boot; each agent key is shown exactly once at creation.

## Scoped access for agents

Agent keys (`sk_live_...`) carry a **scope** (slash-path globs like `aws/dev/*`) and a **permission** (`read` or `manage`). A compromised key only exposes secrets inside its scope, every use is logged, and revocation is instant (`scopuli keys revoke <name>`).

## Tamper-evident audit log

Every read, write, and denial is appended to an audit log **before** the response is sent. Rows are chained with SHA-256 and MACed with HMAC-SHA-256 under a key derived separately from the master password. `scopuli audit verify` recomputes the chain and flags the first broken row.

## Transport security

The server does **not** terminate TLS. Bound to `127.0.0.1` (the default in our guides), no TLS is needed. For anything reachable over a network — LAN or internet — put a reverse proxy (Caddy/Nginx) in front, exactly as in the [VPS guide](deploy-vps.md). Rate limiting applies per-IP on unauthenticated endpoints and per-key on authenticated ones.

## Trust boundary — what we do NOT defend against

Being explicit about the limits:

- **Root on the host / container escape.** Whoever controls the host root can read the master password from the environment and the database file. Harden the host; that is the boundary.
- **Reading the memory of the running vault process.** The KEK and audit HMAC key live in RAM while the server runs.
- **Side channels and coercion.** Out of scope.
- **Exposing port 8080 without TLS.** Not a vulnerability — a misconfiguration the docs warn against repeatedly.

## Reporting a vulnerability

Please report privately via [GitHub Security Advisories](https://github.com/lucaspdude/scopuli/security/advisories/new) — never as a public issue. See [SECURITY.md](https://github.com/lucaspdude/scopuli/blob/main/SECURITY.md) for details. Only the latest release receives security fixes.
