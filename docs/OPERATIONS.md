# scopuli operations

Operational runbook for the scopuli vault.

## Quick start

```bash
# Pull + run
MASTER_PASSWORD=$(openssl rand -hex 32) docker compose up -d

# Capture the operator token from the first-boot logs
docker compose logs scopuli | grep scot_live_

# Save credentials locally (macOS Keychain / Linux secret service)
scopuli login http://127.0.0.1:8080 --token scot_live_...

# Verify
scopuli version
curl http://127.0.0.1:8080/healthz
```

## Day-to-day

```bash
scopuli secret set <path> --value ...   # create
scopuli secret get <path>              # read plaintext
scopuli secret list --prefix aws/      # list (paths + labels + tags)
scopuli secret search "rotated"        # FTS5 over description + metadata
scopuli secret annotate <path> --add-tag rotated --description "new"

scopuli keys create <name> --scope "aws/dev/*" --permission read
scopuli keys list
scopuli keys revoke <name>
```

## Audit

```bash
scopuli audit list --limit 50
scopuli audit verify              # exit 0 if chain OK, 1 if tampered
```

`audit verify` walks the SHA-256 hash chain and HMAC-SHA-256 over every row. The HMAC key is derived from the master password via a separate Argon2id salt (`/data/salt` for KEK; `meta.hmac_key_salt` for HMAC).

## Backup / restore

> Snapshot/restore is **not** wired into the HTTP API in V0; the underlying
> primitive lives at `internal/backup` and uses ChaCha20-Poly1305 with a
> passphrase-derived key.

V0 backup procedure: stop the container, copy `/data` somewhere safe. Both files must come along:
- `vault.db` — SQLCipher-encrypted
- `salt` — Argon2id salt for the KEK

```bash
# Stop the container, snapshot the data dir.
docker compose down
tar czf vault-2025-08-15.tgz -C /path/to/scopuli-data .

# To restore on a new host: extract, set the same MASTER_PASSWORD, bring up.
mkdir -p /var/lib/scopuli
tar xzf vault-2025-08-15.tgz -C /var/lib/scopuli
MASTER_PASSWORD=... docker compose up -d
```

A first-class snapshot/restore command (with passphrase-encrypted bundle) is planned for V0.1.

## Master password rotation

There is no UI for rotating the master password in V0. Two options:

1. **Bring up a new container with a new master password**: this is destructive — the old DB was encrypted with a KEK derived from the old password's salt, and you cannot decrypt it with a different password.
2. **Use the audit chain to verify nothing was tampered with**: `scopuli audit verify` confirms the chain. If you trust the host + backups, recreate from scratch.

Full rotation (re-wrap without re-uploading) is planned.

## Operator token rotation

```bash
# Rotate within the same MASTER_PASSWORD
docker exec -it scopuli scopuli operator rotate --from-env MASTER_PASSWORD
# New token is printed ONCE; copy it to your password manager and re-login.

scopuli login http://127.0.0.1:8080 --token scot_live_...
```

## Troubleshooting

### "decrypt failed" on read

The stored `aad` doesn't match what was used to encrypt. Causes:
- A `description` was edited in the DB out-of-band.
- A secret row was edited by hand.
- Someone swapped ciphertexts between rows.

The error is intentionally opaque. Run `scopuli audit list --limit 20` to see the most recent operations.

### Vault unreachable from CLI

```bash
curl http://127.0.0.1:8080/healthz   # from the same host as the CLI
docker compose logs scopuli          # container logs
```

If the vault is on a different host, ensure the reverse proxy is set up (`SCOPULI_BIND=0.0.0.0:8080` + Caddy/Nginx in front).

### SQLCipher "no such module: fts5"

The binary was built without `-tags sqlite_fts5`. Rebuild:

```bash
make clean && make build
# or, for Docker:
docker build --no-cache -t scopuli:dev .
```

### Keychain prompt spam on macOS

The CLI reads from Keychain on every command. macOS may prompt for access repeatedly. To allow once per session:

```bash
security set-key-partition-list -S apple-tool:,apple: -s "scopuli" -k "" ~/Library/Keychains/login.keychain-db
```

Or fall back to the file credentials at `~/.config/scopuli/credentials` (mode 0600).
