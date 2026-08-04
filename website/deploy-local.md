# Deploy locally (Docker)

Run the vault on your own machine. Bound to `127.0.0.1` by default — only processes on this host can reach it. No TLS needed on localhost.

**Prerequisite:** Docker (or any OCI runtime) installed.

## Option A — docker run

```bash
docker pull ghcr.io/lucaspdude/scopuli:latest

docker run -d \
  --name scopuli \
  --restart unless-stopped \
  -e MASTER_PASSWORD=$(openssl rand -hex 32) \
  -v scopuli-data:/data \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/lucaspdude/scopuli:latest
```

!!! warning "Save your master password"
    `MASTER_PASSWORD` derives the key that encrypts every secret. It is never
    stored anywhere. **If you lose it, the vault is unrecoverable** — put it in
    your password manager the moment you create it. The random value above is
    fine; a memorable passphrase works too.

## Option B — docker compose

```yaml
# docker-compose.yml
services:
  scopuli:
    image: ghcr.io/lucaspdude/scopuli:latest
    container_name: scopuli
    restart: unless-stopped
    environment:
      MASTER_PASSWORD: ${MASTER_PASSWORD:?set it first}
      SCOPULI_BIND: "0.0.0.0:8080"
    volumes:
      - scopuli-data:/data
    ports:
      - "127.0.0.1:8080:8080"

volumes:
  scopuli-data:
```

```bash
MASTER_PASSWORD=$(openssl rand -hex 32) docker compose up -d
```

## First boot: capture the operator token

On first boot the server prints the **operator token** exactly once — this is your admin credential:

```bash
docker logs scopuli | grep scot_live_
```

Copy it into your password manager, then log the CLI in:

```bash
scopuli login http://127.0.0.1:8080 --token scot_live_...
```

The token is stored in your OS keychain (macOS Keychain / Linux secret service), falling back to `~/.config/scopuli/credentials` (mode `0600`).

Lost the token later? Rotate it:

```bash
docker exec -it scopuli scopuli operator rotate --from-env MASTER_PASSWORD
```

## Use it

```bash
# Store a secret
scopuli secret set aws/dev/stripe_key --value sk_live_... --description "Stripe test key"

# Read it back
scopuli secret get aws/dev/stripe_key

# Issue a scoped, read-only key for an agent
scopuli keys create my-agent --scope "aws/dev/*" --permission read
# → prints sk_live_... exactly once

# Check the audit trail
scopuli audit list --limit 20
scopuli audit verify
```

## Where the data lives

Everything lives in the `scopuli-data` Docker volume: the SQLCipher-encrypted `vault.db` and the KEK salt. Both are useless without the master password.

```bash
# Backup (stop first for a consistent copy)
docker stop scopuli
docker run --rm -v scopuli-data:/data:ro -v "$PWD":/backup alpine \
  tar czf "/backup/scopuli-backup-$(date +%F).tar.gz" -C /data .
docker start scopuli
```

## Stop / remove

```bash
docker stop scopuli && docker rm scopuli        # data volume survives
docker volume rm scopuli-data                   # destroys the vault — only if you mean it
```

Ready for an always-on setup? [Deploy on a VPS](deploy-vps.md).
