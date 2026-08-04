# Deploy on a VPS

An always-on vault you and your agents can reach from anywhere, behind HTTPS.

**Prerequisites:**

- A VPS with Docker and Docker Compose installed.
- A domain (or subdomain) pointing at the VPS, e.g. `vault.example.com`.
- [Caddy](https://caddyserver.com/) installed on the host (automatic TLS).

!!! danger "Never expose port 8080 without TLS"
    The scopuli server does not terminate TLS. On a VPS, the container port must
    stay bound to `127.0.0.1` and all traffic must go through the reverse proxy
    over HTTPS. The setup below does exactly that.

## 1. Create the app directory

```bash
sudo mkdir -p /opt/scopuli && cd /opt/scopuli
```

## 2. Write the compose file

```yaml
# /opt/scopuli/docker-compose.yml
services:
  scopuli:
    image: ghcr.io/lucaspdude/scopuli:latest
    container_name: scopuli
    restart: unless-stopped
    env_file: .env
    environment:
      SCOPULI_BIND: "0.0.0.0:8080"
    volumes:
      - scopuli-data:/data
    ports:
      - "127.0.0.1:8080:8080"   # localhost only — Caddy proxies to this

volumes:
  scopuli-data:
```

## 3. Set the master password

```bash
echo "MASTER_PASSWORD=$(openssl rand -hex 32)" | sudo tee /opt/scopuli/.env
sudo chmod 600 /opt/scopuli/.env
```

!!! warning "Save the master password in your password manager"
    It derives the encryption key for every secret and is never stored by
    scopuli. **Losing it means losing the vault — there is no recovery.**

## 4. Start the vault and capture the operator token

```bash
cd /opt/scopuli
sudo docker compose up -d
sudo docker compose logs scopuli | grep scot_live_
```

The `scot_live_...` token is printed **once**. Store it safely — it is your admin credential.

## 5. Put Caddy in front (automatic HTTPS)

```
# /etc/caddy/Caddyfile
vault.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

```bash
sudo systemctl reload caddy
```

Caddy obtains and renews the Let's Encrypt certificate automatically. Verify:

```bash
curl https://vault.example.com/healthz
```

## 6. Firewall

Only SSH and HTTP/S should be reachable from the internet:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

Port 8080 never appears here — it is bound to localhost and only Caddy can reach it.

## 7. Log in from your machine

On your laptop (with the [CLI installed](install.md)):

```bash
scopuli login https://vault.example.com --token scot_live_...
scopuli secret set example/hello --value world
```

Agents on other hosts authenticate with [scoped agent keys](deploy-local.md#use-it) (`sk_live_...`), not the operator token.

## Day 2 operations

**Upgrades**

```bash
cd /opt/scopuli
sudo docker compose pull
sudo docker compose up -d
```

**Backups** — stop, snapshot the volume, start. Both `vault.db` and the `salt` file are required, and both are useless without the master password:

```bash
cd /opt/scopuli
sudo docker compose down
sudo docker run --rm -v scopuli_scopuli-data:/data:ro -v /opt/scopuli/backups:/backup alpine \
  tar czf "/backup/scopuli-$(date +%F).tar.gz" -C /data .
sudo docker compose up -d
```

(Confirm the volume name with `docker volume ls` — Compose prefixes it with the directory name.) Copy the tarball off the VPS; restic/borg/rsync all work.

**Restore** — extract the tarball into a fresh volume and start with the same `MASTER_PASSWORD`.

**Rotate the operator token** (leak, lost device):

```bash
sudo docker exec -it scopuli scopuli operator rotate --from-env MASTER_PASSWORD
# prints the new token once — re-login everywhere
```

**Audit**

```bash
scopuli audit list --limit 50
scopuli audit verify    # exit 0 = chain intact, 1 = tampering detected
```
