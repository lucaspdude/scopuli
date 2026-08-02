# cred-share — Decisions needed before development

> These are the choices **you** (the operator) need to make. The rest of the plan assumes the **(Recommended)** answer unless you say otherwise.
>
> Answer them in any order. Once you've picked, I'll mark them and we move to implementation.

---

## D1. Language / runtime for the server

What runs inside the Docker container.

| Option | Pros | Cons |
|---|---|---|
| **(Recommended) Go** | Single static binary; tiny distroless image; mature `crypto/*` + `crypto/aes` + `x/crypto/argon2`; official MCP SDK; easy to reason about for a security-sensitive service. | Verbose for HTML templates; no native hot reload. |
| Rust | Excellent crypto ecosystem (`rustcrypto`, `aes-gcm`, `argon2`); zero-cost abstractions; `sqlcipher` bindings exist. | Slower to iterate; less mature MCP SDK story. |
| Node.js (TypeScript) | Fast to write; npm MCP SDK is the reference impl; htmx-style templating with `lit` or server-rendered. | Larger image; relies on V8 hardening; runtime foot-gun for a security-sensitive service. |
| Python | Fastest to prototype; great `cryptography` lib; SQLCipher bindings via `pysqlcipher3`. | Heaviest image; GIL concerns; weakest distroless story. |

**Default plan:** Go 1.23.

---

## D2. Client surface for V0

Three options for the operator to interact with the vault.

| Option | Scope | Recommended for |
|---|---|---|
| **(Recommended) CLI + MCP, no web UI** | CLI for the operator; agents use MCP. Lighter to build, fewer attack surfaces, gets us to "agent-first" fastest. | If you primarily run agents from your own terminal and don't need browser access. |
| CLI + MCP + barebones web UI | Adds htmx-based login + CRUD pages. ~1 extra week of work. | If you want browser access from your laptop / phone occasionally. |
| Web UI only | No CLI/MCP. | Not recommended — agents need a programmatic interface. |

The web UI in any option is **operator-only**. Agents don't browse; they use the CLI or MCP. So the decision is just: do you want a UI for yourself?

---

## D3. Network exposure

What the container binds to.

| Option | Behavior |
|---|---|
| **(Recommended) 127.0.0.1 only** | Agent runtimes on the same LXC talk to it directly. No LAN exposure. Safest default for V0. |
| LAN (0.0.0.0:8080) without TLS | Don't. |
| LAN behind reverse proxy with TLS + IP allowlist | Operator sets up Caddy/Nginx. Documented in `OPERATIONS.md` but the container itself still defaults to loopback. |

If you pick "LAN access", we add `CRED_SHARE_TRUSTED_PROXIES` env var and a `--real-ip-from` mechanism. Default behavior stays loopback-only.

---

## D4. Scope syntax

How the operator describes "this key can see these secrets" when creating an agent key.

| Option | Example |
|---|---|
| **(Recommended) Slash paths with `*` glob** | `aws/dev/*,github/lucas/pat` — `*` matches one path segment. Matches the operator's mental model of "folders". |
| Free-form labels (no hierarchy) | `aws-dev-stripe,github-lucas-pat` — no nesting. Easier to parse, weaker structure. |
| Tag-only (every secret has tags, key picks tags) | Secret has `tags: ["aws","dev","stripe"]`, key has `tags: ["aws","dev"]`. More flexible, more UI work. |

The slash-paths option maps 1:1 to how the operator already thinks ("I keep my AWS dev stuff under `aws/dev/`"), is trivial to implement (`path.Match`), and is what `cred-share secret set aws/dev/foo` already requires.

---

## D5. Master-password source

How the operator provides the master password to the running container.

| Option | Behavior |
|---|---|
| **(Recommended) Env var only** | `MASTER_PASSWORD=…` in the container's environment. Exactly what you asked for. CLI `cred-share login` reads it from stdin or its own env. |
| Interactive prompt on first CLI use | Each `cred-share` command prompts. Slower; annoying for agents. |
| Both | Env var if set, interactive prompt if not. Pragmatic. |

The recommended option matches your stated requirement. If you also want the CLI to prompt interactively when the env var is absent, we add a `--prompt` flag in V0.5 — easy.

---

## D6. Key expiry behavior

What happens when an agent key hits its expiry.

| Option | Behavior |
|---|---|
| **(Recommended) Hard expiry + audit row** | Expired keys return 401; a `key.expired` audit row is recorded; operator can re-issue. |
| Soft expiry (warn + keep working) | Hard to reason about; usually a foot-gun. Not recommended. |
| No expiry (operator-managed revocation) | Simpler, but encourages never-rotating keys. |

The recommended option pairs cleanly with the existing revoke flow.

---

## D7. Web UI tech (only relevant if you picked "include UI" in D2)

| Option | Why |
|---|---|
| **(Recommended) Server-rendered Go templates + htmx + a single CSS file** | No JS framework, no build step, tiny attack surface. The UI is for one person (you) on a trusted network. |
| A React/Vue SPA | Overkill; pulls in a node toolchain for a single-user front-end. |

---

## D8. Audit log retention

V0 stores audit rows forever. Pick what we do at the edge.

| Option | Behavior |
|---|---|
| **(Recommended) Keep all rows, no expiry, no archiving** | Disk is cheap; the operator can prune by hand. Add a `cred-share audit prune --before YYYY-MM-DD` command but no automation. |
| Auto-archive after N days | More moving parts. Not V0. |

---

## D9. Image registry / release process

This is a V0.5+ question, but worth flagging now.

| Option | Behavior |
|---|---|
| **(Recommended) GitHub Container Registry (`ghcr.io/lucaspdude/cred-share`)**, tagged `v0`, `v0.0.1`, `latest` | Standard for OSS on GitHub. |
| Docker Hub | Fine, but GHCR is more integrated with GitHub Actions. |
| Self-hosted registry | Only if you're already running one. |

---

## What I need from you

A reply like:

> D1: Go ✅ (default)
> D2: CLI + MCP only (skip web UI for V0)
> D3: 127.0.0.1 only
> D4: slash paths ✅ (default)
> D5: env var only ✅ (default)
> D6: hard expiry ✅ (default)
> D7: n/a
> D8: no expiry ✅ (default)
> D9: GHCR ✅ (default)

…gets us to a buildable spec. If you want to deviate on D2 (include the web UI) or D3 (LAN access), flag it explicitly because they each add non-trivial scope.