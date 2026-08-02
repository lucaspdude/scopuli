# scopuli pi extension — V0 plan

> A TypeScript package that plugs into [pi-coding-agent](https://github.com/lucaspdude/pi-coding-agent) and surfaces scopuli vault state in the agent's UI.

Source lives at `extensions/pi/` in this repo. Published to npm as `@scopuli/pi-extension`.

## 1. Goals

V0 of the extension does **one thing** and does it well:

> Show the operator + agent that the vault is reachable, what keys are loaded, and what scope the current key has — without leaving the pi UI.

That's it. No slash commands, no tools exposed to the agent, no auto-injection of secrets. Each of those is a separate decision and lands in v0.1+ of the extension.

## 2. Non-goals (V0 of the extension)

- Exposing secrets as pi tools. (The MCP server in `scopuli mcp-serve` already handles agent-side secret access; the extension should not duplicate that.)
- Slash commands (`/scopuli ...`). Roadmap v0.1.
- Auto-injecting secrets as env vars at agent start. Roadmap v0.2.
- Multi-vault support. V0 is single-vault per host.
- Key creation / rotation from the extension. Mutation goes through the CLI.

## 3. UX

The pi UI has a status bar at the bottom of the TUI. The extension registers a single widget at the right side:

```
  🔒 scopuli: up · 4 keys · scope read   ↻ 2m ago
```

| State | Display |
|---|---|
| Vault reachable, key loaded, fresh | `🔒 scopuli: up · <N> keys · scope <read|manage>   ↻ <relative-time>` |
| Vault reachable, no key (operator not logged in) | `🔒 scopuli: up · login required` |
| Vault reachable, key loaded but expired | `🔒 scopuli: up · key expired` |
| Vault reachable, key loaded but revoked | `🔒 scopuli: up · key revoked` |
| Vault unreachable (last healthcheck failed) | `⚠ scopuli: <reason>` |
| Auth not detected (no env vars, no Keychain) | `? scopuli: no credentials` |

The status bar is **read-only**. Clicking it does nothing in V0. v0.1 will add a `/scopuli` slash command that opens a quick-action menu.

The relative time refreshes every 30 seconds. The healthcheck is non-blocking — it does a `GET /healthz` against the vault URL with a 1.5 s timeout. If the vault is slow, the status bar shows the **last** state, not a "loading" indicator.

## 4. Authentication discovery

V0 follows the same auto-detect order as the CLI:

```
1. SCOPULI_URL  env var + SCOPULI_KEY    env var  → use directly
2. macOS Keychain entry "scopuli key"  (set by `scopuli login`)  → use that
3. Linux secret-service entry                                  → use that
4. Fallback: ~/.config/scopuli/credentials (mode 0600)         → use that
5. None of the above → status bar shows "no credentials"
```

The extension never writes to the Keychain, the secret service, or the credentials file. It only **reads**. `scopuli login` is the only thing that writes (the operator runs it from the CLI).

If the discovered token is an **operator token** (`scot_live_…`), the status bar shows `scope: all`. If it's an **agent key** (`sk_live_…`), the extension parses the prefix and the metadata exposed by `GET /api/keys/{name}` to render `scope: <permissions>`.

## 5. Wire protocol

The extension talks to the vault over its existing HTTP API. It does **not** shell out to the `scopuli` CLI binary. Reasons:

- The CLI binary may not be on PATH (a CI container with the extension but no CLI).
- Subprocess startup cost (~30 ms) per healthcheck is too high.
- Keeping the extension pure-Node makes it installable via `npm install` with no native deps.

### 5.1 Endpoints used

| Endpoint | Purpose | Auth |
|---|---|---|
| `GET /healthz` | Reachability check (every 30 s) | None |
| `GET /api/keys` | List of keys visible to the caller (one entry when using an agent key) | `X-Scopuli-Operator` or `X-Scopuli-Key` |
| `GET /api/keys/{name}` | Detail (scope, permissions, expiry, description, tags) | Same |

The extension does **not** read secrets via the extension. Secret reads go through the MCP server (which is configured separately by the agent runtime).

### 5.2 Request shape

```http
GET /healthz HTTP/1.1
Host: <vault-url>
```

```http
GET /api/keys HTTP/1.1
Host: <vault-url>
X-Scopuli-Key: sk_live_<…>_sRC4k1
```

### 5.3 Response handling

| Status | Interpretation |
|---|---|
| 200 | Healthy. |
| 401 | Token revoked / expired / unknown. Status bar shows that. |
| 403 | Forbidden. Only happens if the operator token is malformed. |
| 5xx | Vault is up but erroring. Status bar shows the last-known state. |
| Network error / timeout | Vault unreachable. Status bar shows `⚠ scopuli: unreachable`. |

## 6. Repository layout

```
extensions/pi/
├── package.json
├── tsconfig.json
├── README.md
├── src/
│   ├── index.ts          # activate(pi) entrypoint
│   ├── auth.ts           # discoverCredentials(): Promise<Credentials>
│   ├── client.ts         # scopuliApi: thin fetcher wrapper
│   ├── status-bar.ts     # renderStatusBar(state)
│   └── types.ts          # shared types
└── test/
    ├── auth.test.ts
    ├── client.test.ts
    └── status-bar.test.ts
```

`activate(pi)` is the default-exported function. It registers a status bar widget via `pi.ui.statusBar.register('scopuli', renderStatusBar)`. It also wires a refresh timer at 30 s intervals.

## 7. Configuration

The extension looks for these config values in priority order:

| Source | Keys | Notes |
|---|---|---|
| Env vars | `SCOPULI_URL`, `SCOPULI_KEY` | Highest priority. |
| macOS Keychain | service `scopuli key`, account `default` | Set by `scopuli login`. |
| Linux secret service | same | Same. |
| `~/.config/scopuli/credentials` | file with `url` + `key` / `token` lines | Last resort. |

The extension does **not** accept a config file of its own. V0 has one vault per host.

## 8. Error handling

- **No credentials found** → status bar shows `? scopuli: no credentials`. The extension does not prompt interactively (would block the agent's UI).
- **Vault unreachable** → status bar shows `⚠ scopuli: <reason>`. Errors are logged to pi's debug log, not the UI.
- **Token expired / revoked** → status bar shows `🔒 scopuli: up · key <expired|revoked>`. The extension does **not** attempt to refresh; the operator uses `scopuli login` on the CLI to refresh.
- **5xx from the vault** → status bar stays on last-known state. Pi debug log records the error.

## 9. Testing

- Unit tests for `auth.ts` (env-var fallthrough, Keychain mock, file-fallback mock).
- Unit tests for `status-bar.ts` (state mapping, rendered strings).
- Integration test: a fake HTTP server that simulates the vault. The extension's client is tested against it.
- Manual test: install the extension into a real pi install, point at a real vault, verify the status bar updates.

## 10. Distribution

- `npm publish` to the `scopuli` org → `@scopuli/pi-extension`.
- Install: `pi install npm:@scopuli/pi-extension`.
- In dev, `extensions/pi/` is symlinked into `~/.pi/agent/extensions/scopuli`.
- Pinned version. No `latest` tag. The npm package's README documents the scopuli server version it was tested against.

## 11. Roadmap (v0.1+)

| Version | Adds |
|---|---|
| v0.1 | Slash command `/scopuli` with menu (list, search, status, refresh). |
| v0.2 | Tools: `scopuli_list`, `scopuli_get`, `scopuli_search` (read-only). |
| v0.3 | Tools: `scopuli_annotate` (tags + description, manage-permission only). |
| v0.4 | Auto-injection of secrets as env vars at agent start (with operator confirmation). |
| v1.0 | Multi-vault support. Profile-based config (`scopuli profiles`). |

## 12. Open questions

- **Should the extension auto-prompt for credentials on first run?** Current answer: no. The operator runs `scopuli login` once on the CLI; the extension then picks up the credentials. If the operator never runs `scopuli login`, the status bar shows `no credentials`. We can revisit when v0.1 ships.
- **Snooze interval for unreachable state?** Current answer: 30 s. Worth re-evaluating with operator feedback.
- **Should the extension read secrets at all?** Current answer: **no**. The MCP server is the agent's interface for that. The extension is meta-only (status, key info).
