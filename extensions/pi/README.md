# @scopuli/pi-extension

A [pi-coding-agent](https://github.com/lucaspdude/pi-coding-agent) extension that surfaces scopuli vault status in the agent's UI.

> **V0 of the extension** is a **status bar widget only**. No slash commands, no tools exposed to the agent. See [`docs/PI-EXTENSION.md`](../../docs/PI-EXTENSION.md) for the full plan.

## Install

```bash
pi install npm:@scopuli/pi-extension
```

In dev (this repo):

```bash
ln -s "$(pwd)/extensions/pi" ~/.pi/agent/extensions/scopuli
```

## Authentication discovery

In priority order, the extension reads credentials from:

1. `SCOPULI_URL` + `SCOPULI_KEY` env vars
2. macOS Keychain / Linux secret service (`service: scopuli`, `account: default`)
3. `~/.config/scopuli/credentials` (mode 0600)

The extension never **writes** credentials. Run `scopuli login` to populate them.

## What you see

The bottom-right of the pi UI shows one of:

| State | Display |
|---|---|
| Vault reachable, key loaded | `🔒 scopuli: up · N keys · scope <read|manage|all>` |
| Vault reachable, no credentials | `? scopuli: login required` |
| Key revoked | `⚠ scopuli: <url> · key revoked` |
| Key expired | `⚠ scopuli: <url> · key expired` |
| Vault unreachable | `⚠ scopuli: unreachable (<reason>)` |
| No credentials configured | `? scopuli: no credentials` |

The status bar refreshes every 30 seconds. Healthcheck uses a 1.5 s timeout — slow vaults never block the UI.

## Test

```bash
cd extensions/pi
npm install
npm test
```

## Roadmap (v0.1+)

- Slash command `/scopuli` with menu (list, search, status, refresh)
- Tools (read-only): `scopuli_list`, `scopuli_get`, `scopuli_search`
- Tools (mutate, manage keys): `scopuli_annotate`

See [`docs/PI-EXTENSION.md`](../../docs/PI-EXTENSION.md).
