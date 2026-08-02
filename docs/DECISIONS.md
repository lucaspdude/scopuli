# scopuli — Decision log

> Every decision made during the planning phase, with the answer and the rationale. If you change a decision, update the corresponding section in `PLAN.md` / `ARCHITECTURE.md` / `SECURITY.md` and add a note here.

| ID | Decision | Answer | Date |
|---|---|---|---|
| D1 | Language / runtime | **Go 1.23** — single static binary, distroless image, mature crypto stdlib, official MCP SDK. |
| D2 | Client surface for V0 | **CLI only, no web UI.** Operator uses the CLI. Web UI is V1. |
| D3 | Network exposure | **Safe to expose to any network** (LAN or public). Bound to `127.0.0.1:8080` by default; operator overrides when putting a reverse proxy in front. The auth model makes the boundary safe regardless. |
| D4 | Scope syntax | **Slash paths with `*` glob.** `aws/dev/*` matches one path segment. |
| D5 | Master password source | **`MASTER_PASSWORD` env var.** Used at boot to derive the KEK. **Never sent over the wire.** |
| D6 | Key expiry behavior | **Hard expiry + audit row.** Expired keys return 401. |
| D7 | Default expiry on `keys create` | **No default.** Operator specifies `--expires-in` or accepts no expiry. |
| D8 | Audit retention | **Keep all rows indefinitely.** Operator can prune with `scopuli audit prune --before YYYY-MM-DD`. |
| D9 | Image registry | **GHCR** (`ghcr.io/lucaspdude/scopuli`). |
| D10 | Backup format | **Encrypted export bundle (age).** `scopuli snapshot --out bundle.age` and `scopuli restore --in bundle.age`. |
| D11 | First-boot operator-token flow | **Print to stdout on first boot.** Hash stored in `operators` table. Not printed again. |
| D12 | Operator tokens per operator | **One token.** Operator can rotate to a new one. |
| D13 | Operator token storage on the operator's Mac | **macOS Keychain / Linux secret service.** Plaintext file fallback (`~/.config/scopuli/credentials`, mode 0600) if the keychain is unavailable. |
| D14 | MCP transport | **stdio, CLI binary is local to each host.** Streamable HTTP MCP is V1. |
| D15 | Operator count | **Single operator.** No multi-user / RBAC in V0. |
| D16 | Permissions per agent key | **`read` or `manage`.** `manage` implies `read`. |
| D17 | Per-agent audit visibility | **Keys see their own activity only.** Operator sees the full log. |
| D18 | Description format on keys / secrets | **Markdown TEXT.** Free-form, intended for human and agent consumption. Capped at 8 KB per resource. Empty allowed. |
| D19 | Tags storage | **CSV inline** (`tags TEXT`) on the same row as the resource. Max 20 tags per resource, 64 chars per tag. Indexed with `LIKE` prefix matching; no separate table. |
| D20 | Structured metadata storage | **JSON column** (`metadata TEXT`) on the same row. Max 32 key-value pairs; key 64 chars, value 256 chars. Validated against a schema (`object` of strings) on every write. |
| D21 | Edit interface for metadata | **Extend existing endpoints.** `POST /api/secrets` and `POST /api/keys` accept optional `tags`, `description`, `metadata`. `POST /api/keys` becomes idempotent on `name` (UPSERT-as-update-or-create). No separate `PATCH /metadata` endpoint. `scopuli secret annotate` / `scopuli keys update` are CLI sugar. |
| D22 | Search on V0 | **SQLite FTS5** with `unicode61` tokenizer. Two virtual tables: `secrets_fts(path, description, metadata_text)` and `keys_fts(name, description, metadata_text)`. `metadata` JSON is flattened (`k1=v1; k2=v2`) into the index. Triggers keep FTS in sync on insert/update/delete. |
| D23 | Metadata permissions | **`read` permission reads metadata.** `manage` permission can edit metadata (tags, description, structured metadata) on resources within its scope. Operator can edit anything. Every metadata update emits an `audit` row. |
| D24 | pi-coding-agent extension MVP | **Status bar only.** A single indicator (e.g. `🔒 scopuli: up · 4 keys · scope read`) in the pi UI. No slash commands, no tools exposed to the agent in V0. Roadmap: add slash commands and tools in v0.1 of the extension. |
| D25 | pi extension authentication | **Auto-detect.** Try `SCOPULI_URL` + `SCOPULI_KEY` env vars first; then macOS Keychain (via `scopuli login` having been run on the host); then fallback to interactive prompt. No credentials stored by the extension itself. |
| D26 | pi extension distribution | **`npm` package** `@scopuli/pi-extension`. Install: `pi install npm:@scopuli/pi-extension`. In dev, `extensions/pi/` is symlinked into `~/.pi/agent/extensions/scopuli`. Mono-repo subdir. |

## Decisions made live during planning

These answers were taken via the `grill-with-docs` session (via `ask_user_question`). The recommended option was chosen for each.

## Open questions (parked for V1+)

- Multi-host Streamable HTTP MCP.
- Web UI for the operator.
- Multi-operator (TOTP-based unseal).
- 2FA / passkeys.
- Per-secret ACL beyond scope.
- LDAP / OIDC.
- Secret versioning / rollback.
- Webhooks on revocation.
- Per-key IP allowlists.
- HSM / auto-unseal.

If you want to change any of these decisions, just say so and I'll update the docs.