// index.ts — the entrypoint. Registers a status bar widget that polls
// the vault every 30 seconds.

import { discoverCredentials } from "./auth.js";
import { probe } from "./client.js";
import { render } from "./status-bar.js";
import type { ConnectionState, PiAPI } from "./types.js";

const REFRESH_INTERVAL_MS = 30_000;

export default async function activate(pi: PiAPI): Promise<void> {
  let state: ConnectionState = { kind: "no-credentials" };

  // Re-probe whenever the credentials file or env changes (best-effort).
  const refresh = async (): Promise<void> => {
    const creds = await discoverCredentials();
    if (!creds) {
      state = { kind: "no-credentials" };
      return;
    }
    state = { kind: "checking", url: creds.url };
    const info = await probe(creds);
    if (!info.up) {
      state = { kind: "unreachable", url: creds.url, reason: info.errorReason ?? "?" };
      return;
    }
    if (info.errorReason === "unauthorized") {
      state = { kind: "auth-missing", url: creds.url };
      return;
    }
    if (info.errorReason === "key revoked") {
      state = { kind: "revoked", url: creds.url };
      return;
    }
    if (info.errorReason === "key expired") {
      state = { kind: "expired", url: creds.url };
      return;
    }
    state = {
      kind: "up",
      url: creds.url,
      keyCount: info.keyCount,
      scope: info.scope,
      relativeTime: "now",
    };
  };

  // Initial refresh + interval.
  await refresh();
  setInterval(refresh, REFRESH_INTERVAL_MS);

  // Register the status bar widget.
  pi.ui.statusBar.register("scopuli", () => render(state));
}
