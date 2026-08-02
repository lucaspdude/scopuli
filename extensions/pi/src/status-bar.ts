// status-bar.ts — render the status bar text for a given state.

import type { ConnectionState } from "./types.js";

export function render(state: ConnectionState): string {
  switch (state.kind) {
    case "no-credentials":
      return "? scopuli: no credentials";
    case "checking":
      return `… scopuli: ${state.url}`;
    case "up":
      return `🔒 scopuli: up · ${state.keyCount} key${state.keyCount === 1 ? "" : "s"} · scope ${state.scope}`;
    case "expired":
      return `⚠ scopuli: ${state.url} · key expired`;
    case "revoked":
      return `⚠ scopuli: ${state.url} · key revoked`;
    case "unreachable":
      return `⚠ scopuli: unreachable (${state.reason})`;
    case "auth-missing":
      return `? scopuli: ${state.url} · login required`;
  }
}
