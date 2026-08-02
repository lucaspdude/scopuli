// auth.ts — credential discovery.
//
// Order:
//   1. SCOPULI_URL + SCOPULI_KEY env vars
//   2. macOS Keychain entry "scopuli" / "default"
//   3. Linux secret-service entry "scopuli" / "default"
//   4. ~/.config/scopuli/credentials file (mode 0600)
//
// We never WRITE credentials from the extension.

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Credentials } from "./types.js";

export async function discoverCredentials(): Promise<Credentials | null> {
  const envURL = process.env.SCOPULI_URL;
  const envTok = process.env.SCOPULI_KEY;
  if (envURL && envTok) {
    return { url: envURL, token: envTok };
  }

  // Platform-native secret stores. We import dynamically so the file-mode
  // fallback works on every platform without a hard dep.
  if (process.platform === "darwin" || process.platform === "linux") {
    try {
      const keyring = await import("keyring").catch(() => null);
      if (keyring) {
        const payload = await keyring.loadEntry("scopuli", "default");
        if (payload) {
          const parsed = JSON.parse(payload) as Credentials;
          if (parsed.url && parsed.token) return parsed;
        }
      }
    } catch {
      // fall through
    }
  }

  // File-mode fallback.
  const file = path.join(os.homedir(), ".config", "scopuli", "credentials");
  try {
    const data = await fs.readFile(file, "utf8");
    const parsed = JSON.parse(data) as Credentials;
    if (parsed.url && parsed.token) return parsed;
  } catch {
    // no credentials file
  }

  return null;
}
