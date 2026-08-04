// client.ts — thin HTTP client for the scopuli vault.

import type { Credentials } from "./types.js";

export interface VaultKey {
  name: string;
  prefix: string;
  scope: string;
  permissions: string;
  revoked_at?: number;
  expires_at?: number;
}

export interface VaultInfo {
  up: boolean;
  keyCount: number;
  scope: "all" | "read" | "manage";
  errorReason?: string;
}

const TIMEOUT_MS = 1500;

async function fetchWithTimeout(input: string, init: RequestInit, ms: number): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(input, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

export async function probe(creds: Credentials): Promise<VaultInfo> {
  try {
    // /healthz requires no auth.
    const health = await fetchWithTimeout(`${creds.url}/healthz`, { method: "GET" }, TIMEOUT_MS);
    if (!health.ok) {
      return { up: false, keyCount: 0, scope: "read", errorReason: `healthz ${health.status}` };
    }
    // List keys (returns the caller's row if it's an agent key, all if operator).
    const headers = tokenHeader(creds.token);
    const keysResp = await fetchWithTimeout(`${creds.url}/api/keys`, { headers }, TIMEOUT_MS);
    if (!keysResp.ok) {
      if (keysResp.status === 401) {
        return { up: true, keyCount: 0, scope: "read", errorReason: "unauthorized" };
      }
      return { up: true, keyCount: 0, scope: "read", errorReason: `keys ${keysResp.status}` };
    }
    const keys = (await keysResp.json()) as VaultKey[];
    const revoked = keys.find((k) => k.revoked_at && k.revoked_at > 0);
    if (revoked) return { up: true, keyCount: 0, scope: "read", errorReason: "key revoked" };
    const expired = keys.find((k) => k.expires_at && k.expires_at > 0 && k.expires_at < Date.now());
    if (expired) return { up: true, keyCount: 0, scope: "read", errorReason: "key expired" };
    const operator = isOperatorToken(creds.token);
    const scope = operator ? "all" : (keys[0]?.permissions as "read" | "manage") ?? "read";
    return { up: true, keyCount: keys.length, scope };
  } catch (err) {
    return { up: false, keyCount: 0, scope: "read", errorReason: String(err) };
  }
}

function isOperatorToken(t: string): boolean {
  return t.startsWith("scot_live_");
}

function tokenHeader(token: string): Record<string, string> {
  if (token.startsWith("scot_live_")) return { "X-Scopuli-Operator": token };
  if (token.startsWith("sk_live_")) return { "X-Scopuli-Key": token };
  return {};
}
