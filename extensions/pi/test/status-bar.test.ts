// tests for the status bar renderer.
import { test } from "node:test";
import assert from "node:assert/strict";
import { render } from "../src/status-bar.js";

test("no-credentials", () => {
  assert.equal(render({ kind: "no-credentials" }), "? scopuli: no credentials");
});

test("checking", () => {
  assert.equal(render({ kind: "checking", url: "http://x" }), "… scopuli: http://x");
});

test("up with single key", () => {
  const s = render({ kind: "up", url: "http://x", keyCount: 1, scope: "read", relativeTime: "now" });
  assert.match(s, /^🔒 scopuli: up · 1 key · scope read$/);
});

test("up with multiple keys", () => {
  const s = render({ kind: "up", url: "http://x", keyCount: 4, scope: "manage", relativeTime: "now" });
  assert.match(s, /^🔒 scopuli: up · 4 keys · scope manage$/);
});

test("expired", () => {
  const s = render({ kind: "expired", url: "http://x" });
  assert.match(s, /key expired/);
});

test("revoked", () => {
  const s = render({ kind: "revoked", url: "http://x" });
  assert.match(s, /key revoked/);
});

test("unreachable", () => {
  const s = render({ kind: "unreachable", url: "http://x", reason: "ECONNREFUSED" });
  assert.match(s, /unreachable/);
});

test("auth-missing", () => {
  const s = render({ kind: "auth-missing", url: "http://x" });
  assert.match(s, /login required/);
});
