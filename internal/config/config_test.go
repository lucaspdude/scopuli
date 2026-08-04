package config

import (
	"errors"
	"testing"
)

// withEnv sets env vars for the duration of the test, restoring previous values.
func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		prev, had := lookupEnv(k)
		if err := setEnv(k, v); err != nil {
			t.Fatalf("setEnv(%s): %v", k, err)
		}
		t.Cleanup(func() {
			if had {
				_ = setEnv(k, prev)
			} else {
				_ = unsetEnv(k)
			}
		})
	}
}

func TestFromEnvRequiresMasterPassword(t *testing.T) {
	withEnv(t, map[string]string{"MASTER_PASSWORD": ""})
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected error when MASTER_PASSWORD is empty")
	}
}

func TestFromEnvDefaults(t *testing.T) {
	withEnv(t, map[string]string{"MASTER_PASSWORD": "secret"})
	// Clear all other SCOPULI_* vars to ensure defaults apply.
	for _, k := range []string{
		"SCOPULI_BIND", "SCOPULI_DB_PATH", "SCOPULI_LOG_LEVEL",
		"SCOPULI_KEY_DEFAULT_TTL", "SCOPULI_RATE_LIMIT_RPS", "SCOPULI_AGENT_KEY_RPS",
	} {
		_, had := lookupEnv(k)
		if had {
			_ = unsetEnv(k)
		}
	}
	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if c.MasterPassword != "secret" {
		t.Errorf("master password = %q", c.MasterPassword)
	}
	if c.Bind != "127.0.0.1:8080" {
		t.Errorf("bind = %q", c.Bind)
	}
	if c.DBPath != "/data/vault.db" {
		t.Errorf("db path = %q", c.DBPath)
	}
	if c.LogLevel != "info" {
		t.Errorf("log level = %q", c.LogLevel)
	}
	if c.RateLimitRPS != 20 {
		t.Errorf("rate limit = %v", c.RateLimitRPS)
	}
}

func TestFromEnvOverrides(t *testing.T) {
	withEnv(t, map[string]string{
		"MASTER_PASSWORD":         "x",
		"SCOPULI_BIND":            "0.0.0.0:9999",
		"SCOPULI_DB_PATH":         "/tmp/v.db",
		"SCOPULI_LOG_LEVEL":       "debug",
		"SCOPULI_KEY_DEFAULT_TTL": "30m",
		"SCOPULI_RATE_LIMIT_RPS":  "5",
		"SCOPULI_AGENT_KEY_RPS":   "50",
	})
	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if c.Bind != "0.0.0.0:9999" {
		t.Errorf("bind = %q", c.Bind)
	}
	if c.DBPath != "/tmp/v.db" {
		t.Errorf("db path = %q", c.DBPath)
	}
	if c.LogLevel != "debug" {
		t.Errorf("log level = %q", c.LogLevel)
	}
	if c.KeyDefaultTTL.String() != "30m0s" {
		t.Errorf("key default TTL = %v", c.KeyDefaultTTL)
	}
	if c.RateLimitRPS != 5 {
		t.Errorf("rate limit = %v", c.RateLimitRPS)
	}
}

func TestFromEnvInvalidTTL(t *testing.T) {
	withEnv(t, map[string]string{
		"MASTER_PASSWORD":         "x",
		"SCOPULI_KEY_DEFAULT_TTL": "not-a-duration",
	})
	if _, err := FromEnv(); err == nil || !contains(err.Error(), "TTL") {
		t.Fatalf("expected TTL error, got %v", err)
	}
}

func TestFromEnvInvalidRate(t *testing.T) {
	withEnv(t, map[string]string{
		"MASTER_PASSWORD":        "x",
		"SCOPULI_RATE_LIMIT_RPS": "abc",
	})
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected rate-limit parse error")
	}
}

// errors.Is import only to keep compatibility if someone adds errors later.
var _ = errors.Is
