// Package config parses scopuli's environment variables.
//
// All settings come from env vars in V0. See PLAN.md / ARCHITECTURE.md for
// the full reference.
package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Config is the validated runtime configuration.
type Config struct {
	MasterPassword string
	Bind           string
	DBPath         string
	LogLevel       string
	KeyDefaultTTL  time.Duration
	RateLimitRPS   float64
	AgentKeyRPS    float64
}

// FromEnv reads the configuration from the environment. Returns an error
// if MASTER_PASSWORD is missing (V0 is fail-loud on missing master password).
func FromEnv() (*Config, error) {
	c := &Config{
		Bind:         "127.0.0.1:8080",
		DBPath:       "/data/vault.db",
		LogLevel:     "info",
		RateLimitRPS: 20,
		AgentKeyRPS:  100,
	}
	c.MasterPassword = strings.TrimSpace(strings.TrimRight(getEnv("MASTER_PASSWORD", ""), "\r"))
	if c.MasterPassword == "" {
		return nil, errors.New("config: MASTER_PASSWORD env var is required")
	}
	if v := getEnv("SCOPULI_BIND", ""); v != "" {
		c.Bind = v
	}
	if v := getEnv("SCOPULI_DB_PATH", ""); v != "" {
		c.DBPath = v
	}
	if v := getEnv("SCOPULI_LOG_LEVEL", ""); v != "" {
		c.LogLevel = v
	}
	if v := getEnv("SCOPULI_KEY_DEFAULT_TTL", ""); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("config: SCOPULI_KEY_DEFAULT_TTL: %w", err)
		}
		c.KeyDefaultTTL = d
	}
	if v := getEnv("SCOPULI_RATE_LIMIT_RPS", ""); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f < 0 {
			return nil, fmt.Errorf("config: SCOPULI_RATE_LIMIT_RPS: %v", err)
		}
		c.RateLimitRPS = f
	}
	if v := getEnv("SCOPULI_AGENT_KEY_RPS", ""); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f < 0 {
			return nil, fmt.Errorf("config: SCOPULI_AGENT_KEY_RPS: %v", err)
		}
		c.AgentKeyRPS = f
	}
	return c, nil
}

func getEnv(key, fallback string) string {
	v, ok := lookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	return v
}
