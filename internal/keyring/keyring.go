// Package keyring persists the operator token in the platform secret store
// (macOS Keychain / Linux secret service) with a file-mode fallback.
package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/zalando/go-keyring"
)

const (
	serviceName = "scopuli"
	account     = "default"
)

// service/acct are the live keychain coordinates; tests override them so
// they never touch the operator's real entry.
var (
	service = serviceName
	acct    = account
)

var ErrNoCredentials = errors.New("keyring: no credentials stored")

// Credentials is the (url, token) pair.
type Credentials struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

// Save persists credentials. On macOS uses Keychain; on Linux uses secret
// service; everywhere else falls back to a 0600 file.
func Save(homeDir string, c Credentials) error {
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		payload, err := json.Marshal(c)
		if err != nil {
			return err
		}
		if err := keyring.Set(service, acct, string(payload)); err == nil {
			return nil
		}
		// Fall through to file on error.
	}
	return saveFile(homeDir, c)
}

// Load retrieves credentials.
func Load(homeDir string) (Credentials, error) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		payload, err := keyring.Get(service, acct)
		if err == nil {
			var c Credentials
			if err := json.Unmarshal([]byte(payload), &c); err == nil {
				return c, nil
			}
			// A non-JSON payload means a foreign/corrupt entry (e.g. a
			// manually-created Keychain item squatting on our slot): fall
			// through to the file instead of failing hard.
		}
	}
	return loadFile(homeDir)
}

// Delete removes credentials.
func Delete(homeDir string) error {
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		_ = keyring.Delete(service, acct)
	}
	return os.Remove(credentialsPath(homeDir))
}

func saveFile(homeDir string, c Credentials) error {
	payload, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(credentialsPath(homeDir)), 0700); err != nil {
		return err
	}
	return os.WriteFile(credentialsPath(homeDir), payload, 0600)
}

func loadFile(homeDir string) (Credentials, error) {
	b, err := os.ReadFile(credentialsPath(homeDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Credentials{}, ErrNoCredentials
		}
		return Credentials{}, err
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return Credentials{}, err
	}
	return c, nil
}

func credentialsPath(homeDir string) string {
	if homeDir == "" {
		homeDir, _ = os.UserHomeDir()
	}
	return filepath.Join(homeDir, ".config", "scopuli", "credentials")
}

// FilePath returns the credentials file path (for documentation / show).
func FilePath(homeDir string) string { return credentialsPath(homeDir) }

// Helper to build the JSON for debug.
func (c Credentials) String() string {
	return fmt.Sprintf("Credentials{url=%s, token=%s...}", c.URL, short(c.Token))
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}
