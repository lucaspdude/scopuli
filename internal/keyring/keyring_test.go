package keyring

import (
	"runtime"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestLoadFallsBackToFileOnForeignKeychainEntry is the regression test for
// the agent-login incident: a non-JSON payload squatting on the keychain
// slot (e.g. a manually-created Keychain item) used to make Load fail hard,
// even with a valid credentials file. Load must fall through to the file.
func TestLoadFallsBackToFileOnForeignKeychainEntry(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("keychain backend only on darwin/linux")
	}
	// Never touch the operator's real slot.
	service = "scopuli-test"
	acct = "default"
	t.Cleanup(func() {
		_ = keyring.Delete(service, acct)
		service = serviceName
		acct = account
	})
	if err := keyring.Set(service, acct, "definitely-not-json"); err != nil {
		t.Skipf("keychain unavailable: %v", err)
	}

	home := t.TempDir()
	want := Credentials{URL: "https://example", Token: "scot_live_test"}
	if err := saveFile(home, want); err != nil {
		t.Fatalf("saveFile: %v", err)
	}
	got, err := Load(home)
	if err != nil {
		t.Fatalf("Load with foreign keychain entry: %v", err)
	}
	if got != want {
		t.Fatalf("Load = %+v, want %+v", got, want)
	}
}

// TestLoadPrefersValidKeychainEntry: a valid JSON keychain payload wins
// over the file, preserving the original precedence.
func TestLoadPrefersValidKeychainEntry(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("keychain backend only on darwin/linux")
	}
	service = "scopuli-test"
	acct = "default"
	t.Cleanup(func() {
		_ = keyring.Delete(service, acct)
		service = serviceName
		acct = account
	})
	if err := keyring.Set(service, acct, `{"url":"https://kc","token":"scot_live_kc"}`); err != nil {
		t.Skipf("keychain unavailable: %v", err)
	}

	home := t.TempDir()
	if err := saveFile(home, Credentials{URL: "https://file", Token: "scot_live_file"}); err != nil {
		t.Fatalf("saveFile: %v", err)
	}
	got, err := Load(home)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.URL != "https://kc" {
		t.Fatalf("Load = %+v, want keychain entry to win", got)
	}
}
