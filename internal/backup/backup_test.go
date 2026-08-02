package backup

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestSnapshotRestoreRoundTrip(t *testing.T) {
	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	src := bytes.NewReader(plaintext)
	var bundle bytes.Buffer
	if err := Snapshot(src, &bundle, "passphrase123"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	// header: 4 magic + 1 ver + 16 salt + 12 nonce = 33 bytes
	if bundle.Len() != 33+len(plaintext)+16 {
		t.Fatalf("bundle length = %d, want %d", bundle.Len(), 33+len(plaintext)+16)
	}
	var out bytes.Buffer
	if err := Restore(&bundle, &out, "passphrase123"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestRestoreWrongPassphrase(t *testing.T) {
	src := bytes.NewReader([]byte("payload"))
	var bundle bytes.Buffer
	if err := Snapshot(src, &bundle, "correct"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	var out bytes.Buffer
	if err := Restore(&bundle, &out, "wrong"); err == nil {
		t.Fatal("Restore with wrong passphrase should fail")
	}
}

func TestRestoreBadMagic(t *testing.T) {
	src := bytes.NewReader([]byte("not a bundle"))
	if err := Restore(src, io.Discard, "p"); err == nil {
		t.Fatal("Restore of non-bundle should fail")
	}
}

func TestSnapshotEmptyPassphrase(t *testing.T) {
	if err := Snapshot(bytes.NewReader(nil), io.Discard, ""); !errors.Is(err, errors.Unwrap(err)) && err == nil {
		// Either errors.Is check passes, or err == nil which we don't want.
		t.Fatalf("Snapshot with empty passphrase should fail")
	}
	// Robust check:
	if err := Snapshot(bytes.NewReader(nil), io.Discard, ""); err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}
