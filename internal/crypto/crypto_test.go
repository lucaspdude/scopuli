package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// TestDeriveKEKDeterministic verifies Argon2id is deterministic for the
// same (password, salt, params) tuple. If this fails the audit chain and
// secret decryption will both be unrecoverable across boots.
func TestDeriveKEKDeterministic(t *testing.T) {
	salt := bytes.Repeat([]byte{0x42}, KDFSaltLen)
	p := DefaultKDFParams()
	k1 := DeriveKEK("correct horse battery staple", salt, p)
	k2 := DeriveKEK("correct horse battery staple", salt, p)
	if !bytes.Equal(k1, k2) {
		t.Fatal("KDF is not deterministic for identical inputs")
	}
	if len(k1) != 32 {
		t.Fatalf("KEK length = %d, want 32", len(k1))
	}
}

// TestDeriveKEKSensitiveToPassword verifies the KEK changes with the
// password (this is the entire point).
func TestDeriveKEKSensitiveToPassword(t *testing.T) {
	salt := bytes.Repeat([]byte{0x42}, KDFSaltLen)
	p := DefaultKDFParams()
	k1 := DeriveKEK("password-a", salt, p)
	k2 := DeriveKEK("password-b", salt, p)
	if bytes.Equal(k1, k2) {
		t.Fatal("two different passwords produced the same KEK")
	}
}

// TestDeriveKEKSensitiveToSalt verifies the KEK changes with the salt.
func TestDeriveKEKSensitiveToSalt(t *testing.T) {
	p := DefaultKDFParams()
	k1 := DeriveKEK("password", bytes.Repeat([]byte{0x01}, KDFSaltLen), p)
	k2 := DeriveKEK("password", bytes.Repeat([]byte{0x02}, KDFSaltLen), p)
	if bytes.Equal(k1, k2) {
		t.Fatal("two different salts produced the same KEK")
	}
}

// TestValidateParams exercises the bounds checks.
func TestValidateParams(t *testing.T) {
	good := DefaultKDFParams()
	if err := good.Validate(); err != nil {
		t.Fatalf("default params invalid: %v", err)
	}
	bad := good
	bad.MemoryKiB = 1
	if err := bad.Validate(); !errors.Is(err, ErrInvalidKDFParams) {
		t.Fatalf("expected ErrInvalidKDFParams, got %v", err)
	}
	bad = good
	bad.Iterations = 100
	if err := bad.Validate(); !errors.Is(err, ErrInvalidKDFParams) {
		t.Fatalf("expected ErrInvalidKDFParams, got %v", err)
	}
	bad = good
	bad.KeyLen = 16
	if err := bad.Validate(); !errors.Is(err, ErrInvalidKDFParams) {
		t.Fatalf("expected ErrInvalidKDFParams, got %v", err)
	}
}

// TestNewSaltUniqueness: two consecutive calls produce different salts.
// Statistical, but with 128 bits of entropy the collision probability is
// effectively zero.
func TestNewSaltUniqueness(t *testing.T) {
	s1, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	s2, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	if bytes.Equal(s1, s2) {
		t.Fatal("two salts were identical")
	}
	if len(s1) != KDFSaltLen {
		t.Fatalf("salt length = %d, want %d", len(s1), KDFSaltLen)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	kek := bytes.Repeat([]byte{0xab}, 32)
	plain := []byte("the eagle has landed")
	aad := []byte("aws/prod/eagle")
	sealed, err := Seal(kek, plain, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed) != NonceSize+len(plain)+16 {
		t.Fatalf("sealed length = %d, want %d", len(sealed), NonceSize+len(plain)+16)
	}
	got, err := Open(kek, sealed, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", got, plain)
	}
}

// TestOpenFailsOnTamperedCiphertext: changing one byte of the ciphertext
// MUST cause Open to fail with ErrAuth. This is the integrity property.
func TestOpenFailsOnTamperedCiphertext(t *testing.T) {
	kek := bytes.Repeat([]byte{0xab}, 32)
	plain := []byte("very secret value")
	aad := []byte("aws/prod/x")
	sealed, err := Seal(kek, plain, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealed[len(sealed)-1] ^= 0x01 // flip last bit of the GCM tag
	_, err = Open(kek, sealed, aad)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("Open on tampered ciphertext = %v, want ErrAuth", err)
	}
}

// TestOpenFailsOnWrongAAD: the AAD is part of the integrity guarantee.
// Swapping the AAD between two ciphertexts MUST cause both to fail.
func TestOpenFailsOnWrongAAD(t *testing.T) {
	kek := bytes.Repeat([]byte{0xcd}, 32)
	aad1 := []byte("aws/prod/foo")
	aad2 := []byte("aws/prod/bar")
	sealed, err := Seal(kek, []byte("payload"), aad1)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(kek, sealed, aad2); !errors.Is(err, ErrAuth) {
		t.Fatalf("Open with wrong AAD = %v, want ErrAuth", err)
	}
}

// TestOpenFailsOnWrongKEK: a different KEK MUST not decrypt.
func TestOpenFailsOnWrongKEK(t *testing.T) {
	kek1 := bytes.Repeat([]byte{0x01}, 32)
	kek2 := bytes.Repeat([]byte{0x02}, 32)
	sealed, err := Seal(kek1, []byte("payload"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(kek2, sealed, []byte("aad")); !errors.Is(err, ErrAuth) {
		t.Fatalf("Open with wrong KEK = %v, want ErrAuth", err)
	}
}

// TestAADSecretStable: same inputs always produce the same AAD. The audit
// chain and decryption both depend on this.
func TestAADSecretStable(t *testing.T) {
	a1 := AADSecret("aws/prod/stripe", "Production Stripe key", 1)
	a2 := AADSecret("aws/prod/stripe", "Production Stripe key", 1)
	if a1 != a2 {
		t.Fatalf("AAD is not deterministic")
	}
	a3 := AADSecret("aws/prod/stripe", "Production Stripe key", 2)
	if a1 == a3 {
		t.Fatalf("AAD did not change when version bumped")
	}
	a4 := AADSecret("aws/prod/stripe", "Different description", 1)
	if a1 == a4 {
		t.Fatalf("AAD did not change when description changed")
	}
}

// TestHMACDeterministic: HMAC must be deterministic and 32 bytes long.
func TestHMACDeterministic(t *testing.T) {
	k := []byte("hmac-key")
	m := []byte("the message")
	mac1 := HMAC(k, m)
	mac2 := HMAC(k, m)
	if !bytes.Equal(mac1, mac2) {
		t.Fatal("HMAC is not deterministic")
	}
	if len(mac1) != 32 {
		t.Fatalf("HMAC length = %d, want 32", len(mac1))
	}
}

// TestSHA256KnownAnswer uses the FIPS-180 KAT for "abc".
// Source: https://www.di-mgt.com.au/sha_testvectors.html
func TestSHA256KnownAnswer(t *testing.T) {
	got := hex.EncodeToString(SHA256([]byte("abc")))
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Fatalf("SHA-256(abc) = %s, want %s", got, want)
	}
}
