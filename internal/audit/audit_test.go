package audit

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	scrypt "github.com/lucaspdude/scopuli/internal/crypto"
	"github.com/lucaspdude/scopuli/internal/store"
	"github.com/lucaspdude/scopuli/internal/token"
)

func newAudit(t *testing.T) (*Logger, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	kek := bytes.Repeat([]byte{0x77}, 32)
	s, err := store.Open(context.Background(), filepath.Join(dir, "v.db"), kek, scrypt.DefaultKDFParams())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	hmacKey := token.AuditHMACKey("master", bytes.Repeat([]byte{0x55}, 16))
	return NewLogger(s, hmacKey), s
}

func TestAppendAndVerify(t *testing.T) {
	l, _ := newAudit(t)
	for i := 0; i < 5; i++ {
		if _, err := l.Append(context.Background(), Entry{
			TS: int64(i + 1), ActorKind: "operator", ActorID: 1,
			Action: "read", Path: "aws/prod/x", Result: "ok",
		}); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}
	ok, brokenID, _, _, err := l.Verify(context.Background())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatalf("chain broken at id %d", brokenID)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	l, s := newAudit(t)
	for i := 0; i < 3; i++ {
		_, _ = l.Append(context.Background(), Entry{
			TS: int64(i + 1), ActorKind: "operator", ActorID: 1,
			Action: "read", Path: "x", Result: "ok",
		})
	}
	// Tamper: change result of row id=2 from 'ok' to 'denied'.
	if _, err := s.DB().Exec(`UPDATE audit SET result = 'denied' WHERE id = 2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	ok, brokenID, _, _, err := l.Verify(context.Background())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("expected chain to be broken after tamper")
	}
	if brokenID != 2 {
		t.Fatalf("expected broken at id=2, got %d", brokenID)
	}
}

func TestAppendRespectsChain(t *testing.T) {
	l, _ := newAudit(t)
	// Append three, capture their IDs.
	var ids []int64
	for i := 0; i < 3; i++ {
		id, err := l.Append(context.Background(), Entry{
			TS: int64(i + 1), ActorKind: "operator", ActorID: 1,
			Action: "write", Path: "p", Result: "ok",
		})
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
		ids = append(ids, id)
	}
	if ids[0] != 1 || ids[1] != 2 || ids[2] != 3 {
		t.Fatalf("unexpected ids: %v", ids)
	}
}

func TestListRespectsFilters(t *testing.T) {
	l, s := newAudit(t)
	// Add a key actor
	_, _, _, err := token.AgentKey()
	if err != nil {
		t.Fatalf("AgentKey: %v", err)
	}
	// Insert directly to keep it simple.
	for i := 0; i < 5; i++ {
		_, _ = l.Append(context.Background(), Entry{
			TS: int64(i + 1), ActorKind: "key", ActorID: 42,
			Action: "read", Path: "x", Result: "ok",
		})
	}
	entries, err := l.List(context.Background(), 0, 42, 100)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
	// Since filter: only entries with ts >= 3.
	entries, err = l.List(context.Background(), 3, 0, 100)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries (ts >= 3), got %d", len(entries))
	}
	// Limit.
	entries, err = l.List(context.Background(), 0, 0, 2)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries with limit=2, got %d", len(entries))
	}
	_ = s
}
