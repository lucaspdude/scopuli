package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/lucaspdude/scopuli/internal/api"
	"github.com/lucaspdude/scopuli/internal/audit"
	"github.com/lucaspdude/scopuli/internal/store"
	"github.com/lucaspdude/scopuli/internal/token"
)

// newServeCmd implements `scopuli serve` (the daemon).
func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the scopuli vault daemon",
		RunE:  runServe,
	}
}

func runServe(cmd *cobra.Command, _ []string) error {
	masterPassword := os.Getenv("MASTER_PASSWORD")
	if masterPassword == "" {
		return errors.New("MASTER_PASSWORD env var is required")
	}
	bind := getenv("SCOPULI_BIND", "127.0.0.1:8080")
	dbPath := getenv("SCOPULI_DB_PATH", "/data/vault.db")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s, kek, err := store.OpenWithMasterPassword(ctx, dbPath, masterPassword)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer s.Close()

	hmacSalt, err := s.GetMeta(ctx, "hmac_key_salt")
	if err != nil || len(hmacSalt) == 0 {
		hmacSalt = make([]byte, 16)
		for i := range hmacSalt {
			hmacSalt[i] = byte(i)
		}
		_ = s.SetMeta(ctx, "hmac_key_salt", hmacSalt)
	}
	hmacKey := token.AuditHMACKey(masterPassword, hmacSalt)
	logger := audit.NewLogger(s, hmacKey)

	fresh, err := s.IsFresh(ctx)
	if err != nil {
		return err
	}
	if fresh {
		if err := bootstrapFirstBoot(ctx, s); err != nil {
			return fmt.Errorf("first boot: %w", err)
		}
		if ok, id, _, _, _ := logger.Verify(ctx); !ok {
			return fmt.Errorf("audit verify failed at id %d", id)
		}
		slog.Info("first boot complete")
	} else {
		slog.Info("scopuli booted", "db", dbPath)
	}

	srv := &api.Server{
		Store:        s,
		Audit:        logger,
		KEK:          kek,
		Bind:         bind,
		LogLevel:     os.Getenv("SCOPULI_LOG_LEVEL"),
		StartedAt:    time.Now(),
		OperatorName: "primary",
		SessionKey:   api.UISessionKey(kek),
	}
	httpSrv := &http.Server{
		Addr:              bind,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		slog.Info("shutting down")
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		_ = httpSrv.Shutdown(shutCtx)
		cancel()
	}()

	slog.Info("listening", "addr", bind)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func bootstrapFirstBoot(ctx context.Context, s *store.Store) error {
	tok, hash, prefix, err := token.OperatorToken()
	if err != nil {
		return err
	}
	op := &store.Operator{
		Name: "primary", Hash: hash, Prefix: prefix, CreatedAt: time.Now().UnixMilli(),
	}
	if err := s.CreateOperator(ctx, op); err != nil {
		return err
	}
	if err := s.MarkFirstBootDone(ctx); err != nil {
		return err
	}
	fmt.Println("================================================================")
	fmt.Println("scopuli: first boot")
	fmt.Println("operator token (save to your password manager):")
	fmt.Println(tok)
	fmt.Println("================================================================")
	return nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
