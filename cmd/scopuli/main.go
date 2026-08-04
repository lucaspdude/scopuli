// scopuli — credential vault CLI / daemon.
//
// This is the single binary. Subcommand dispatch lives in subcommands.go.
package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "v0.0.1"
	commit  = "dev"
)

func main() {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "scopuli",
		Short: "Self-hosted credential vault",
		Long:  "scopuli is a self-hosted credential vault for sharing scoped secrets with agents and humans.",
		// If no subcommand is given, print help.
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	root.PersistentPreRun = func(_ *cobra.Command, _ []string) {
		setupLogger()
	}
	root.AddCommand(
		newServeCmd(),
		newLoginCmd(),
		newLogoutCmd(),
		newVersionCmd(),
		newSecretCmd(),
		newKeysCmd(),
		newOperatorCmd(),
		newAuditCmd(),
		newMcpCmd(),
	)
	return root
}

func setupLogger() {
	lvl := os.Getenv("SCOPULI_LOG_LEVEL")
	if lvl == "" {
		lvl = "info"
	}
	var level slog.Level
	switch lvl {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(h))
}
