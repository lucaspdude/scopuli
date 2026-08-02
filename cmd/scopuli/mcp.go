package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/lucaspdude/scopuli/internal/mcp"
)

// newMcpCmd implements `scopuli mcp-serve` (stdio JSON-RPC 2.0 server).
func newMcpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp-serve",
		Short: "Run the MCP server over stdio (for LLM runtimes)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMcp()
		},
	}
	return cmd
}

func runMcp() error {
	// Pick credentials from env vars first, then keyring.
	url := os.Getenv("SCOPULI_URL")
	tok := os.Getenv("SCOPULI_KEY")
	if url == "" || tok == "" {
		// Fall back to keyring / file. The MCP server inherits the
		// operator's login state.
		c, err := resolveCreds()
		if err != nil {
			return fmt.Errorf("no credentials (set SCOPULI_URL+SCOPULI_KEY or run `scopuli login`)")
		}
		if url == "" {
			url = c.URL
		}
		if tok == "" {
			tok = c.Token
		}
	}
	srv := mcp.NewServer(url, tok)
	// Trap signals to gracefully exit the stdio loop.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		os.Exit(0)
	}()
	if err := srv.ServeStdio(os.Stdin, os.Stdout); err != nil {
		return err
	}
	return nil
}

// resolveCreds is a tiny indirection so we can stub it in tests if needed.
var resolveCreds = defaultResolveCreds

func defaultResolveCreds() (creds, error) {
	out, err := exec.Command("scopuli", "login", "--show").Output()
	if err == nil {
		var c creds
		// Cheap parse — we know the format is fixed.
		fmt.Sscanf(string(out), "URL: %s\nToken: %s\n", &c.URL, &c.Token)
		return c, nil
	}
	return creds{}, err
}

type creds struct {
	URL   string
	Token string
}
