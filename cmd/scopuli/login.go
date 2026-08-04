package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/lucaspdude/scopuli/internal/client"
	"github.com/lucaspdude/scopuli/internal/keyring"
)

func newLoginCmd() *cobra.Command {
	var show bool
	var urlFlag string
	var tokenFlag string
	cmd := &cobra.Command{
		Use:   "login [url]",
		Short: "Save the operator token in the OS keyring",
		RunE: func(cmd *cobra.Command, args []string) error {
			if show {
				c, err := client.FromKeyring()
				if err != nil {
					return err
				}
				fmt.Println("URL:", c.BaseURL)
				fmt.Println("Token:", redact(c.Token))
				return nil
			}
			url := urlFlag
			if url == "" && len(args) > 0 {
				url = args[0]
			}
			tok := tokenFlag
			if tok == "" {
				fmt.Fprint(os.Stderr, "operator token: ")
				var input string
				if _, err := fmt.Scanln(&input); err != nil {
					return err
				}
				tok = input
			}
			if url == "" || tok == "" {
				return fmt.Errorf("url and token required")
			}
			if err := keyring.Save("", keyring.Credentials{URL: url, Token: tok}); err != nil {
				return err
			}
			c := client.New(url, tok)
			if err := c.Healthz(); err != nil {
				fmt.Fprintln(os.Stderr, "warning: vault not reachable:", err)
			}
			fmt.Println("credentials saved in", keyring.FilePath(""))
			return nil
		},
	}
	cmd.Flags().BoolVar(&show, "show", false, "show the saved URL and a redacted token")
	cmd.Flags().StringVar(&urlFlag, "url", "", "vault URL (default: read from arg)")
	cmd.Flags().StringVar(&tokenFlag, "token", "", "operator token (default: prompt)")
	return cmd
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove stored credentials",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := keyring.Delete(""); err != nil {
				return err
			}
			fmt.Println("credentials removed")
			return nil
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, _ []string) {
			out := map[string]string{"version": version, "commit": commit}
			b, _ := json.Marshal(out)
			fmt.Println(string(b))
		},
	}
}

func redact(t string) string {
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "...redacted..."
}
