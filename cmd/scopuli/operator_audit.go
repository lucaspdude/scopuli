package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/lucaspdude/scopuli/internal/client"
)

func newOperatorCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "operator", Short: "Operator-level commands"}
	cmd.AddCommand(newOperatorRotateCmd())
	return cmd
}

func newOperatorRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the master password and re-encrypt all secrets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(os.Stderr, "rotate is a server-side operation. Pass the new master password via the API.")
			fmt.Fprintln(os.Stderr, "Inside the container: POST /api/operator/rotate with {\"new_master_password\":...}")
			return nil
		},
	}
}

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Audit log inspection"}
	cmd.AddCommand(newAuditListCmd(), newAuditVerifyCmd())
	return cmd
}

func newAuditListCmd() *cobra.Command {
	var since, key string
	var limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List audit entries (operator only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := client.EnvOrKeyring()
			if err != nil {
				return err
			}
			path := "/api/audit?limit=" + strconv.Itoa(limit)
			if since != "" {
				path += "&since=" + since
			}
			if key != "" {
				path += "&key=" + key
			}
			var out any
			status, err := c.GetJSON(path, &out)
			if err != nil {
				return err
			}
			if status != 200 {
				return fmt.Errorf("status %d", status)
			}
			b, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(b))
			return nil
		},
	}
	cmd.Flags().StringVar(&since, "since", "", "since timestamp (ms)")
	cmd.Flags().StringVar(&key, "key", "", "filter by key name")
	cmd.Flags().IntVar(&limit, "limit", 100, "max entries")
	return cmd
}

func newAuditVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Walk the audit chain (operator only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := client.EnvOrKeyring()
			if err != nil {
				return err
			}
			var out map[string]any
			status, err := c.GetJSON("/api/audit/verify", &out)
			if err != nil {
				return err
			}
			if status == 200 {
				fmt.Println("ok")
				return nil
			}
			b, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(b))
			os.Exit(1)
			return nil
		},
	}
}
