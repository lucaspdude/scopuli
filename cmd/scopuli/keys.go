package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lucaspdude/scopuli/internal/client"
)

func newKeysCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "keys", Short: "Manage agent API keys"}
	cmd.AddCommand(
		newKeysCreateCmd(),
		newKeysListCmd(),
		newKeysGetCmd(),
		newKeysUpdateCmd(),
		newKeysRevokeCmd(),
		newKeysSearchCmd(),
	)
	return cmd
}

func newKeysCreateCmd() *cobra.Command {
	var scope, perms, expiresIn, description string
	var tags, meta []string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Issue a new agent key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client.EnvOrKeyring()
			if err != nil {
				return err
			}
			req := map[string]any{
				"name":        args[0],
				"scope":       scope,
				"permissions": perms,
				"expires_in":  expiresIn,
				"description": description,
				"tags":        tags,
				"metadata":    kvListToMap(meta),
			}
			out, err := c.CreateKey(req)
			if err != nil {
				return err
			}
			fmt.Println("name:", out["name"])
			fmt.Println("key:", out["key"])
			fmt.Println("prefix:", out["prefix"])
			fmt.Println("scope:", out["scope"])
			fmt.Println("permissions:", out["permissions"])
			return nil
		},
	}
	cmd.Flags().StringVar(&scope, "scope", "", "CSV of slash-path globs")
	cmd.Flags().StringVar(&perms, "permission", "read", "read or manage")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", "duration string (e.g. 30d, 720h)")
	cmd.Flags().StringVar(&description, "description", "", "Markdown description")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "tag (can be repeated)")
	cmd.Flags().StringSliceVar(&meta, "meta", nil, "metadata k=v")
	_ = cmd.MarkFlagRequired("scope")
	return cmd
}

func newKeysListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List keys",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := client.EnvOrKeyring()
			if err != nil {
				return err
			}
			var out []map[string]any
			status, err := c.GetJSON("/api/keys", &out)
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
}

func newKeysGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <name>",
		Short: "Show key details (prefix, scope, permissions, never the hash)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client.EnvOrKeyring()
			if err != nil {
				return err
			}
			var out map[string]any
			status, err := c.GetJSON("/api/keys/"+args[0], &out)
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
}

func newKeysUpdateCmd() *cobra.Command {
	var scope, perms, expiresIn, description string
	var addTags, removeTags, unsetMeta []string
	var setMeta []string
	cmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Update mutable fields on a key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client.EnvOrKeyring()
			if err != nil {
				return err
			}
			req := map[string]any{
				"add_tags":       addTags,
				"remove_tags":    removeTags,
				"set_metadata":   kvListToMap(setMeta),
				"unset_metadata": unsetMeta,
			}
			if scope != "" {
				req["scope"] = scope
			}
			if perms != "" {
				req["permissions"] = perms
			}
			if expiresIn != "" {
				req["expires_in"] = expiresIn
			}
			if description != "" {
				req["description"] = description
			}
			return c.AnnotateKey(args[0], req)
		},
	}
	cmd.Flags().StringVar(&scope, "scope", "", "new scope (CSV)")
	cmd.Flags().StringVar(&perms, "permission", "", "new permission: read|manage")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", "extend expiry")
	cmd.Flags().StringVar(&description, "description", "", "new description")
	cmd.Flags().StringSliceVar(&addTags, "add-tag", nil, "tag to add")
	cmd.Flags().StringSliceVar(&removeTags, "remove-tag", nil, "tag to remove")
	cmd.Flags().StringSliceVar(&setMeta, "set-meta", nil, "metadata k=v")
	cmd.Flags().StringSliceVar(&unsetMeta, "unset-meta", nil, "metadata key to remove")
	return cmd
}

func newKeysRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <name>",
		Short: "Revoke a key (instant)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client.EnvOrKeyring()
			if err != nil {
				return err
			}
			status, err := c.PostNoContent("/api/keys/"+args[0]+"/revoke", "")
			if err != nil {
				return err
			}
			if status < 200 || status >= 300 {
				return fmt.Errorf("status %d", status)
			}
			fmt.Println("revoked:", args[0])
			return nil
		},
	}
}

func newKeysSearchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "search <query>",
		Short: "FTS5 search across key name, description, metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client.EnvOrKeyring()
			if err != nil {
				return err
			}
			var out []map[string]any
			status, err := c.GetJSON("/api/keys/search?q="+queryEscape(args[0]), &out)
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
}

func queryEscape(s string) string {
	// Use the stdlib url.QueryEscape via client.
	return strings.ReplaceAll(s, " ", "+")
}

// silence unused import warnings if any
var _ = os.Stderr
