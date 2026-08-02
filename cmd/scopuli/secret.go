package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lucaspdude/scopuli/internal/client"
)

func newSecretCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "secret", Short: "Manage secrets"}
	cmd.AddCommand(
		newSecretGetCmd(),
		newSecretSetCmd(),
		newSecretListCmd(),
		newSecretDeleteCmd(),
		newSecretSearchCmd(),
		newSecretAnnotateCmd(),
	)
	return cmd
}

func newSecretGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <path>",
		Short: "Print the plaintext value of a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client.EnvOrKeyring()
			if err != nil {
				return err
			}
			out, err := c.GetSecret(args[0])
			if err != nil {
				return err
			}
			fmt.Println(out["value"])
			return nil
		},
	}
}

func newSecretSetCmd() *cobra.Command {
	var label, description string
	var tags, meta []string
	var valueFromStdin, valueFromFile bool
	cmd := &cobra.Command{
		Use:   "set <path>",
		Short: "Create or update a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client.EnvOrKeyring()
			if err != nil {
				return err
			}
			val, err := resolveValue(valueFromStdin, valueFromFile)
			if err != nil {
				return err
			}
			req := map[string]any{
				"path":        args[0],
				"value":       val,
				"label":       label,
				"description": description,
				"tags":        tags,
				"metadata":    kvListToMap(meta),
			}
			return c.PutSecret(req)
		},
	}
	cmd.Flags().StringVar(&label, "label", "", "short label")
	cmd.Flags().StringVar(&description, "description", "", "Markdown description (max 8KB)")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "tag (can be repeated)")
	cmd.Flags().StringSliceVar(&meta, "meta", nil, "metadata key=value (can be repeated)")
	cmd.Flags().BoolVar(&valueFromStdin, "value-from-stdin", false, "read value from stdin")
	cmd.Flags().BoolVar(&valueFromFile, "value-from-file", false, "read value from a file path passed as second positional arg")
	return cmd
}

func newSecretListCmd() *cobra.Command {
	var prefix string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secrets (paths only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := client.EnvOrKeyring()
			if err != nil {
				return err
			}
			out, err := c.ListSecrets(prefix)
			if err != nil {
				return err
			}
			b, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(b))
			return nil
		},
	}
	cmd.Flags().StringVar(&prefix, "prefix", "", "filter by path prefix")
	return cmd
}

func newSecretDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <path>",
		Short: "Delete a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client.EnvOrKeyring()
			if err != nil {
				return err
			}
			status, err := c.Delete("/api/secrets/" + args[0])
			if err != nil {
				return err
			}
			if status < 200 || status >= 300 {
				return fmt.Errorf("status %d", status)
			}
			return nil
		},
	}
}

func newSecretSearchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "search <query>",
		Short: "FTS5 search across description and metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client.EnvOrKeyring()
			if err != nil {
				return err
			}
			out, err := c.SearchSecrets(args[0])
			if err != nil {
				return err
			}
			b, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(b))
			return nil
		},
	}
}

func newSecretAnnotateCmd() *cobra.Command {
	var addTags, removeTags, unsetMeta []string
	var description string
	var setMeta []string
	cmd := &cobra.Command{
		Use:   "annotate <path>",
		Short: "Edit tags/description/metadata incrementally",
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
			if description != "" {
				req["description"] = description
			}
			return c.AnnotateSecret(args[0], req)
		},
	}
	cmd.Flags().StringSliceVar(&addTags, "add-tag", nil, "tag to add")
	cmd.Flags().StringSliceVar(&removeTags, "remove-tag", nil, "tag to remove")
	cmd.Flags().StringVar(&description, "description", "", "new description (re-encrypts)")
	cmd.Flags().StringSliceVar(&setMeta, "set-meta", nil, "metadata k=v to set")
	cmd.Flags().StringSliceVar(&unsetMeta, "unset-meta", nil, "metadata key to remove")
	return cmd
}

func resolveValue(stdin, file bool) (string, error) {
	if stdin && file {
		return "", fmt.Errorf("--value-from-stdin and --value-from-file are mutually exclusive")
	}
	if stdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\n"), nil
	}
	if file {
		// The CLI binary accepts the file path as a positional argument
		// (not implemented here; kept simple for V0).
		return "", fmt.Errorf("--value-from-file: pass the file path as second arg (not yet implemented)")
	}
	// Fallback: prompt.
	fmt.Fprint(os.Stderr, "value: ")
	var input string
	if _, err := fmt.Scanln(&input); err != nil {
		return "", err
	}
	return input, nil
}

func kvListToMap(items []string) map[string]string {
	out := map[string]string{}
	for _, item := range items {
		eq := strings.IndexByte(item, '=')
		if eq < 0 {
			out[item] = ""
			continue
		}
		out[item[:eq]] = item[eq+1:]
	}
	return out
}
