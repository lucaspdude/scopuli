// Package mcp implements the JSON-RPC 2.0 MCP server over stdio.
//
// The server speaks the Model Context Protocol tools API. Each tool call
// is forwarded to the scopuli HTTP API using the supplied credentials.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/lucaspdude/scopuli/internal/client"
)

// Server is the MCP server.
type Server struct {
	URL   string
	Token string
	HTTP  *client.Client
}

// NewServer returns a server bound to the given vault URL + token.
func NewServer(vaultURL, token string) *Server {
	return &Server{
		URL:   vaultURL,
		Token: token,
		HTTP:  client.New(vaultURL, token),
	}
}

// JSON-RPC 2.0 envelope.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Tool definitions for `tools/list`.
type toolList struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

func (s *Server) toolDefs() []toolList {
	str := func(d string) map[string]any {
		return map[string]any{"type": "string", "description": d}
	}
	obj := func(props map[string]any, req []string) map[string]any {
		return map[string]any{
			"type":       "object",
			"properties": props,
			"required":   req,
		}
	}
	return []toolList{
		{
			Name:        "list_secrets",
			Description: "List secrets visible to the calling key (path + label + tags + description; never value).",
			InputSchema: obj(map[string]any{
				"prefix": str("Filter by path prefix."),
				"tag":    str("Filter by tag."),
			}, nil),
			Annotations: map[string]any{"readOnlyHint": true},
		},
		{
			Name:        "get_secret",
			Description: "Fetch the plaintext value of one secret.",
			InputSchema: obj(map[string]any{"path": str("Slash-path of the secret.")}, []string{"path"}),
			Annotations: map[string]any{"readOnlyHint": true},
		},
		{
			Name:        "set_secret",
			Description: "Create or update a secret. Re-encrypts on description change.",
			InputSchema: obj(map[string]any{
				"path":        str("Slash-path."),
				"value":       str("Plaintext value."),
				"label":       str("Optional short label."),
				"description": str("Markdown description (max 8KB)."),
				"tags":        map[string]any{"type": "array", "items": str("tag")},
				"metadata":    map[string]any{"type": "object", "additionalProperties": str("value")},
			}, []string{"path", "value"}),
			Annotations: map[string]any{"idempotentHint": true},
		},
		{
			Name:        "delete_secret",
			Description: "Delete a secret (requires manage permission).",
			InputSchema: obj(map[string]any{"path": str("Slash-path.")}, []string{"path"}),
			Annotations: map[string]any{"destructiveHint": true},
		},
		{
			Name:        "search_secrets",
			Description: "Full-text search across description and metadata.",
			InputSchema: obj(map[string]any{
				"query": str("Search query."),
				"limit": map[string]any{"type": "integer"},
			}, []string{"query"}),
			Annotations: map[string]any{"readOnlyHint": true},
		},
		{
			Name:        "search_keys",
			Description: "Full-text search across key name, description, metadata.",
			InputSchema: obj(map[string]any{
				"query": str("Search query."),
			}, []string{"query"}),
			Annotations: map[string]any{"readOnlyHint": true},
		},
		{
			Name:        "list_keys",
			Description: "List agent keys visible to the caller.",
			InputSchema: obj(map[string]any{"tag": str("Filter by tag.")}, nil),
			Annotations: map[string]any{"readOnlyHint": true},
		},
		{
			Name:        "annotate_secret",
			Description: "Incrementally update tags/description/metadata on a secret.",
			InputSchema: obj(map[string]any{
				"path":           str("Slash-path."),
				"add_tags":       map[string]any{"type": "array", "items": str("tag")},
				"remove_tags":    map[string]any{"type": "array", "items": str("tag")},
				"description":    str("New description (re-encrypts)."),
				"set_metadata":   map[string]any{"type": "object", "additionalProperties": str("value")},
				"unset_metadata": map[string]any{"type": "array", "items": str("key")},
			}, []string{"path"}),
		},
		{
			Name:        "annotate_key",
			Description: "Incrementally update tags/description/metadata on an agent key.",
			InputSchema: obj(map[string]any{
				"name":           str("Key name."),
				"add_tags":       map[string]any{"type": "array", "items": str("tag")},
				"remove_tags":    map[string]any{"type": "array", "items": str("tag")},
				"description":    str("New description."),
				"set_metadata":   map[string]any{"type": "object", "additionalProperties": str("value")},
				"unset_metadata": map[string]any{"type": "array", "items": str("key")},
			}, []string{"name"}),
		},
	}
}

// ServeStdio reads JSON-RPC requests (one per line) from r and writes
// responses to w.
func (s *Server) ServeStdio(r io.Reader, w io.Writer) error {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			resp := s.handle(line)
			if resp != nil {
				if b, err := json.Marshal(resp); err == nil {
					if _, err := w.Write(append(b, '\n')); err != nil {
						return err
					}
				}
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (s *Server) handle(raw []byte) *rpcResponse {
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return &rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}}
	}
	switch req.Method {
	case "initialize":
		return &rpcResponse{
			JSONRPC: "2.0", ID: req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"serverInfo": map[string]any{
					"name":    "scopuli",
					"version": "0.0.1",
				},
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
			},
		}
	case "tools/list":
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": s.toolDefs()}}
	case "tools/call":
		return s.callTool(req)
	default:
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "method not found"}}
	}
}

type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type toolCallResult struct {
	Content []map[string]any `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

func (s *Server) callTool(req rpcRequest) *rpcResponse {
	var p toolCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "invalid params"}}
	}
	ctx := context.Background()
	var (
		text string
		err  error
	)
	switch p.Name {
	case "list_secrets":
		text, err = s.listSecrets(ctx, p.Arguments)
	case "get_secret":
		text, err = s.getSecret(ctx, p.Arguments)
	case "set_secret":
		text, err = s.setSecret(ctx, p.Arguments)
	case "delete_secret":
		text, err = s.deleteSecret(ctx, p.Arguments)
	case "search_secrets":
		text, err = s.searchSecrets(ctx, p.Arguments)
	case "search_keys":
		text, err = s.searchKeys(ctx, p.Arguments)
	case "list_keys":
		text, err = s.listKeys(ctx, p.Arguments)
	case "annotate_secret":
		text, err = s.annotateSecret(ctx, p.Arguments)
	case "annotate_key":
		text, err = s.annotateKey(ctx, p.Arguments)
	default:
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "unknown tool: " + p.Name}}
	}
	res := toolCallResult{IsError: err != nil}
	if err != nil {
		res.Content = []map[string]any{{"type": "text", "text": err.Error()}}
	} else {
		res.Content = []map[string]any{{"type": "text", "text": text}}
	}
	return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: res}
}

func (s *Server) listSecrets(ctx context.Context, args map[string]any) (string, error) {
	prefix := argString(args, "prefix")
	out, err := s.HTTP.ListSecrets(prefix)
	if err != nil {
		return "", err
	}
	return asJSON(out), nil
}

func (s *Server) getSecret(ctx context.Context, args map[string]any) (string, error) {
	pth, _ := args["path"].(string)
	if pth == "" {
		return "", errors.New("path required")
	}
	out, err := s.HTTP.GetSecret(pth)
	if err != nil {
		return "", err
	}
	// For MCP, return the value (this is the agent's primary purpose).
	val, _ := out["value"].(string)
	return val, nil
}

func (s *Server) setSecret(ctx context.Context, args map[string]any) (string, error) {
	if err := s.HTTP.PutSecret(args); err != nil {
		return "", err
	}
	return "ok", nil
}

func (s *Server) deleteSecret(ctx context.Context, args map[string]any) (string, error) {
	pth, _ := args["path"].(string)
	if pth == "" {
		return "", errors.New("path required")
	}
	status, err := s.HTTP.Delete("/api/secrets/" + url.PathEscape(pth))
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("status %d", status)
	}
	return "ok", nil
}

func (s *Server) searchSecrets(ctx context.Context, args map[string]any) (string, error) {
	q, _ := args["query"].(string)
	if q == "" {
		return "", errors.New("query required")
	}
	out, err := s.HTTP.SearchSecrets(q)
	if err != nil {
		return "", err
	}
	return asJSON(out), nil
}

func (s *Server) searchKeys(ctx context.Context, args map[string]any) (string, error) {
	q, _ := args["query"].(string)
	if q == "" {
		return "", errors.New("query required")
	}
	var out []map[string]any
	status, err := s.HTTP.GetJSON("/api/keys/search?q="+url.QueryEscape(q), &out)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("status %d", status)
	}
	return asJSON(out), nil
}

func (s *Server) listKeys(ctx context.Context, args map[string]any) (string, error) {
	var out []map[string]any
	status, err := s.HTTP.GetJSON("/api/keys", &out)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("status %d", status)
	}
	return asJSON(out), nil
}

func (s *Server) annotateSecret(ctx context.Context, args map[string]any) (string, error) {
	pth, _ := args["path"].(string)
	if pth == "" {
		return "", errors.New("path required")
	}
	if err := s.HTTP.AnnotateSecret(pth, args); err != nil {
		return "", err
	}
	return "ok", nil
}

func (s *Server) annotateKey(ctx context.Context, args map[string]any) (string, error) {
	name, _ := args["name"].(string)
	if name == "" {
		return "", errors.New("name required")
	}
	if err := s.HTTP.AnnotateKey(name, args); err != nil {
		return "", err
	}
	return "ok", nil
}

func asJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func argString(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return strings.TrimSpace(v)
}
