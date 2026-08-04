// Package client is the HTTP client used by the scopuli CLI and MCP server.
// It owns the credentials path resolution and HTTP plumbing.
package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lucaspdude/scopuli/internal/keyring"
)

// Client is the scopuli HTTP client.
type Client struct {
	BaseURL string
	Token   string // operator token OR agent key
	HTTP    *http.Client
}

// New returns a Client that authenticates with the given token against the
// given base URL.
func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// FromKeyring loads credentials from the OS keyring or file fallback.
func FromKeyring() (*Client, error) {
	creds, err := keyring.Load("")
	if err != nil {
		return nil, err
	}
	return New(creds.URL, creds.Token), nil
}

// do performs a request and returns the response body bytes (caller-decoded).
func (c *Client) do(method, path, body string) ([]byte, int, error) {
	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequest(method, c.BaseURL+path, strings.NewReader(body))
	} else {
		req, err = http.NewRequest(method, c.BaseURL+path, nil)
	}
	if err != nil {
		return nil, 0, err
	}
	if strings.HasPrefix(c.Token, "scot_live_") {
		req.Header.Set("X-Scopuli-Operator", c.Token)
	} else if strings.HasPrefix(c.Token, "sk_live_") {
		req.Header.Set("X-Scopuli-Key", c.Token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data, resp.StatusCode, nil
}

// GetJSON issues a GET and decodes JSON into v.
func (c *Client) GetJSON(path string, v any) (int, error) {
	data, status, err := c.do("GET", path, "")
	if err != nil {
		return status, err
	}
	if status >= 200 && status < 300 && v != nil && len(data) > 0 {
		if err := json.Unmarshal(data, v); err != nil {
			return status, fmt.Errorf("decode: %w (body=%s)", err, string(data))
		}
	}
	return status, nil
}

// PostJSON issues a POST and decodes JSON into v.
func (c *Client) PostJSON(path, body string, v any) (int, error) {
	data, status, err := c.do("POST", path, body)
	if err != nil {
		return status, err
	}
	if status >= 200 && status < 300 && v != nil && len(data) > 0 {
		if err := json.Unmarshal(data, v); err != nil {
			return status, fmt.Errorf("decode: %w (body=%s)", err, string(data))
		}
	}
	return status, nil
}

// PostNoContent issues a POST and discards the body. Returns just the status.
func (c *Client) PostNoContent(path, body string) (int, error) {
	_, status, err := c.do("POST", path, body)
	return status, err
}

// Delete issues a DELETE.
func (c *Client) Delete(path string) (int, error) {
	_, status, err := c.do("DELETE", path, "")
	return status, err
}

// PutSecret issues POST /api/secrets with the canonical JSON shape.
func (c *Client) PutSecret(req map[string]any) error {
	b, _ := json.Marshal(req)
	status, err := c.PostNoContent("/api/secrets", string(b))
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("status %d", status)
	}
	return nil
}

// AnnotateSecret issues POST /api/secrets/annotate?path=...
func (c *Client) AnnotateSecret(path string, req map[string]any) error {
	b, _ := json.Marshal(req)
	q := url.Values{"path": {path}}
	status, err := c.PostNoContent("/api/secrets/annotate?"+q.Encode(), string(b))
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("status %d", status)
	}
	return nil
}

// AnnotateKey issues POST /api/keys/{name}/update.
func (c *Client) AnnotateKey(name string, req map[string]any) error {
	b, _ := json.Marshal(req)
	status, err := c.PostNoContent("/api/keys/"+url.PathEscape(name)+"/update", string(b))
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("status %d", status)
	}
	return nil
}

// CreateKey issues POST /api/keys.
func (c *Client) CreateKey(req map[string]any) (map[string]any, error) {
	b, _ := json.Marshal(req)
	var out map[string]any
	status, err := c.PostJSON("/api/keys", string(b), &out)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("status %d", status)
	}
	return out, nil
}

// GetSecret issues GET /api/secrets/<path>.
func (c *Client) GetSecret(path string) (map[string]any, error) {
	var out map[string]any
	status, err := c.GetJSON("/api/secrets/"+url.PathEscape(path), &out)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("status %d", status)
	}
	return out, nil
}

// ListSecrets issues GET /api/secrets. When reveal is true, the server
// returns full plaintext values instead of masked previews.
func (c *Client) ListSecrets(prefix string, reveal bool) ([]map[string]any, error) {
	q := url.Values{}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	if reveal {
		q.Set("reveal", "1")
	}
	path := "/api/secrets"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out []map[string]any
	status, err := c.GetJSON(path, &out)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("status %d", status)
	}
	return out, nil
}

// SearchSecrets issues GET /api/secrets/search?q=...
func (c *Client) SearchSecrets(q string) ([]map[string]any, error) {
	var out []map[string]any
	status, err := c.GetJSON("/api/secrets/search?q="+url.QueryEscape(q), &out)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("status %d", status)
	}
	return out, nil
}

// Healthz issues GET /healthz.
func (c *Client) Healthz() error {
	_, status, err := c.do("GET", "/healthz", "")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("healthz status %d", status)
	}
	return nil
}

// ServerIsUp returns true if /healthz returns 200.
func (c *Client) ServerIsUp() bool {
	return c.Healthz() == nil
}

// ErrAuthMissing is returned when no credentials are configured and no
// token flag was given.
var ErrAuthMissing = errors.New("client: not logged in (run `scopuli login`)")

// MustClient resolves credentials from the keyring or returns ErrAuthMissing.
func MustClient() (*Client, error) {
	c, err := FromKeyring()
	if err != nil {
		if errors.Is(err, keyring.ErrNoCredentials) {
			return nil, ErrAuthMissing
		}
		return nil, err
	}
	return c, nil
}

// envOrKeyring prefers env var SCOPULI_URL+SCOPULI_KEY. SCOPULI_OPERATOR_TOKEN
// is accepted as an alias for SCOPULI_KEY (operators frequently use the
// explicit name in their dotenv / config.fish). SCOPULI_KEY wins if both are
// set.
func envOrKeyring() (*Client, error) {
	if url := os.Getenv("SCOPULI_URL"); url != "" {
		tok := os.Getenv("SCOPULI_KEY")
		if tok == "" {
			tok = os.Getenv("SCOPULI_OPERATOR_TOKEN")
		}
		if tok == "" {
			return nil, errors.New("scopuli: SCOPULI_URL set but SCOPULI_KEY (or SCOPULI_OPERATOR_TOKEN) missing")
		}
		return New(url, tok), nil
	}
	return MustClient()
}

// EnvOrKeyring is the public alias used by the CLI.
func EnvOrKeyring() (*Client, error) { return envOrKeyring() }

// UnusedBuffer is here so the file imports bytes even if not used directly.
var _ = bytes.NewBuffer
