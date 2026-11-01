package coord

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// CacheFile is the node's copy of its last map inside state_dir.
const CacheFile = "netmap.json"

// StatusError is a non-200 answer of the coordination.
type StatusError struct {
	Code int
	Msg  string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("coord: status %d: %s", e.Code, e.Msg)
}

// IsStatus reports whether err is a StatusError with code.
func IsStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == code
}

// Client is a node's side of the coordination. Every call is bounded by
// its context; the long-poll needs a deadline above LongPoll.
type Client struct {
	base string
	http *http.Client

	mu    sync.Mutex
	token string
}

// NewClient returns a client of the coordination at rawURL (https://…)
// that accepts only the certificate with fingerprint fp.
func NewClient(rawURL, fp string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("coord: url %q must be https://host:port", rawURL)
	}
	tc, err := PinnedTLSConfig(fp)
	if err != nil {
		return nil, err
	}
	return &Client{
		base: strings.TrimRight(rawURL, "/"),
		http: &http.Client{Transport: &http.Transport{TLSClientConfig: tc, ForceAttemptHTTP2: true}},
	}, nil
}

// Token returns the token of the last registration, or "".
func (c *Client) Token() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

// do sends a request with the node's token and returns the body of a 200.
func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	if tok := c.Token(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{Code: resp.StatusCode, Msg: strings.TrimSpace(string(b))}
	}
	return b, nil
}

// Register registers the node and keeps the token for the other calls.
func (c *Client) Register(ctx context.Context, req RegisterRequest) (RegisterResponse, error) {
	var resp RegisterResponse
	b, err := c.do(ctx, http.MethodPost, "/v1/register", req)
	if err != nil {
		return resp, err
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		return resp, err
	}
	c.mu.Lock()
	c.token = resp.Token
	c.mu.Unlock()
	return resp, nil
}

// Netmap long-polls the map newer than since and returns it with the raw
// body, which is what the cache keeps.
func (c *Client) Netmap(ctx context.Context, since uint64) (Netmap, []byte, error) {
	var nm Netmap
	b, err := c.do(ctx, http.MethodGet, "/v1/netmap?since="+strconv.FormatUint(since, 10), nil)
	if err != nil {
		return nm, nil, err
	}
	if err := json.Unmarshal(b, &nm); err != nil {
		return nm, nil, err
	}
	return nm, b, nil
}

// ReportEndpoints replaces the node's endpoints.
func (c *Client) ReportEndpoints(ctx context.Context, eps []string) error {
	_, err := c.do(ctx, http.MethodPost, "/v1/endpoints", EndpointsRequest{Endpoints: eps})
	return err
}

// SaveCache writes the raw body of a map to dir/netmap.json.
func SaveCache(dir string, raw []byte) error {
	return writeFileAtomic(filepath.Join(dir, CacheFile), raw, 0o600)
}

// LoadCache reads dir/netmap.json; the error wraps os.ErrNotExist when
// there is no cache yet.
func LoadCache(dir string) (Netmap, error) {
	var nm Netmap
	b, err := os.ReadFile(filepath.Join(dir, CacheFile))
	if err != nil {
		return nm, err
	}
	if err := json.Unmarshal(b, &nm); err != nil {
		return nm, fmt.Errorf("coord: %s: %w", CacheFile, err)
	}
	return nm, nil
}
