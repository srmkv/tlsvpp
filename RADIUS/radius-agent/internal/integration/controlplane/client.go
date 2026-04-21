// Package controlplane implements the HTTP client that pushes resolved user
// records from radius-agent to the tlsagent control plane.
package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// UserRecord is the minimal user descriptor pushed to tlsagent.
type UserRecord struct {
	Username string `json:"username"`
	Profile  string `json:"profile"`
	Enabled  bool   `json:"enabled"`
	Source   string `json:"source"` // radius source ID for auditing
}

// ImportPayload is the request body for POST /api/admin/radius/import.
type ImportPayload struct {
	Users []UserRecord `json:"users"`
}

// ImportResult is the response body from POST /api/admin/radius/import.
type ImportResult struct {
	Created int      `json:"created"`
	Updated int      `json:"updated"`
	Skipped int      `json:"skipped"`
	Errors  []string `json:"errors,omitempty"`
}

// Client pushes user state to the tlsagent admin API.
type Client struct {
	APIBase    string
	Token      string
	httpClient *http.Client
}

// New returns a new Client. If apiBase is empty, all push calls are no-ops.
func New(apiBase, token string) *Client {
	return &Client{
		APIBase: strings.TrimRight(strings.TrimSpace(apiBase), "/"),
		Token:   token,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Enabled returns true when a control-plane API base URL is configured.
func (c *Client) Enabled() bool {
	return strings.TrimSpace(c.APIBase) != ""
}

// PushUsers pushes a resolved user list to tlsagent.
// The call is idempotent: tlsagent will create new users and update changed
// ones, skipping users whose state is identical.
// Returns nil if the client is not configured (api_base is empty).
func (c *Client) PushUsers(ctx context.Context, users []UserRecord) (*ImportResult, error) {
	if !c.Enabled() {
		return nil, nil
	}
	if len(users) == 0 {
		return &ImportResult{}, nil
	}

	payload, err := json.Marshal(ImportPayload{Users: users})
	if err != nil {
		return nil, fmt.Errorf("controlplane PushUsers marshal: %w", err)
	}

	url := c.APIBase + "/api/admin/radius/import"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("controlplane PushUsers new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("controlplane PushUsers http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("controlplane PushUsers: status %d from %s", resp.StatusCode, url)
	}

	var result ImportResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		// Non-fatal: request succeeded but response is unparseable
		log.Printf("controlplane PushUsers: decode response err=%v", err)
		return &result, nil
	}
	return &result, nil
}
