package controlplane

import "context"

type Client struct {
	APIBase string
	Token   string
}

func New(apiBase, token string) *Client { return &Client{APIBase: apiBase, Token: token} }

func (c *Client) PushResolvedPolicy(ctx context.Context, _ string, _ any) error {
	// TODO: интеграция в основной control-plane.
	return nil
}
