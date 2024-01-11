package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

type Client struct {
	baseURL string
	http    *http.Client
	auth    *BasicAuth
}

func (c *Client) Post(ctx context.Context, path string, payload any) (*http.Response, error) {
	body := new(bytes.Buffer)

	if err := json.NewEncoder(body).Encode(payload); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+path, body)
	if err != nil {
		return nil, err
	}

	if c.auth != nil {
		req.SetBasicAuth(c.auth.Username, c.auth.Password)
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	return c.Do(req)
}

func (c *Client) Get(ctx context.Context, path string, query url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}

	if c.auth != nil {
		req.SetBasicAuth(c.auth.Username, c.auth.Password)
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.URL.RawQuery = query.Encode()

	return c.Do(req)
}

func (c *Client) Fetch(ctx context.Context, api string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", api, nil)
	if err != nil {
		return nil, err
	}

	if c.auth != nil {
		req.SetBasicAuth(c.auth.Username, c.auth.Password)
	}

	return c.Do(req)
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.http.Do(req)
}

func New(options []ClientOption) (*Client, error) {
	client := &Client{
		http: NewHTTPClient(),
	}

	for _, o := range options {
		if err := o(client); err != nil {
			return nil, err
		}
	}

	return client, nil
}
