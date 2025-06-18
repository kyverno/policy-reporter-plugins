package cveawg

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/api"
)

const API = "https://cveawg.mitre.org"

var ErrNotFound = errors.New("CVE not found")

type Client struct {
	*api.Client
}

func (c *Client) GetCVE(ctx context.Context, name string) (*CVE, error) {
	resp, err := c.Get(ctx, fmt.Sprintf("/api/cve/%s", name), url.Values{})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return api.Decode[CVE](resp.Body)
}

func (c *Client) FetchFromTrivyDB(ctx context.Context, name string) (*TrivyCVE, error) {
	resp, err := c.Fetch(ctx, fmt.Sprintf("https://raw.githubusercontent.com/aquasecurity/trivy-db-data/main/k8s/cves/%s.json", name))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return api.Decode[TrivyCVE](resp.Body)
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		return nil, fmt.Errorf("unexpected error code: %d", resp.StatusCode)
	}
}

func New(options []api.ClientOption) (*Client, error) {
	options = append(options, api.WithBaseURL(API), api.WithProxyEnv())

	baseClient, err := api.New(options)
	if err != nil {
		return nil, err
	}

	client := &Client{
		Client: baseClient,
	}

	return client, nil
}
