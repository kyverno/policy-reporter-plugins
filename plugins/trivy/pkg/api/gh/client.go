package gh

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/google/go-github/v58/github"
	"go.uber.org/zap"

	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/api"
)

var (
	ErrNotFound  = errors.New("GHSA not found")
	ErrReqFailed = errors.New("GHSA request failed")
)

type Client struct {
	baseClient *github.Client
}

func (c *Client) Get(ctx context.Context, GHSA string) (*github.GlobalSecurityAdvisory, error) {
	result, res, err := c.baseClient.SecurityAdvisories.GetGlobalSecurityAdvisories(ctx, GHSA)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return result, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		b, _ := io.ReadAll(res.Body)
		zap.L().Error("request failed", zap.String("response", string(b)), zap.String("GHSA", GHSA))

		return nil, ErrReqFailed
	}
}

func New() *Client {
	client := github.NewClient(api.NewHTTPClient())

	return &Client{client}
}
