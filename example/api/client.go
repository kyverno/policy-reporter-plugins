package api

import (
	"context"
	"errors"

	"github.com/kyverno/policy-reporter-plugins/sdk/api"
)

type Client struct{}

//	@Summary		List of Policies
//	@Description	list all available policies
//	@Tags			policies
//	@Produce		json
//	@Success		200	{array}	PolicyListItem
//	@Failure		500
//	@Router			/v1/policies [get]
func (c *Client) GetPolicies(_ context.Context) ([]api.PolicyListItem, error) {
	return policies, nil
}

//	@Summary		Get single Policy by Name
//	@Description	get policy details by unique name, try "disallow-capabilities", "CVE-2022-41723" or "min"
//	@Tags			policies
//	@Produce		json
//	@Param			name	path		string	true	"Unique Policy Name"
//	@Success		200		{object}	Policy
//	@Failure		500
//	@Router			/v1/policies/{name} [get]
func (c *Client) GetPolicy(_ context.Context, name string) (*api.Policy, error) {
	pol, ok := details[name]
	if !ok {
		return nil, errors.New("not found")
	}

	return pol, nil
}

func NewClient() api.Client {
	return &Client{}
}
