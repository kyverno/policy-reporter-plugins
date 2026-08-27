package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8serror "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	sdk "github.com/kyverno/policy-reporter-plugins/sdk/api"
)

type fakePolicyClient struct {
	list      []sdk.PolicyListItem
	listErr   error
	policy    *sdk.Policy
	policyErr error
	gotPolicy string
}

func (f *fakePolicyClient) GetPolicies(ctx context.Context) ([]sdk.PolicyListItem, error) {
	return f.list, f.listErr
}

func (f *fakePolicyClient) GetPolicy(ctx context.Context, name string) (*sdk.Policy, error) {
	f.gotPolicy = name
	return f.policy, f.policyErr
}

func newTestServer(client *fakePolicyClient) *httptest.Server {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	group := engine.Group("v1")
	_ = NewHandler(client).Register(group)

	return httptest.NewServer(engine)
}

func TestList_ReturnsPolicyListFromClient(t *testing.T) {
	client := &fakePolicyClient{list: []sdk.PolicyListItem{
		{Name: "require-team-label", Title: "Require Team Label"},
	}}
	server := newTestServer(client)
	defer server.Close()

	resp, err := http.Get(server.URL + "/v1/policies")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body []sdk.PolicyListItem
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, client.list, body)
}

func TestList_ReturnsInternalServerErrorOnClientError(t *testing.T) {
	client := &fakePolicyClient{listErr: assertError("boom")}
	server := newTestServer(client)
	defer server.Close()

	resp, err := http.Get(server.URL + "/v1/policies")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestGet_ReturnsPolicyDetailsAndTrimsLeadingSlash(t *testing.T) {
	client := &fakePolicyClient{policy: &sdk.Policy{Name: "require-team-label", Title: "Require Team Label"}}
	server := newTestServer(client)
	defer server.Close()

	resp, err := http.Get(server.URL + "/v1/policies/require-team-label")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "require-team-label", client.gotPolicy)

	var body sdk.Policy
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, *client.policy, body)
}

func TestGet_ReturnsNotFoundWhenClientReportsNotFound(t *testing.T) {
	client := &fakePolicyClient{policyErr: k8serror.NewNotFound(schema.GroupResource{Resource: "validatingadmissionpolicies"}, "missing")}
	server := newTestServer(client)
	defer server.Close()

	resp, err := http.Get(server.URL + "/v1/policies/missing")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestGet_ReturnsInternalServerErrorOnOtherClientError(t *testing.T) {
	client := &fakePolicyClient{policyErr: assertError("boom")}
	server := newTestServer(client)
	defer server.Close()

	resp, err := http.Get(server.URL + "/v1/policies/require-team-label")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

type assertError string

func (e assertError) Error() string { return string(e) }
