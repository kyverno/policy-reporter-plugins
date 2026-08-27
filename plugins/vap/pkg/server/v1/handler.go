// Package v1 implements the Policy Reporter plugin API v1 contract (see
// github.com/kyverno/policy-reporter-plugins/sdk/api) for
// ValidatingAdmissionPolicy: listing policies and fetching one policy's
// details. Unlike Kyverno, ValidatingAdmissionPolicy has no PolicyException
// equivalent, so - matching the kyverno-plugin's vpol/ivpol handlers, which
// are in the same position for Kyverno's own CEL-based policy types - there
// is no exception-generation endpoint here.
package v1

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	k8serror "k8s.io/apimachinery/pkg/api/errors"

	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/policy"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/server"
)

type APIHandler struct {
	client policy.Client
}

func (h *APIHandler) Register(engine *gin.RouterGroup) error {
	engine.GET("policies", h.List)
	engine.GET("policies/*policy", h.Get)

	return nil
}

func (h *APIHandler) List(ctx *gin.Context) {
	list, err := h.client.GetPolicies(ctx)
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to list validatingadmissionpolicies: %w", err))
		return
	}

	ctx.JSON(http.StatusOK, list)
}

func (h *APIHandler) Get(ctx *gin.Context) {
	details, err := h.client.GetPolicy(ctx, strings.TrimPrefix(ctx.Param("policy"), "/"))

	if k8serror.IsNotFound(err) {
		ctx.AbortWithStatus(http.StatusNotFound)
		return
	}

	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to get validatingadmissionpolicy details: %w", err))
		return
	}

	ctx.JSON(http.StatusOK, details)
}

func NewHandler(client policy.Client) *APIHandler {
	return &APIHandler{client: client}
}

func WithAPI(client policy.Client) server.ServerOption {
	return func(s *server.Server) error {
		return s.Register("v1", NewHandler(client))
	}
}
