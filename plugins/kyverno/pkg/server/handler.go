package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	k8serror "k8s.io/apimachinery/pkg/api/errors"

	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/core"
	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/kubernetes/kyverno"
)

type APIHandler struct {
	client  kyverno.Client
	coreAPI *core.Client
}

func (h *APIHandler) Register(engine *gin.RouterGroup) error {
	engine.GET("policies", h.List)
	engine.GET("policies/*policy", h.Get)

	return nil
}

func (h *APIHandler) List(ctx *gin.Context) {
	list, err := h.client.GetPolicies(ctx)
	if err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to list policies: %w", err))
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
		ctx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to get policy details: %w", err))
		return
	}

	ctx.JSON(http.StatusOK, details)
}

func NewHandler(client kyverno.Client, coreAPI *core.Client) *APIHandler {
	return &APIHandler{client, coreAPI}
}

func WithAPI(client kyverno.Client, coreAPI *core.Client) ServerOption {
	return func(s *Server) error {
		return s.Register("api", NewHandler(client, coreAPI))
	}
}
