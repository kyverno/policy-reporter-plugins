package v1

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	k8serror "k8s.io/apimachinery/pkg/api/errors"

	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/core"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/kubernetes/kyverno/vpol"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/server"
)

var (
	ControllerKinds = []string{"Deployment", "DaemonSet", "StatefulSet", "CronJob", "Job"}
)

type APIHandler struct {
	client  vpol.Client
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
		ctx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to list validatingpolicies: %w", err))
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
		ctx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to get validatingpolicy details: %w", err))
		return
	}

	ctx.JSON(http.StatusOK, details)
}

func NewHandler(client vpol.Client, coreAPI *core.Client) *APIHandler {
	return &APIHandler{client, coreAPI}
}

func WithAPI(client vpol.Client, coreAPI *core.Client) server.ServerOption {
	return func(s *server.Server) error {
		return s.Register("vpol/v1", NewHandler(client, coreAPI))
	}
}
