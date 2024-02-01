package v1

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/kyverno/policy-reporter-plugins/sdk/api"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/api/core"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/server"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/utils"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/vulnr"
)

type APIHandler struct {
	coreAPI *core.Client
	service *vulnr.Service
}

func (h *APIHandler) Register(engine *gin.RouterGroup) error {
	engine.GET("v1/policies", h.List)
	engine.GET("v1/policies/*policy", h.Get)

	return nil
}

func (h *APIHandler) List(ctx *gin.Context) {
	list, err := h.coreAPI.ListPolicies(ctx, url.Values{"sources": []string{"Trivy Vulnerability"}})
	if err != nil {
		zap.L().Error("failed to list policy list from core api", zap.Error(err))
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	policies := make([]*vulnr.Vulnerability, 0, len(list))
	mx := new(sync.Mutex)

	g := &errgroup.Group{}
	for _, p := range list {
		p := p
		g.Go(func() error {
			v, err := h.service.Get(ctx, p.Name)
			if err != nil {
				return fmt.Errorf("%s: %w", p.Name, err)
			}

			v.Category = p.Category
			v.Severity = p.Severity

			mx.Lock()
			policies = append(policies, v)
			mx.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		zap.L().Error("failed to policy details", zap.Error(err))
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	results := utils.Map(policies, func(p *vulnr.Vulnerability) api.PolicyListItem {
		return api.PolicyListItem{
			Name:        p.ID,
			Title:       p.Title,
			Description: p.Description,
			Category:    p.Category,
			Severity:    p.Severity,
		}
	})

	slices.SortStableFunc(results, func(a, b api.PolicyListItem) int {
		return strings.Compare(a.Title, b.Title)
	})

	ctx.JSON(http.StatusOK, results)
}

func (h *APIHandler) Get(ctx *gin.Context) {
	name := strings.TrimPrefix(ctx.Param("policy"), "/")

	v, err := h.service.Get(ctx, name)
	if err != nil {
		zap.L().Error("failed to policy details", zap.Error(err))
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	ctx.JSON(http.StatusOK, MapVulnrToDetails(v))
}

func NewHandler(coreAPI *core.Client, service *vulnr.Service) *APIHandler {
	return &APIHandler{coreAPI, service}
}

func WithAPI(coreAPI *core.Client, service *vulnr.Service) server.ServerOption {
	return func(s *server.Server) error {
		return s.Register("api/vulnr", NewHandler(coreAPI, service))
	}
}
