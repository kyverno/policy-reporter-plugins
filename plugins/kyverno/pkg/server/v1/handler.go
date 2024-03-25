package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/itchyny/json2yaml"
	k8serror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kyverno/policy-reporter-plugins/sdk/api"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/core"
	v1 "github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/kyverno/v1"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/kyverno/v2beta1"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/kubernetes/kyverno"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/server"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/utils"
)

var (
	ControllerKinds = []string{"Deployment", "DaemonSet", "StatefulSet", "CronJob", "Job"}
)

type APIHandler struct {
	client  kyverno.Client
	coreAPI *core.Client
}

func (h *APIHandler) Register(engine *gin.RouterGroup) error {
	engine.GET("v1/policies", h.List)
	engine.GET("v1/policies/*policy", h.Get)
	engine.POST("v1/policies/exception", h.Exception)

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

func (h *APIHandler) Exception(ctx *gin.Context) {
	request := &api.ExceptionRequest{}

	if err := ctx.BindJSON(request); err != nil {
		ctx.AbortWithError(http.StatusBadRequest, err)
		return
	}

	for i, policy := range request.Policies {
		if len(policy.Rules) == 0 {
			name, namespace := utils.SplitPolicyName(policy.Name)

			policy, err := h.client.GetCRD(ctx, name, namespace)
			if err != nil {
				ctx.AbortWithError(http.StatusNotFound, err)
			}

			var rules []string

			if policy.GetSpec() != nil {
				rules = utils.Map(policy.GetSpec().Rules, func(rule v1.Rule) string {
					return rule.Name
				})
			}

			if policy.GetStatus() != nil {
				rules = append(rules, utils.Map(policy.GetStatus().Autogen.Rules, func(rule v1.Rule) string {
					return rule.Name
				})...)
			}

			request.Policies[i].Rules = rules
		}
	}

	kinds := []string{request.Resource.Kind}
	if utils.Contains(ControllerKinds, request.Resource.Kind) {
		kinds = append(kinds, "Pod")

		for i, policy := range request.Policies {
			if len(policy.Rules) == 1 && strings.HasPrefix(policy.Rules[0], "autogen-cronjob-") {
				request.Policies[i].Rules = append(
					policy.Rules,
					strings.Replace(policy.Rules[0], "autogen-cronjob-", "autogen-", 1),
					strings.TrimPrefix(policy.Rules[0], "autogen-cronjob-"),
				)
			} else if len(policy.Rules) == 1 && strings.HasPrefix(policy.Rules[0], "autogen-") {
				request.Policies[i].Rules = append(
					policy.Rules,
					strings.TrimPrefix(policy.Rules[0], "autogen-"),
				)
			}
		}
	}

	if request.Resource.Kind == "Deployment" {
		kinds = append(kinds, "ReplicaSet")
	}

	if request.Resource.Kind == "CronJob" {
		kinds = append(kinds, "Job")
	}

	exPolicies := make([]v2beta1.Exception, 0, len(request.Policies))
	for _, p := range request.Policies {
		exPolicies = append(exPolicies, v2beta1.Exception{
			PolicyName: p.Name,
			RuleNames:  p.Rules,
		})
	}

	exception := v2beta1.PolicyException{
		TypeMeta: metav1.TypeMeta{
			Kind:       "PolicyException",
			APIVersion: "kyverno.io/v2beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-exception", request.Resource.Name),
			Namespace: request.Resource.Namespace,
		},
		Spec: v2beta1.PolicyExceptionSpec{
			Exceptions: exPolicies,
			Match: v2beta1.MatchResources{
				Any: []v1.ResourceFilter{
					{
						ResourceDescription: v1.ResourceDescription{
							Kinds:      kinds,
							Namespaces: []string{request.Resource.Namespace},
							Names:      []string{fmt.Sprintf("%s*", request.Resource.Name)},
						},
					},
				},
			},
		},
	}

	data, _ := json.Marshal(exception)

	var output strings.Builder

	if err := json2yaml.Convert(&output, bytes.NewReader(data)); err != nil {
		ctx.AbortWithError(http.StatusBadRequest, err)
		return
	}

	ctx.JSON(http.StatusOK, api.ExceptionResponse{
		Resource: output.String(),
	})
}

func NewHandler(client kyverno.Client, coreAPI *core.Client) *APIHandler {
	return &APIHandler{client, coreAPI}
}

func WithAPI(client kyverno.Client, coreAPI *core.Client) server.ServerOption {
	return func(s *server.Server) error {
		return s.Register("api", NewHandler(client, coreAPI))
	}
}
