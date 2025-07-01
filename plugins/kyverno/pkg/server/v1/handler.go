package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/itchyny/json2yaml"
	"go.uber.org/zap"
	k8serror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kyverno/policy-reporter-plugins/sdk/api"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/core"
	v1 "github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/kyverno/v1"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/kyverno/v2beta1"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/kubernetes/kyverno/pol"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/server"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/utils"
)

var (
	ControllerKinds = []string{"Deployment", "DaemonSet", "StatefulSet", "CronJob", "Job"}
)

type APIHandler struct {
	client  pol.Client
	coreAPI *core.Client
}

func (h *APIHandler) Register(engine *gin.RouterGroup) error {
	engine.GET("policies", h.List)
	engine.GET("policies/*policy", h.Get)
	engine.POST("policies/exception", h.Exception)

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

			var rules []api.ExceptionRule

			if policy.GetSpec() != nil {
				rules = utils.Map(policy.GetSpec().Rules, func(rule v1.Rule) api.ExceptionRule {
					return api.ExceptionRule{Name: rule.Name}
				})
			}

			if policy.GetStatus() != nil {
				rules = append(rules, utils.Map(policy.GetStatus().Autogen.Rules, func(rule v1.Rule) api.ExceptionRule {
					return api.ExceptionRule{Name: rule.Name}
				})...)
			}

			request.Policies[i].Rules = rules
		}
	}

	pssList := make([]v1.PodSecurityStandard, 0)

	kinds := []string{request.Resource.Kind}
	if utils.Contains(ControllerKinds, request.Resource.Kind) {
		kinds = append(kinds, "Pod")

		for i, policy := range request.Policies {
			for _, rule := range policy.Rules {
				if strings.HasPrefix(rule.Name, "autogen-cronjob-") {
					request.Policies[i].Rules = append(
						policy.Rules,
						api.ExceptionRule{Name: strings.Replace(rule.Name, "autogen-cronjob-", "autogen-", 1)},
						api.ExceptionRule{Name: strings.TrimPrefix(rule.Name, "autogen-cronjob-")},
					)
				} else if strings.HasPrefix(rule.Name, "autogen-") {
					request.Policies[i].Rules = append(
						policy.Rules,
						api.ExceptionRule{Name: strings.TrimPrefix(rule.Name, "autogen-")},
					)
				}

				if cl, ok := rule.Props["controlsJSON"]; ok {
					var controls []pol.Control
					err := json.Unmarshal([]byte(cl), &controls)
					if err != nil {
						zap.L().Error("failed to unmarshal control", zap.Error(err), zap.String("control", cl))
						continue
					}

					for _, c := range controls {
						pss := v1.PodSecurityStandard{
							ControlName: c.Name,
						}
						if c.Images != nil {
							pss.Images = wildcardTagOrDigest(c.Images)
						}
						pssList = append(pssList, pss)
					}
				} else if cl, ok := rule.Props["controls"]; ok {
					controls := strings.Split(cl, ",")
					for _, c := range controls {
						pssList = append(pssList, v1.PodSecurityStandard{
							ControlName: c,
						})
					}
				}
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
			RuleNames: utils.Map(p.Rules, func(rule api.ExceptionRule) string {
				return rule.Name
			}),
		})
	}

	namespaces := make([]string, 0, 1)
	if request.Resource.Namespace != "" {
		namespaces = append(namespaces, request.Resource.Namespace)
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
							Namespaces: namespaces,
							Names:      []string{fmt.Sprintf("%s*", request.Resource.Name)},
						},
					},
				},
			},
			PodSecurity: pssList,
		},
	}

	data, _ := json.Marshal(exception)

	var output strings.Builder

	if err := json2yaml.Convert(&output, bytes.NewReader(data)); err != nil {
		ctx.AbortWithError(http.StatusBadRequest, err)
		return
	}

	minVersion := "1.11"
	if len(exception.Spec.PodSecurity) > 0 {
		minVersion = "1.12"
	}

	ctx.JSON(http.StatusOK, api.ExceptionResponse{
		MinVersion: minVersion,
		Resource:   output.String(),
	})
}

func NewHandler(client pol.Client, coreAPI *core.Client) *APIHandler {
	return &APIHandler{client, coreAPI}
}

func WithAPI(client pol.Client, coreAPI *core.Client) server.ServerOption {
	return func(s *server.Server) error {
		return s.Register("v1", NewHandler(client, coreAPI))
	}
}

var regexpTagOrDigest = regexp.MustCompile(":.*|@.*")

func wildcardTagOrDigest(images []string) []string {
	for i, s := range images {
		images[i] = regexpTagOrDigest.ReplaceAllString(s, "*")
	}
	return images
}
