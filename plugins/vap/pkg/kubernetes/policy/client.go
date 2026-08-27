package policy

import (
	"context"
	"fmt"
	"strings"

	sdk "github.com/kyverno/policy-reporter-plugins/sdk/api"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/metadata"
	gocache "zgo.at/zcache/v2"

	"github.com/kyverno/policy-reporter/vap-plugin/pkg/utils"
)

// policySchema is the GroupVersionResource for ValidatingAdmissionPolicy,
// which - unlike Kyverno's policy CRDs - is cluster-scoped only; there is no
// namespaced variant to also list/get.
var policySchema = admissionregistrationv1.SchemeGroupVersion.WithResource("validatingadmissionpolicies")

const (
	// KeyListCache is the cache key GetPolicies stores its result list
	// under.
	KeyListCache = "validatingadmissionpolicies"

	// TitleAnnotation, set on a ValidatingAdmissionPolicy, provides a
	// human-readable title for the Policy Reporter plugin API. Falls back
	// to a title-cased version of the policy name when absent.
	TitleAnnotation = "vap.kubernetes.io/title"
	// DescriptionAnnotation, set on a ValidatingAdmissionPolicy, provides
	// the description shown in the Policy Reporter plugin API.
	DescriptionAnnotation = "vap.kubernetes.io/description"
	// SubjectAnnotation, set on a ValidatingAdmissionPolicy, lists the
	// engine subjects (e.g. Kubernetes resource kinds) the policy targets,
	// as a comma-separated string.
	SubjectAnnotation = "vap.kubernetes.io/subject"
)

// Client exposes ValidatingAdmissionPolicy data in the shape the Policy
// Reporter plugin API contract expects (see sdk/api.Client).
type Client interface {
	GetPolicies(ctx context.Context) ([]sdk.PolicyListItem, error)
	GetPolicy(ctx context.Context, name string) (*sdk.Policy, error)
}

type client struct {
	metaClient    metadata.Interface
	dynamicClient dynamic.Interface
	cache         *gocache.Cache[string, []sdk.PolicyListItem]
}

// NewClient builds a Client backed by the given metadata and dynamic
// clients. cache may be nil, in which case GetPolicies always hits the
// KubeAPI.
func NewClient(metaClient metadata.Interface, dynamicClient dynamic.Interface, cache *gocache.Cache[string, []sdk.PolicyListItem]) Client {
	return &client{metaClient: metaClient, dynamicClient: dynamicClient, cache: cache}
}

func (c *client) GetPolicies(ctx context.Context) ([]sdk.PolicyListItem, error) {
	if c.cache != nil {
		if list, ok := c.cache.Get(KeyListCache); ok {
			return list, nil
		}
	}

	list, err := c.metaClient.Resource(policySchema).List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing validatingadmissionpolicies: %w", err)
	}

	policies := utils.Map(list.Items, func(p v1.PartialObjectMetadata) sdk.PolicyListItem {
		title := p.Annotations[TitleAnnotation]
		if title == "" {
			title = utils.Title(p.Name)
		}

		return sdk.PolicyListItem{
			Title:       title,
			Name:        p.Name,
			Category:    utils.Defaults(p.Annotations[CategoryAnnotation], "Other"),
			Severity:    p.Annotations[SeverityAnnotation],
			Description: p.Annotations[DescriptionAnnotation],
		}
	})

	if c.cache != nil {
		c.cache.Set(KeyListCache, policies)
	}

	return policies, nil
}

func (c *client) GetPolicy(ctx context.Context, name string) (*sdk.Policy, error) {
	name = strings.TrimPrefix(name, "/")

	unstr, err := c.dynamicClient.Resource(policySchema).Get(ctx, name, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting validatingadmissionpolicy %s: %w", name, err)
	}

	details := mapPolicy(unstr.Object)

	if details.Title == "" {
		details.Title = details.Name
	}

	return details, nil
}

// mapPolicy converts an unstructured ValidatingAdmissionPolicy's content
// into the sdk.Policy shape the plugin API returns.
func mapPolicy(policy map[string]any) *sdk.Policy {
	details := &sdk.Policy{
		SourceCode: &sdk.SourceCode{
			ContentType: "yaml",
			Content:     mapContent(policy),
		},
		Engine: &sdk.Engine{
			Name: "ValidatingAdmissionPolicy",
		},
	}

	if meta, ok := policy["metadata"].(map[string]any); ok {
		details.Name = utils.ToString(meta["name"])

		if annotations, ok := meta["annotations"].(map[string]any); ok {
			if t, ok := annotations[TitleAnnotation]; ok {
				details.Title = utils.ToString(t)
			}

			details.Category = utils.ToString(annotations[CategoryAnnotation])
			details.Severity = utils.ToString(annotations[SeverityAnnotation])
			details.Description = utils.ToString(annotations[DescriptionAnnotation])

			if s, ok := annotations[SubjectAnnotation]; ok {
				details.Engine.Subjects = utils.Map(strings.Split(utils.ToString(s), ","), func(s string) string {
					return strings.TrimSpace(s)
				})
			}
		}
	}

	if spec, ok := policy["spec"].(map[string]any); ok {
		details.Details = []sdk.DetailsItem{
			{Title: "FailurePolicy", Value: utils.Defaults(utils.ToString(spec["failurePolicy"]), "Fail")},
		}

		if validations, ok := spec["validations"].([]any); ok {
			details.Details = append(details.Details, sdk.DetailsItem{
				Title: "Validations", Value: fmt.Sprintf("%d", len(validations)),
			})
		}

		if matchConditions, ok := spec["matchConditions"].([]any); ok && len(matchConditions) > 0 {
			details.Details = append(details.Details, sdk.DetailsItem{
				Title: "MatchConditions", Value: fmt.Sprintf("%d", len(matchConditions)),
			})
		}

		if paramKind, ok := spec["paramKind"].(map[string]any); ok {
			details.Details = append(details.Details, sdk.DetailsItem{
				Title: "ParamKind", Value: utils.ToString(paramKind["kind"]),
			})
		}
	}

	return details
}
