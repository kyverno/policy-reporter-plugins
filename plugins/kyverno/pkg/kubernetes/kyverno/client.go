package kyverno

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	sdk "github.com/kyverno/policy-reporter-plugins/sdk/api"
	gocache "github.com/patrickmn/go-cache"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/metadata"

	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/core"
	apiV1 "github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/kyverno/v1"
	kyvernoTypes "github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/kyverno/v1"
	kyvernoV1 "github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/client/clientset/versioned/typed/kyverno/v1"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/kubernetes"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/utils"
)

var (
	clusterPolicySchema = apiV1.SchemeGroupVersion.WithResource("clusterpolicies")
	policySchema        = apiV1.SchemeGroupVersion.WithResource("policies")
)

const (
	KeyListCache = "policies"

	AnnotationPolicyTitle       = "policies.kyverno.io/title"
	AnnotationPolicyDescription = "policies.kyverno.io/description"
	AnnotationPolicySubjects    = "policies.kyverno.io/subject"
	AnnotationPolicyCategory    = "policies.kyverno.io/category"
	AnnotationPolicySeverity    = "policies.kyverno.io/severity"
	AnnotationK8sVersion        = "kyverno.io/kubernetes-version"
	AnnotationEngineVersion     = "kyverno.io/kyverno-version"
)

type Client interface {
	GetPolicies(ctx context.Context) ([]sdk.PolicyListItem, error)
	GetPolicy(ctx context.Context, name string) (*sdk.Policy, error)
	GetCRD(ctx context.Context, name, namespace string) (kyvernoTypes.PolicyInterface, error)
}

type client struct {
	metaClient    metadata.Interface
	dynamicClient dynamic.Interface
	v1Client      kyvernoV1.KyvernoV1Interface
	coreClient    *core.Client
	cache         *gocache.Cache
}

func (c *client) GetPolicies(ctx context.Context) ([]sdk.PolicyListItem, error) {
	if list, ok := c.cache.Get(KeyListCache); ok {
		zap.L().Debug("loading policy list from cache")
		return list.([]sdk.PolicyListItem), nil
	}

	results := make([]v1.PartialObjectMetadata, 0)
	mx := new(sync.Mutex)

	g := &errgroup.Group{}

	zap.L().Debug("loading policy list from KubeAPI")
	g.Go(func() error {
		list, err := kubernetes.Retry(func() (*v1.PartialObjectMetadataList, error) {
			return c.metaClient.Resource(clusterPolicySchema).List(ctx, v1.ListOptions{})
		})
		if err != nil {
			return err
		}

		mx.Lock()
		results = append(results, list.Items...)
		mx.Unlock()

		return nil
	})

	g.Go(func() error {
		list, err := kubernetes.Retry(func() (*v1.PartialObjectMetadataList, error) {
			return c.metaClient.Resource(policySchema).Namespace("").List(ctx, v1.ListOptions{})
		})
		if err != nil {
			return err
		}

		mx.Lock()
		results = append(results, list.Items...)
		mx.Unlock()

		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	policies := utils.Map(results, func(p v1.PartialObjectMetadata) sdk.PolicyListItem {
		var title string
		if v, ok := p.Annotations[AnnotationPolicyTitle]; ok {
			title = v
		} else if p.Name != "" {
			title = utils.Title(p.Name)
		}

		return sdk.PolicyListItem{
			Title:       title,
			Namespace:   p.Namespace,
			Name:        p.Name,
			Category:    utils.Defaults(p.Annotations[AnnotationPolicyCategory], "Other"),
			Severity:    p.Annotations[AnnotationPolicySeverity],
			Description: p.Annotations[AnnotationPolicyDescription],
		}
	})

	c.cache.Set(KeyListCache, policies, gocache.DefaultExpiration)

	return policies, nil
}

func (c *client) GetPolicy(ctx context.Context, resource string) (*sdk.Policy, error) {
	var name, namespace string

	parts := strings.Split(resource, "/")
	if len(parts) == 2 {
		namespace = parts[0]
		name = parts[1]
	} else {
		name = parts[0]
	}

	var unstr *unstructured.Unstructured
	var err error

	if namespace == "" {
		unstr, err = kubernetes.Retry(func() (*unstructured.Unstructured, error) {
			return c.dynamicClient.Resource(clusterPolicySchema).Get(ctx, name, v1.GetOptions{})
		})
	} else {
		unstr, err = kubernetes.Retry(func() (*unstructured.Unstructured, error) {
			return c.dynamicClient.Resource(policySchema).Namespace(namespace).Get(ctx, name, v1.GetOptions{})
		})
	}
	if err != nil {
		return nil, err
	}

	policy := unstr.Object
	details := &sdk.Policy{
		SourceCode: &sdk.SourceCode{
			ContentType: "yaml",
			Content:     mapContent(policy),
		},
	}

	metadata := policy["metadata"].(map[string]any)

	details.Name = name
	details.Namespace = namespace

	if a, ok := metadata["annotations"]; ok {
		annotations := a.(map[string]any)

		if t, ok := annotations[AnnotationPolicyTitle]; ok {
			details.Title = toString(t)
		}

		details.Category = toString(annotations[AnnotationPolicyCategory])
		details.Severity = toString(annotations[AnnotationPolicySeverity])
		details.Description = toString(annotations[AnnotationPolicyDescription])

		if t, ok := annotations[AnnotationPolicyTitle]; ok {
			details.Title = toString(t)
		}

		details.Engine = &sdk.Engine{
			Name:    "Kyverno",
			Version: toString(annotations[AnnotationEngineVersion]),
		}

		if t, ok := annotations[AnnotationPolicySubjects]; ok {
			details.Engine.Subjects = utils.Map(strings.Split(toString(t), ","), func(s string) string {
				return strings.TrimSpace(s)
			})
		}
	}

	if spec, ok := policy["spec"].(map[string]any); ok {
		details.Details = []sdk.DetailsItem{
			{Title: "Background", Value: toBoolString(spec["background"])},
			{Title: "Admission", Value: toBoolString(spec["admission"])},
			{Title: "FailurePolicy", Value: toString(spec["failurePolicy"])},
			{Title: "Mode", Value: toString(spec["validationFailureAction"])},
		}
	}

	query := url.Values{}
	query.Set("policy", name)
	query.Set("source", "kyverno")

	if namespace != "" {
		query.Set("namespace", namespace)
	}

	if exceptions, _ := c.coreClient.GetPropertyValues(ctx, "exception", query); len(exceptions) > 0 {
		list := utils.Map(exceptions, func(e core.ResultProperty) sdk.DetailsItem {
			return sdk.DetailsItem{
				Title: "Name",
				Value: fmt.Sprintf("%s/%s", e.Namespace, e.Property),
			}
		})

		details.Additional = append(details.Additional, sdk.Details{
			Title: "Policy Exceptions",
			Items: list,
		})
	}

	if details.Title == "" {
		details.Title = details.Name
	}

	return details, nil
}

func (c *client) GetCRD(ctx context.Context, name, namespace string) (kyvernoTypes.PolicyInterface, error) {
	if namespace == "" {
		return c.v1Client.ClusterPolicies().Get(ctx, name, v1.GetOptions{})
	}

	return c.v1Client.Policies(namespace).Get(ctx, name, v1.GetOptions{})
}

func toString(value any) string {
	if v, ok := value.(string); ok {
		return strings.TrimSpace(v)
	}

	return ""
}

func NewClient(metaClient metadata.Interface, dynamicClient dynamic.Interface, kclient kyvernoV1.KyvernoV1Interface, coreClient *core.Client, cache *gocache.Cache) Client {
	return &client{metaClient, dynamicClient, kclient, coreClient, cache}
}
