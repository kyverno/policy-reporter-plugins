package policy

import (
	"context"
	"fmt"
	"strings"

	sdk "github.com/kyverno/policy-reporter-plugins/sdk/api"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/labels"
	admissionregistrationv1listers "k8s.io/client-go/listers/admissionregistration/v1"

	"github.com/kyverno/policy-reporter/vap-plugin/pkg/utils"
)

const (
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

// client reads from the same informer-backed lister MetadataLookup uses
// (see NewClient) rather than issuing its own KubeAPI calls: the informer's
// local cache already avoids per-request KubeAPI traffic, so a separate
// TTL cache on top of it would just be a second, redundant cache.
type client struct {
	lister admissionregistrationv1listers.ValidatingAdmissionPolicyLister
}

// NewClient builds a Client backed by lister - the same
// ValidatingAdmissionPolicyLister exposed by MetadataLookup.Lister(), so the
// plugin API reuses the app's one ValidatingAdmissionPolicy informer instead
// of starting a second one. lister may be nil (e.g. when the informer failed
// to sync at startup - see MetadataLookup), in which case both methods
// return an error instead of panicking.
func NewClient(lister admissionregistrationv1listers.ValidatingAdmissionPolicyLister) Client {
	return &client{lister: lister}
}

func (c *client) GetPolicies(_ context.Context) ([]sdk.PolicyListItem, error) {
	if c.lister == nil {
		return nil, fmt.Errorf("validatingadmissionpolicy lister not available")
	}

	list, err := c.lister.List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("listing validatingadmissionpolicies: %w", err)
	}

	return utils.Map(list, func(p *admissionregistrationv1.ValidatingAdmissionPolicy) sdk.PolicyListItem {
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
	}), nil
}

func (c *client) GetPolicy(_ context.Context, name string) (*sdk.Policy, error) {
	if c.lister == nil {
		return nil, fmt.Errorf("validatingadmissionpolicy lister not available")
	}

	p, err := c.lister.Get(strings.TrimPrefix(name, "/"))
	if err != nil {
		return nil, fmt.Errorf("getting validatingadmissionpolicy %s: %w", name, err)
	}

	details := mapPolicy(p)

	if details.Title == "" {
		details.Title = details.Name
	}

	return details, nil
}

// mapPolicy converts a ValidatingAdmissionPolicy into the sdk.Policy shape
// the plugin API returns.
func mapPolicy(p *admissionregistrationv1.ValidatingAdmissionPolicy) *sdk.Policy {
	details := &sdk.Policy{
		Name: p.Name,
		SourceCode: &sdk.SourceCode{
			ContentType: "yaml",
			Content:     mapContent(p),
		},
		Engine: &sdk.Engine{
			Name: "ValidatingAdmissionPolicy",
		},
		Category:    p.Annotations[CategoryAnnotation],
		Severity:    p.Annotations[SeverityAnnotation],
		Description: p.Annotations[DescriptionAnnotation],
	}

	if t, ok := p.Annotations[TitleAnnotation]; ok {
		details.Title = t
	}

	if s, ok := p.Annotations[SubjectAnnotation]; ok {
		details.Engine.Subjects = utils.Map(strings.Split(s, ","), strings.TrimSpace)
	}

	details.Details = []sdk.DetailsItem{
		{Title: "FailurePolicy", Value: failurePolicyValue(p.Spec.FailurePolicy)},
	}

	if len(p.Spec.Validations) > 0 {
		details.Details = append(details.Details, sdk.DetailsItem{
			Title: "Validations", Value: fmt.Sprintf("%d", len(p.Spec.Validations)),
		})
	}

	if len(p.Spec.MatchConditions) > 0 {
		details.Details = append(details.Details, sdk.DetailsItem{
			Title: "MatchConditions", Value: fmt.Sprintf("%d", len(p.Spec.MatchConditions)),
		})
	}

	if p.Spec.ParamKind != nil {
		details.Details = append(details.Details, sdk.DetailsItem{
			Title: "ParamKind", Value: p.Spec.ParamKind.Kind,
		})
	}

	return details
}

// failurePolicyValue mirrors the ValidatingAdmissionPolicy admission
// plugin's own default: an unset failurePolicy behaves as "Fail".
func failurePolicyValue(fp *admissionregistrationv1.FailurePolicyType) string {
	if fp == nil || *fp == "" {
		return "Fail"
	}

	return string(*fp)
}
