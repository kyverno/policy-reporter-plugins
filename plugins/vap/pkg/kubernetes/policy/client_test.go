package policy

import (
	"context"
	"testing"

	sdk "github.com/kyverno/policy-reporter-plugins/sdk/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	admissionregistrationv1listers "k8s.io/client-go/listers/admissionregistration/v1"
	"k8s.io/client-go/tools/cache"
)

// newLister builds a ValidatingAdmissionPolicyLister directly from a local
// cache.Indexer, seeded with policies - the same lister type
// MetadataLookup.Lister() exposes, but without paying for a fake clientset
// and an informer's async initial sync.
func newLister(t *testing.T, policies ...*admissionregistrationv1.ValidatingAdmissionPolicy) admissionregistrationv1listers.ValidatingAdmissionPolicyLister {
	t.Helper()

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, p := range policies {
		require.NoError(t, indexer.Add(p))
	}

	return admissionregistrationv1listers.NewValidatingAdmissionPolicyLister(indexer)
}

func TestGetPolicies_MapsAnnotationsToPolicyListItem(t *testing.T) {
	lister := newLister(t, policyWithAnnotations("require-team-label", map[string]string{
		TitleAnnotation:       "Require Team Label",
		CategoryAnnotation:    "best-practices",
		SeverityAnnotation:    "high",
		DescriptionAnnotation: "requires a team label",
	}))

	client := NewClient(lister, Defaults{})

	list, err := client.GetPolicies(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)

	assert.Equal(t, sdk.PolicyListItem{
		Title:       "Require Team Label",
		Name:        "require-team-label",
		Category:    "best-practices",
		Severity:    "high",
		Description: "requires a team label",
	}, list[0])
}

func TestGetPolicies_TitleFallsBackToTitleCasedName(t *testing.T) {
	lister := newLister(t, policyWithAnnotations("require-team-label", nil))

	client := NewClient(lister, Defaults{})

	list, err := client.GetPolicies(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)

	assert.Equal(t, "Require-Team-Label", list[0].Title)
}

func TestGetPolicies_FallsBackToConfiguredDefaultsWhenNoAnnotation(t *testing.T) {
	lister := newLister(t, policyWithAnnotations("require-team-label", nil))

	client := NewClient(lister, Defaults{Severity: "medium", Category: "best-practices"})

	list, err := client.GetPolicies(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)

	assert.Equal(t, "medium", list[0].Severity)
	assert.Equal(t, "best-practices", list[0].Category)
}

func TestGetPolicies_AnnotationOverridesConfiguredDefaults(t *testing.T) {
	lister := newLister(t, policyWithAnnotations("require-team-label", map[string]string{
		SeverityAnnotation: "high",
		CategoryAnnotation: "compliance",
	}))

	client := NewClient(lister, Defaults{Severity: "medium", Category: "best-practices"})

	list, err := client.GetPolicies(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)

	assert.Equal(t, "high", list[0].Severity)
	assert.Equal(t, "compliance", list[0].Category)
}

func TestGetPolicies_EmptyWhenNoAnnotationAndNoConfiguredDefault(t *testing.T) {
	lister := newLister(t, policyWithAnnotations("require-team-label", nil))

	client := NewClient(lister, Defaults{})

	list, err := client.GetPolicies(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)

	assert.Empty(t, list[0].Severity)
	assert.Empty(t, list[0].Category)
}

func TestGetPolicies_NilListerReturnsError(t *testing.T) {
	client := NewClient(nil, Defaults{})

	_, err := client.GetPolicies(context.Background())
	assert.Error(t, err)
}

func TestGetPolicy_MapsSpecAndAnnotations(t *testing.T) {
	fp := admissionregistrationv1.Fail
	policy := policyWithAnnotations("require-team-label", map[string]string{
		TitleAnnotation:       "Require Team Label",
		CategoryAnnotation:    "best-practices",
		SeverityAnnotation:    "high",
		DescriptionAnnotation: "requires a team label",
		SubjectAnnotation:     "Pod, Deployment",
	})
	policy.Spec = admissionregistrationv1.ValidatingAdmissionPolicySpec{
		FailurePolicy: &fp,
		Validations: []admissionregistrationv1.Validation{
			{Expression: "true"},
		},
		MatchConditions: []admissionregistrationv1.MatchCondition{
			{Name: "always", Expression: "true"},
		},
		ParamKind: &admissionregistrationv1.ParamKind{Kind: "ConfigMap", APIVersion: "v1"},
	}

	client := NewClient(newLister(t, policy), Defaults{})

	details, err := client.GetPolicy(context.Background(), "require-team-label")
	require.NoError(t, err)

	assert.Equal(t, "require-team-label", details.Name)
	assert.Equal(t, "Require Team Label", details.Title)
	assert.Equal(t, "best-practices", details.Category)
	assert.Equal(t, "high", details.Severity)
	assert.Equal(t, "requires a team label", details.Description)
	require.NotNil(t, details.Engine)
	assert.Equal(t, "ValidatingAdmissionPolicy", details.Engine.Name)
	assert.Equal(t, []string{"Pod", "Deployment"}, details.Engine.Subjects)
	assert.Contains(t, details.Details, sdk.DetailsItem{Title: "FailurePolicy", Value: "Fail"})
	assert.Contains(t, details.Details, sdk.DetailsItem{Title: "Validations", Value: "1"})
	assert.Contains(t, details.Details, sdk.DetailsItem{Title: "MatchConditions", Value: "1"})
	assert.Contains(t, details.Details, sdk.DetailsItem{Title: "ParamKind", Value: "ConfigMap"})
	require.NotNil(t, details.SourceCode)
	assert.Equal(t, "yaml", details.SourceCode.ContentType)
	assert.Contains(t, details.SourceCode.Content, "require-team-label")
}

func TestGetPolicy_FallsBackToConfiguredDefaultsWhenNoAnnotation(t *testing.T) {
	policy := policyWithAnnotations("require-team-label", nil)

	client := NewClient(newLister(t, policy), Defaults{Severity: "medium", Category: "best-practices"})

	details, err := client.GetPolicy(context.Background(), "require-team-label")
	require.NoError(t, err)
	assert.Equal(t, "medium", details.Severity)
	assert.Equal(t, "best-practices", details.Category)
}

func TestGetPolicy_AnnotationOverridesConfiguredDefaults(t *testing.T) {
	policy := policyWithAnnotations("require-team-label", map[string]string{
		SeverityAnnotation: "high",
		CategoryAnnotation: "compliance",
	})

	client := NewClient(newLister(t, policy), Defaults{Severity: "medium", Category: "best-practices"})

	details, err := client.GetPolicy(context.Background(), "require-team-label")
	require.NoError(t, err)
	assert.Equal(t, "high", details.Severity)
	assert.Equal(t, "compliance", details.Category)
}

func TestGetPolicy_FailurePolicyDefaultsToFailWhenUnset(t *testing.T) {
	policy := policyWithAnnotations("require-team-label", nil)

	client := NewClient(newLister(t, policy), Defaults{})

	details, err := client.GetPolicy(context.Background(), "require-team-label")
	require.NoError(t, err)
	assert.Contains(t, details.Details, sdk.DetailsItem{Title: "FailurePolicy", Value: "Fail"})
}

func TestGetPolicy_TitleFallsBackToName(t *testing.T) {
	policy := policyWithAnnotations("require-team-label", nil)

	client := NewClient(newLister(t, policy), Defaults{})

	details, err := client.GetPolicy(context.Background(), "require-team-label")
	require.NoError(t, err)
	assert.Equal(t, "require-team-label", details.Title)
}

func TestGetPolicy_TrimsLeadingSlashFromPathParam(t *testing.T) {
	policy := policyWithAnnotations("require-team-label", nil)

	client := NewClient(newLister(t, policy), Defaults{})

	details, err := client.GetPolicy(context.Background(), "/require-team-label")
	require.NoError(t, err)
	assert.Equal(t, "require-team-label", details.Name)
}

func TestGetPolicy_NotFound(t *testing.T) {
	client := NewClient(newLister(t), Defaults{})

	_, err := client.GetPolicy(context.Background(), "does-not-exist")
	require.Error(t, err)
}

func TestGetPolicy_NilListerReturnsError(t *testing.T) {
	client := NewClient(nil, Defaults{})

	_, err := client.GetPolicy(context.Background(), "require-team-label")
	assert.Error(t, err)
}
