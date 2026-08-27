package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
	gocache "zgo.at/zcache/v2"

	sdk "github.com/kyverno/policy-reporter-plugins/sdk/api"
)

const policyAPIVersion = "admissionregistration.k8s.io/v1"

func newPartialPolicy(name string, annotations map[string]string) *metav1.PartialObjectMetadata {
	return &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			APIVersion: policyAPIVersion,
			Kind:       "ValidatingAdmissionPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
		},
	}
}

func newMetaClient(t *testing.T, policies ...*metav1.PartialObjectMetadata) *metadatafake.FakeMetadataClient {
	t.Helper()

	scheme := metadatafake.NewTestScheme()
	metav1.AddMetaToScheme(scheme)

	objs := make([]runtime.Object, 0, len(policies))
	for _, p := range policies {
		objs = append(objs, p)
	}

	return metadatafake.NewSimpleMetadataClient(scheme, objs...)
}

func newDynamicClient(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), objs...)
}

func unstructuredPolicy(name string, annotations map[string]string, spec map[string]any) *unstructured.Unstructured {
	metadata := map[string]any{"name": name}
	if annotations != nil {
		metadata["annotations"] = toAnyMap(annotations)
	}

	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": policyAPIVersion,
		"kind":       "ValidatingAdmissionPolicy",
		"metadata":   metadata,
		"spec":       spec,
	}}
}

func toAnyMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestGetPolicies_MapsAnnotationsToPolicyListItem(t *testing.T) {
	meta := newMetaClient(t, newPartialPolicy("require-team-label", map[string]string{
		TitleAnnotation:       "Require Team Label",
		CategoryAnnotation:    "best-practices",
		SeverityAnnotation:    "high",
		DescriptionAnnotation: "requires a team label",
	}))

	client := NewClient(meta, newDynamicClient(), nil)

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
	meta := newMetaClient(t, newPartialPolicy("require-team-label", nil))

	client := NewClient(meta, newDynamicClient(), nil)

	list, err := client.GetPolicies(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)

	assert.Equal(t, "Require-Team-Label", list[0].Title)
}

func TestGetPolicies_CategoryDefaultsToOther(t *testing.T) {
	meta := newMetaClient(t, newPartialPolicy("require-team-label", nil))

	client := NewClient(meta, newDynamicClient(), nil)

	list, err := client.GetPolicies(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)

	assert.Equal(t, "Other", list[0].Category)
}

func TestGetPolicies_UsesCacheOnHit(t *testing.T) {
	meta := newMetaClient(t, newPartialPolicy("require-team-label", nil))
	cache := gocache.New[string, []sdk.PolicyListItem](0, 0)
	cached := []sdk.PolicyListItem{{Name: "cached-policy"}}
	cache.Set(KeyListCache, cached)

	client := NewClient(meta, newDynamicClient(), cache)

	list, err := client.GetPolicies(context.Background())
	require.NoError(t, err)
	assert.Equal(t, cached, list)
}

func TestGetPolicy_MapsSpecAndAnnotations(t *testing.T) {
	unstr := unstructuredPolicy("require-team-label", map[string]string{
		TitleAnnotation:       "Require Team Label",
		CategoryAnnotation:    "best-practices",
		SeverityAnnotation:    "high",
		DescriptionAnnotation: "requires a team label",
		SubjectAnnotation:     "Pod, Deployment",
	}, map[string]any{
		"failurePolicy": "Fail",
		"validations": []any{
			map[string]any{"expression": "true"},
		},
		"matchConditions": []any{
			map[string]any{"expression": "true"},
		},
		"paramKind": map[string]any{"kind": "ConfigMap"},
	})

	client := NewClient(newMetaClient(t), newDynamicClient(unstr), nil)

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

func TestGetPolicy_TitleFallsBackToName(t *testing.T) {
	unstr := unstructuredPolicy("require-team-label", nil, map[string]any{})

	client := NewClient(newMetaClient(t), newDynamicClient(unstr), nil)

	details, err := client.GetPolicy(context.Background(), "require-team-label")
	require.NoError(t, err)
	assert.Equal(t, "require-team-label", details.Title)
}

func TestGetPolicy_TrimsLeadingSlashFromPathParam(t *testing.T) {
	unstr := unstructuredPolicy("require-team-label", nil, map[string]any{})

	client := NewClient(newMetaClient(t), newDynamicClient(unstr), nil)

	details, err := client.GetPolicy(context.Background(), "/require-team-label")
	require.NoError(t, err)
	assert.Equal(t, "require-team-label", details.Name)
}

func TestGetPolicy_NotFound(t *testing.T) {
	client := NewClient(newMetaClient(t), newDynamicClient(), nil)

	_, err := client.GetPolicy(context.Background(), "does-not-exist")
	require.Error(t, err)
}
