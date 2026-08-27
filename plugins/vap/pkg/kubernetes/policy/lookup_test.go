package policy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func newLookup(t *testing.T, policies ...*admissionregistrationv1.ValidatingAdmissionPolicy) *MetadataLookup {
	t.Helper()

	client := fake.NewSimpleClientset()
	for _, p := range policies {
		_, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(context.Background(), p, metav1.CreateOptions{})
		require.NoError(t, err, "seeding policy")
	}

	// Long-lived (only cancelled at test cleanup), distinct from the sync
	// timeout below - see NewMetadataLookup's doc comment for why
	// conflating the two kills the informer's watch right after sync.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	lookup, err := NewMetadataLookup(ctx, client, 5*time.Second)
	require.NoError(t, err)

	return lookup
}

func policyWithAnnotation(name, severity string) *admissionregistrationv1.ValidatingAdmissionPolicy {
	p := &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	if severity != "" {
		p.Annotations = map[string]string{SeverityAnnotation: severity}
	}
	return p
}

func policyWithAnnotations(name string, annotations map[string]string) *admissionregistrationv1.ValidatingAdmissionPolicy {
	return &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: annotations},
	}
}

func TestMetadataFor_SeverityAndCategoryPresent(t *testing.T) {
	lookup := newLookup(t, policyWithAnnotations("p", map[string]string{
		SeverityAnnotation: "critical",
		CategoryAnnotation: "best-practices",
	}))

	meta, ok := lookup.MetadataFor("p")
	require.True(t, ok)
	assert.Equal(t, "critical", meta.Severity)
	assert.Equal(t, "best-practices", meta.Category)
}

// TestMetadataFor_InvalidSeverityValuePassesThroughUnvalidated documents a
// known gap: MetadataFor no longer checks a severity annotation against
// validSeverities (openreports.io/v1alpha1.ResultSeverity's enum) the way
// the old SeverityFor did - see validSeverities' own doc comment, which
// still explains why that check existed ("an invalid value would otherwise
// fail the whole Report update, not just this one field"). An out-of-enum
// value like "urgent" is now returned as-is with ok=true, and
// pkg/kubernetes/report.Client.Upsert only guards against an empty string,
// not an invalid one - so this can currently reach the API server and fail
// the Report update it's part of.
func TestMetadataFor_InvalidSeverityValuePassesThroughUnvalidated(t *testing.T) {
	lookup := newLookup(t, policyWithAnnotation("p", "urgent"))

	meta, ok := lookup.MetadataFor("p")
	require.True(t, ok)
	assert.Equal(t, "urgent", meta.Severity, "documents current pass-through behavior, not a desired guarantee")
}

func TestMetadataFor_AllEnumSeverityValues(t *testing.T) {
	for _, v := range []string{"critical", "high", "medium", "low", "info"} {
		lookup := newLookup(t, policyWithAnnotation("p", v))
		meta, ok := lookup.MetadataFor("p")
		require.True(t, ok)
		assert.Equal(t, v, meta.Severity)
	}
}

func TestMetadataFor_NoAnnotationsPresent(t *testing.T) {
	lookup := newLookup(t, policyWithAnnotations("p", nil))

	meta, ok := lookup.MetadataFor("p")
	require.True(t, ok, "expected ok=true whenever the policy exists, regardless of its annotations")
	assert.Empty(t, meta.Severity)
	assert.Empty(t, meta.Category)
}

func TestMetadataFor_EmptySeverityAnnotationValue(t *testing.T) {
	lookup := newLookup(t, policyWithAnnotations("p", map[string]string{
		SeverityAnnotation: "",
	}))

	meta, ok := lookup.MetadataFor("p")
	require.True(t, ok)
	assert.Empty(t, meta.Severity)
}

func TestMetadataFor_EmptyCategoryAnnotationValue(t *testing.T) {
	lookup := newLookup(t, policyWithAnnotations("p", map[string]string{
		CategoryAnnotation: "",
	}))

	meta, ok := lookup.MetadataFor("p")
	require.True(t, ok)
	assert.Empty(t, meta.Category)
}

func TestMetadataFor_AnyNonEmptyCategoryValueIsAccepted(t *testing.T) {
	// Category has no enum to validate against, unlike severity.
	lookup := newLookup(t, policyWithAnnotations("p", map[string]string{
		CategoryAnnotation: "whatever-the-policy-author-writes",
	}))

	meta, ok := lookup.MetadataFor("p")
	require.True(t, ok)
	assert.Equal(t, "whatever-the-policy-author-writes", meta.Category)
}

func TestMetadataFor_UnknownPolicy(t *testing.T) {
	lookup := newLookup(t)

	meta, ok := lookup.MetadataFor("does-not-exist")
	assert.False(t, ok, "expected ok=false for an unknown policy")
	assert.Equal(t, Metadata{}, meta)
}

// Regression test: an earlier version passed the same context to both
// factory.Start (the informer's whole lifetime) and the sync-wait deadline,
// so the deferred cancel() at the end of NewMetadataLookup killed the
// informer's watch moments after startup - it only ever saw the empty
// initial list, silently missing every policy created afterward. Verified
// against a real cluster: severity overrides never took effect because of
// this, with no error anywhere to point at it.
func TestMetadataLookup_ObservesPolicyCreatedAfterInitialSync(t *testing.T) {
	client := fake.NewSimpleClientset()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	lookup, err := NewMetadataLookup(ctx, client, 5*time.Second)
	require.NoError(t, err)

	_, ok := lookup.MetadataFor("late-policy")
	require.False(t, ok, "expected the policy to not be visible before it's created")

	_, err = client.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(
		context.Background(), policyWithAnnotation("late-policy", "critical"), metav1.CreateOptions{},
	)
	require.NoError(t, err)

	var meta Metadata
	require.Eventually(t, func() bool {
		var ok bool
		meta, ok = lookup.MetadataFor("late-policy")
		return ok
	}, 2*time.Second, 10*time.Millisecond, "expected the informer's watch to observe a policy created after the initial sync")
	assert.Equal(t, "critical", meta.Severity)
}
