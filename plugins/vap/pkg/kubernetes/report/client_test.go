package report

import (
	"context"
	"errors"
	"testing"

	"github.com/openreports/reports-api/pkg/client/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/kyverno/policy-reporter/vap-plugin/pkg/audit"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/builder"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/policy"
)

// staticMapper is a test double for mapper.Mapper that always resolves to a
// fixed Kind, avoiding a dependency on cluster discovery in unit tests.
type staticMapper struct {
	kind schema.GroupVersionKind
}

func (m staticMapper) KindFor(schema.GroupVersionResource) (schema.GroupVersionKind, error) {
	return m.kind, nil
}

// staticResourceGetter is a test double for resourceGetter, tracking call
// count so tests can assert the live lookup is skipped when the audit
// event already carried a UID.
type staticResourceGetter struct {
	uid   types.UID
	err   error
	calls int
}

func (s *staticResourceGetter) GetUID(context.Context, schema.GroupVersionResource, string, string) (types.UID, error) {
	s.calls++
	return s.uid, s.err
}

// staticPolicyMeta is a test double for policyMetadataLookup.
type staticPolicyMeta struct {
	severity   string
	severityOK bool
	category   string
	categoryOK bool
}

func (s staticPolicyMeta) MetadataFor(string) (policy.Metadata, bool) {
	return policy.Metadata{
		Severity: s.severity,
		Category: s.category,
	}, s.severityOK || s.categoryOK
}

func newTestClient() (*Client, *fake.Clientset) {
	// dynamicClient and severity are nil: no live UID lookup, no severity
	// override.
	clientset := fake.NewSimpleClientset()
	m := staticMapper{kind: schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}}
	c := New(clientset, m, nil, nil, nil, nil, builder.Options{})
	return c, clientset
}

func newTestClientWithResourceGetter(rg resourceGetter) (*Client, *fake.Clientset) {
	clientset := fake.NewSimpleClientset()
	m := staticMapper{kind: schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}}
	c := &Client{
		reports:     clientset,
		mapper:      m,
		resources:   rg,
		labels:      map[string]string{ManagedByLabel: ManagedByValue},
		builderOpts: builder.Options{},
	}
	return c, clientset
}

func newTestClientWithPolicyMeta(pm policyMetadataLookup, opts builder.Options) (*Client, *fake.Clientset) {
	clientset := fake.NewSimpleClientset()
	m := staticMapper{kind: schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}}
	c := &Client{
		reports:     clientset,
		mapper:      m,
		policyMeta:  pm,
		labels:      map[string]string{ManagedByLabel: ManagedByValue},
		builderOpts: opts,
	}
	return c, clientset
}

var errNotFound = errors.New("not found")

func testResource(uid string) audit.Resource {
	return audit.Resource{
		APIGroup: "apps", APIVersion: "v1", Resource: "deployments",
		Namespace: "default", Name: "web", UID: uid,
	}
}

// denyEvent builds an Event matching what audit.Parse produces for a
// Deny-action rejection: a single Result, with Action set on both the
// Result itself and (redundantly, for a single-action event like this one)
// the Event.
func denyEvent(uid string) audit.Event {
	return audit.Event{
		Resource: testResource(uid),
		HasAudit: false,
		Results: []audit.Result{{
			Policy:  "require-labels",
			Binding: "require-labels-binding",
			Message: "labels are required",
			Action:  audit.ActionDeny,
		}},
	}
}

// auditEvent builds an Event matching what audit.Parse produces for an
// Audit-action failure.
func auditEvent(uid string) audit.Event {
	ev := denyEvent(uid)
	ev.HasAudit = true
	ev.Results[0].Action = audit.ActionAudit
	return ev
}

func TestUpsert_EmptyBatchIsNoOp(t *testing.T) {
	c, clientset := newTestClient()
	ctx := context.Background()

	require.NoError(t, c.Upsert(ctx, audit.Event{}))

	list, err := clientset.OpenreportsV1alpha1().Reports("").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, list.Items, "expected no report to be created for an event with no results")
}

func TestUpsert_CreatesNamespacedReportWithOwnerReference(t *testing.T) {
	c, clientset := newTestClient()
	ctx := context.Background()

	require.NoError(t, c.Upsert(ctx, denyEvent("uid-1")))

	list, err := clientset.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, list.Items, 1)

	r := list.Items[0]
	require.NotNil(t, r.Scope)
	assert.Equal(t, "Deployment", r.Scope.Kind)
	assert.Equal(t, "web", r.Scope.Name)
	require.Len(t, r.OwnerReferences, 1)
	assert.EqualValues(t, "uid-1", r.OwnerReferences[0].UID)
	assert.Equal(t, 1, r.Summary.Fail)
	assert.Equal(t, ManagedByValue, r.Labels[ManagedByLabel])
	assert.NotEmpty(t, r.Annotations[LastObservedAnnotation])
}

func TestUpsert_DeniedCreateHasNoOwnerReference(t *testing.T) {
	c, clientset := newTestClient()
	ctx := context.Background()

	require.NoError(t, c.Upsert(ctx, denyEvent("")))

	list, err := clientset.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	assert.Empty(t, list.Items[0].OwnerReferences, "expected no owner reference for a denied create")
}

func TestUpsert_BackfillsUIDFromLiveResourceOnCreate(t *testing.T) {
	// Audit action only: the request was allowed through, so the resource
	// is expected to actually exist.
	rg := &staticResourceGetter{uid: "live-uid-1"}
	c, clientset := newTestClientWithResourceGetter(rg)
	ctx := context.Background()

	require.NoError(t, c.Upsert(ctx, auditEvent("")))
	require.Equal(t, 1, rg.calls, "expected exactly 1 live lookup")

	list, err := clientset.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, list.Items, 1)

	owners := list.Items[0].OwnerReferences
	require.Len(t, owners, 1)
	assert.EqualValues(t, "live-uid-1", owners[0].UID)
}

func TestUpsert_NoBackfillWhenLiveLookupFails(t *testing.T) {
	// Audit action, but the live GET fails anyway (e.g. missing RBAC for
	// this resource type, or a race where the resource was deleted again
	// before the lookup ran) - the report is left without an owner
	// reference exactly as it would be with no live lookup at all.
	rg := &staticResourceGetter{err: errNotFound}
	c, clientset := newTestClientWithResourceGetter(rg)
	ctx := context.Background()

	require.NoError(t, c.Upsert(ctx, auditEvent("")))
	require.Equal(t, 1, rg.calls, "expected the lookup to still be attempted for Audit action")

	list, err := clientset.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, list.Items[0].OwnerReferences, "expected no owner reference when the live lookup fails")
}

func TestUpsert_DenyActionNeverAttemptsLiveLookup(t *testing.T) {
	// A Deny-action event means the request was rejected: for a Create,
	// the resource never existed in the first place, so the live lookup
	// isn't even attempted - not attempted-and-failed, never called at
	// all, even when (as here) it's configured to return a real UID.
	rg := &staticResourceGetter{uid: "should-never-be-used"}
	c, clientset := newTestClientWithResourceGetter(rg)
	ctx := context.Background()

	require.NoError(t, c.Upsert(ctx, denyEvent("")))
	assert.Equal(t, 0, rg.calls, "expected the live lookup to never be attempted for Deny action")

	list, err := clientset.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, list.Items[0].OwnerReferences, "expected no owner reference for a Deny event")
}

func TestUpsert_SkipsLiveLookupWhenAuditEventAlreadyHasUID(t *testing.T) {
	rg := &staticResourceGetter{uid: "should-not-be-used"}
	c, clientset := newTestClientWithResourceGetter(rg)
	ctx := context.Background()

	require.NoError(t, c.Upsert(ctx, auditEvent("uid-from-audit-event")))
	assert.Equal(t, 0, rg.calls, "expected the live lookup to be skipped when the audit event already has a UID")

	list, err := clientset.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	owners := list.Items[0].OwnerReferences
	require.Len(t, owners, 1)
	assert.EqualValues(t, "uid-from-audit-event", owners[0].UID)
}

func TestUpsert_RepeatedIdenticalEventIsIdempotent(t *testing.T) {
	c, clientset := newTestClient()
	ctx := context.Background()

	require.NoError(t, c.Upsert(ctx, denyEvent("uid-1")))
	require.NoError(t, c.Upsert(ctx, denyEvent("uid-1")))

	list, err := clientset.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, list.Items, 1)

	r := list.Items[0]
	assert.Len(t, r.Results, 1)
	assert.Equal(t, 1, r.Summary.Fail)
}

func TestUpsert_SingleEventWithMultipleResultsPersistsAllOfThem(t *testing.T) {
	// Matches what audit.Parse actually produces for multiple failing
	// Audit-action bindings on one request (see
	// audit.TestParse_AuditActionMultipleFailures) - unlike Deny, which
	// Parse only ever yields at most one Result for.
	c, clientset := newTestClient()
	ctx := context.Background()

	ev := auditEvent("uid-1")
	ev.Results = []audit.Result{
		{Policy: "require-labels", Binding: "require-labels-binding", Message: "m1", Action: audit.ActionAudit},
		{Policy: "min-replicas", Binding: "min-replicas-binding", Message: "m2", Action: audit.ActionAudit},
	}

	require.NoError(t, c.Upsert(ctx, ev))

	list, err := clientset.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	r := list.Items[0]
	assert.Len(t, r.Results, 2, "expected 2 results from one event")
	assert.Equal(t, 2, r.Summary.Fail)
}

func TestUpsert_SecondEventReplacesTheFirstEntirely(t *testing.T) {
	// The core batch-replace behavior: a later audit event for the same
	// resource is a fresh, complete evaluation - a policy result from an
	// earlier event that isn't part of this one (e.g. its binding no longer
	// matches) must be dropped, not carried forward as stale history.
	c, clientset := newTestClient()
	ctx := context.Background()

	first := denyEvent("uid-1")
	second := denyEvent("uid-1")
	second.Results = []audit.Result{{Policy: "min-replicas", Binding: "min-replicas-binding", Message: "too few replicas", Action: audit.ActionDeny}}

	require.NoError(t, c.Upsert(ctx, first))
	require.NoError(t, c.Upsert(ctx, second))

	list, err := clientset.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	r := list.Items[0]
	require.Len(t, r.Results, 1, "expected 1 result (the second event replaces the first)")
	assert.Equal(t, "min-replicas", r.Results[0].Policy, "expected only the second event's policy to remain")
	assert.Equal(t, 1, r.Summary.Fail)
}

func TestUpsert_SeverityAnnotationOverridesDefault(t *testing.T) {
	opts := builder.Options{Severity: "medium"}
	c, clientset := newTestClientWithPolicyMeta(staticPolicyMeta{severity: "critical", severityOK: true}, opts)
	ctx := context.Background()

	require.NoError(t, c.Upsert(ctx, denyEvent("uid-1")))

	list, err := clientset.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	assert.EqualValues(t, "critical", list.Items[0].Results[0].Severity)
}

func TestUpsert_FallsBackToDefaultSeverityWhenLookupHasNone(t *testing.T) {
	opts := builder.Options{Severity: "medium"}
	c, clientset := newTestClientWithPolicyMeta(staticPolicyMeta{severityOK: false}, opts)
	ctx := context.Background()

	require.NoError(t, c.Upsert(ctx, denyEvent("uid-1")))

	list, err := clientset.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	assert.EqualValues(t, "medium", list.Items[0].Results[0].Severity)
}

func TestUpsert_CategoryAnnotationOverridesDefault(t *testing.T) {
	opts := builder.Options{Category: "default-category"}
	c, clientset := newTestClientWithPolicyMeta(staticPolicyMeta{category: "best-practices", categoryOK: true}, opts)
	ctx := context.Background()

	require.NoError(t, c.Upsert(ctx, denyEvent("uid-1")))

	list, err := clientset.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, "best-practices", list.Items[0].Results[0].Category)
}

func TestUpsert_FallsBackToDefaultCategoryWhenLookupHasNone(t *testing.T) {
	opts := builder.Options{Category: "default-category"}
	c, clientset := newTestClientWithPolicyMeta(staticPolicyMeta{categoryOK: false}, opts)
	ctx := context.Background()

	require.NoError(t, c.Upsert(ctx, denyEvent("uid-1")))

	list, err := clientset.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, "default-category", list.Items[0].Results[0].Category)
}

func TestUpsert_SeverityAndCategoryOverriddenTogether(t *testing.T) {
	c, clientset := newTestClientWithPolicyMeta(staticPolicyMeta{
		severity: "critical", severityOK: true,
		category: "best-practices", categoryOK: true,
	}, builder.Options{})
	ctx := context.Background()

	require.NoError(t, c.Upsert(ctx, denyEvent("uid-1")))

	list, err := clientset.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	result := list.Items[0].Results[0]
	assert.EqualValues(t, "critical", result.Severity)
	assert.Equal(t, "best-practices", result.Category)
}

func TestUpsert_NoPolicyMetaLookupConfiguredUsesDefaults(t *testing.T) {
	// newTestClient's Client has a nil policy metadata lookup entirely
	// (disabled).
	c, clientset := newTestClient()
	ctx := context.Background()

	require.NoError(t, c.Upsert(ctx, denyEvent("uid-1")))

	list, err := clientset.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	result := list.Items[0].Results[0]
	assert.Empty(t, result.Severity)
	assert.Empty(t, result.Category)
}

func TestUpsert_ClusterScopedResourceUsesClusterReport(t *testing.T) {
	c, clientset := newTestClient()
	ctx := context.Background()

	ev := denyEvent("uid-1")
	ev.Resource.Namespace = ""

	require.NoError(t, c.Upsert(ctx, ev))

	list, err := clientset.OpenreportsV1alpha1().ClusterReports().List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, list.Items, 1)
}
