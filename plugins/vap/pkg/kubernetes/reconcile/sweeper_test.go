package reconcile

import (
	"context"
	"testing"
	"time"

	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	"github.com/openreports/reports-api/pkg/client/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/report"
)

func managedReport(name string, age time.Duration, owned bool) *openreportsv1alpha1.Report {
	r := &openreportsv1alpha1.Report{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "default",
			Labels:            map[string]string{report.ManagedByLabel: report.ManagedByValue},
			Annotations:       map[string]string{},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
	}
	if owned {
		r.OwnerReferences = []metav1.OwnerReference{{Name: "web", UID: "uid-1"}}
	}
	return r
}

func TestSweeper_DeletesExpiredOrphan(t *testing.T) {
	old := managedReport("orphan-old", 48*time.Hour, false)
	client := fake.NewSimpleClientset(old)
	sweeper := NewSweeper(client, nil, nil, 24*time.Hour, zap.NewNop())

	sweeper.sweepOnce(context.Background())

	list, err := client.OpenreportsV1alpha1().Reports("default").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, list.Items, "expected expired orphan report to be deleted")
}

func TestSweeper_KeepsFreshOrphan(t *testing.T) {
	fresh := managedReport("orphan-fresh", 1*time.Hour, false)
	client := fake.NewSimpleClientset(fresh)
	sweeper := NewSweeper(client, nil, nil, 24*time.Hour, zap.NewNop())

	sweeper.sweepOnce(context.Background())

	list, err := client.OpenreportsV1alpha1().Reports("default").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, list.Items, 1, "expected fresh orphan report to survive")
}

func TestSweeper_KeepsOwnedReportRegardlessOfAge(t *testing.T) {
	owned := managedReport("owned-old", 48*time.Hour, true)
	client := fake.NewSimpleClientset(owned)
	sweeper := NewSweeper(client, nil, nil, 24*time.Hour, zap.NewNop())

	sweeper.sweepOnce(context.Background())

	list, err := client.OpenreportsV1alpha1().Reports("default").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, list.Items, 1, "expected owned report to survive regardless of age")
}

func TestSweeper_LastObservedAnnotationTakesPriorityOverCreationTimestamp(t *testing.T) {
	// Created long ago, but recently touched by an audit event: the
	// LastObservedAnnotation should win over CreationTimestamp and keep it
	// alive. This is the common case in practice, since UID (needed for an
	// OwnerReference) is almost never present on audit ObjectRefs.
	r := managedReport("recently-observed", 48*time.Hour, false)
	r.Annotations[report.LastObservedAnnotation] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)

	client := fake.NewSimpleClientset(r)
	sweeper := NewSweeper(client, nil, nil, 24*time.Hour, zap.NewNop())

	sweeper.sweepOnce(context.Background())

	list, err := client.OpenreportsV1alpha1().Reports("default").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, list.Items, 1, "expected recently-observed report to survive despite old creation timestamp")
}

func TestSweeper_DeletesWhenLastObservedExpiredEvenIfRecentlyCreated(t *testing.T) {
	r := managedReport("stale-despite-recent-creation", time.Minute, false)
	r.Annotations[report.LastObservedAnnotation] = time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)

	client := fake.NewSimpleClientset(r)
	sweeper := NewSweeper(client, nil, nil, 24*time.Hour, zap.NewNop())

	sweeper.sweepOnce(context.Background())

	list, err := client.OpenreportsV1alpha1().Reports("default").List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, list.Items, "expected stale report to be deleted despite recent creation timestamp")
}

func TestSweeper_ReconcilesDriftedLabels(t *testing.T) {
	owned := managedReport("owned", time.Minute, true)
	client := fake.NewSimpleClientset(owned)
	sweeper := NewSweeper(client, map[string]string{"team": "platform"}, nil, 24*time.Hour, zap.NewNop())

	sweeper.sweepOnce(context.Background())

	updated, err := client.OpenreportsV1alpha1().Reports("default").Get(context.Background(), "owned", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "platform", updated.Labels["team"])
}
