// Package reconcile runs the periodic, leader-elected maintenance sweep
// over managed Reports/ClusterReports. Real audit events almost never carry
// their target resource's UID (verified against a live cluster - see
// report.LastObservedAnnotation), so a managed report usually has no
// OwnerReference for Kubernetes to garbage-collect it by once its resource
// is deleted. This sweep is the primary cleanup mechanism instead: it
// deletes any ownerless managed report that hasn't been touched by a new
// audit event within a configured TTL, and reconciles managed-by
// labels/annotations after a config change.
package reconcile

import (
	"context"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	versioned "github.com/openreports/reports-api/pkg/client/clientset/versioned"

	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/report"
)

// Sweeper performs the periodic maintenance pass.
type Sweeper struct {
	client      versioned.Interface
	labels      map[string]string
	annotations map[string]string
	ttl         time.Duration
	log         *zap.Logger
}

// NewSweeper builds a Sweeper. labels/annotations should match what
// report.Client is configured with, so drift after a config change gets
// reconciled onto existing objects.
func NewSweeper(client versioned.Interface, labels, annotations map[string]string, ttl time.Duration, log *zap.Logger) *Sweeper {
	merged := map[string]string{report.ManagedByLabel: report.ManagedByValue}
	for k, v := range labels {
		merged[k] = v
	}

	return &Sweeper{client: client, labels: merged, annotations: annotations, ttl: ttl, log: log}
}

// Run sweeps immediately, then on every tick of interval, until ctx is
// cancelled. Intended to run only while this process holds the leader
// election lease.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration) {
	s.sweepOnce(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepOnce(ctx)
		}
	}
}

func (s *Sweeper) sweepOnce(ctx context.Context) {
	s.reconcileReports(ctx)
	s.reconcileClusterReports(ctx)
}

func isManaged(labels map[string]string) bool {
	return labels[report.ManagedByLabel] == report.ManagedByValue
}

func (s *Sweeper) reconcileReports(ctx context.Context) {
	// Filtered in-process rather than via a server-side LabelSelector: this
	// keeps behavior identical against both the real API server and the
	// fake clientset used in tests, and the managed set is small enough
	// that listing everything once per sweep interval is cheap.
	list, err := s.client.OpenreportsV1alpha1().Reports("").List(ctx, metav1.ListOptions{})
	if err != nil {
		s.log.Error("failed to list reports for reconciliation", zap.Error(err))
		return
	}

	for i := range list.Items {
		r := &list.Items[i]
		if !isManaged(r.Labels) {
			continue
		}

		// The client used for List above is bound to namespace "" (all
		// namespaces); Update/Delete need a client bound to this report's
		// actual namespace.
		client := s.client.OpenreportsV1alpha1().Reports(r.Namespace)

		if s.isStale(r.ObjectMeta) {
			if err := client.Delete(ctx, r.Name, metav1.DeleteOptions{}); err != nil {
				s.log.Error("failed to delete orphaned report", zap.String("namespace", r.Namespace), zap.String("name", r.Name), zap.Error(err))
			}
			continue
		}

		if reconcileLabelsAnnotations(&r.ObjectMeta, s.labels, s.annotations) {
			if _, err := client.Update(ctx, r, metav1.UpdateOptions{}); err != nil {
				s.log.Error("failed to reconcile report labels", zap.String("namespace", r.Namespace), zap.String("name", r.Name), zap.Error(err))
			}
		}
	}
}

func (s *Sweeper) reconcileClusterReports(ctx context.Context) {
	client := s.client.OpenreportsV1alpha1().ClusterReports()

	list, err := client.List(ctx, metav1.ListOptions{})
	if err != nil {
		s.log.Error("failed to list cluster reports for reconciliation", zap.Error(err))
		return
	}

	for i := range list.Items {
		r := &list.Items[i]
		if !isManaged(r.Labels) {
			continue
		}

		if s.isStale(r.ObjectMeta) {
			if err := client.Delete(ctx, r.Name, metav1.DeleteOptions{}); err != nil {
				s.log.Error("failed to delete orphaned cluster report", zap.String("name", r.Name), zap.Error(err))
			}
			continue
		}

		if reconcileLabelsAnnotations(&r.ObjectMeta, s.labels, s.annotations) {
			if _, err := client.Update(ctx, r, metav1.UpdateOptions{}); err != nil {
				s.log.Error("failed to reconcile cluster report labels", zap.String("name", r.Name), zap.Error(err))
			}
		}
	}
}

// isStale reports whether a managed Report/ClusterReport's target resource
// has likely been deleted, so it should be swept.
//
// A real OwnerReference (rare - see report.LastObservedAnnotation for why)
// means Kubernetes garbage-collects this report directly once its owner is
// gone, so TTL deletion is skipped for it. Otherwise, staleness is judged
// by how long it's been since the last audit event touched this report
// (report.LastObservedAnnotation, stamped on every upsert), falling back to
// CreationTimestamp for a report from before that annotation existed.
func (s *Sweeper) isStale(meta metav1.ObjectMeta) bool {
	if len(meta.OwnerReferences) > 0 {
		return false
	}

	last := meta.CreationTimestamp.Time
	if raw, ok := meta.Annotations[report.LastObservedAnnotation]; ok {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			last = parsed
		}
	}

	return time.Since(last) > s.ttl
}

func reconcileLabelsAnnotations(meta *metav1.ObjectMeta, labels, annotations map[string]string) bool {
	changed := false

	if meta.Labels == nil && len(labels) > 0 {
		meta.Labels = map[string]string{}
	}
	for k, v := range labels {
		if meta.Labels[k] != v {
			meta.Labels[k] = v
			changed = true
		}
	}

	if meta.Annotations == nil && len(annotations) > 0 {
		meta.Annotations = map[string]string{}
	}
	for k, v := range annotations {
		if meta.Annotations[k] != v {
			meta.Annotations[k] = v
			changed = true
		}
	}

	return changed
}
