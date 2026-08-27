// Package policy resolves per-policy metadata from ValidatingAdmissionPolicy
// objects themselves - data the audit log doesn't carry, since it's not
// part of any admission event, only of the policy resource's own metadata.
package policy

import (
	"context"
	"fmt"
	"time"

	admissionregistrationv1listers "k8s.io/client-go/listers/admissionregistration/v1"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// SeverityAnnotation, set on a ValidatingAdmissionPolicy, overrides the
// severity of every ReportResult built from that policy's failures -
// instead of the app-wide default (config Report.Severity).
const SeverityAnnotation = "vap.kubernetes.io/severity"

// CategoryAnnotation, set on a ValidatingAdmissionPolicy, overrides the
// category of every ReportResult built from that policy's failures -
// instead of the app-wide default (config Report.Category).
const CategoryAnnotation = "vap.kubernetes.io/category"

// validSeverities mirrors openreports.io/v1alpha1.ResultSeverity's enum
// (+kubebuilder:validation:Enum=critical;high;low;medium;info). Enforced
// here rather than left to the API server: an invalid value would
// otherwise fail the whole Report update, not just this one field.
// Category has no such enum - any non-empty value is accepted as-is.
var validSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
	"info":     true,
}

type Metadata struct {
	Category string
	Severity string
}

// MetadataLookup resolves a ValidatingAdmissionPolicy's own annotations
// (SeverityAnnotation, CategoryAnnotation), backed by a single local
// informer cache shared across both, so a lookup doesn't cost an API call
// per audit event - VAP evaluations can happen far more often than
// policies themselves change.
type MetadataLookup struct {
	lister admissionregistrationv1listers.ValidatingAdmissionPolicyLister
}

// NewMetadataLookup builds a MetadataLookup, blocking until its informer's
// initial cache sync completes or syncTimeout elapses, whichever comes
// first. ctx governs the informer's entire background watch, which keeps
// running for as long as ctx lives - it must be a long-lived (e.g.
// application-lifetime) context, NOT one that's cancelled once this
// function returns: doing that once cancelled the informer's watch itself
// moments after startup, since a stop channel doesn't distinguish "done
// syncing" from "done for good" - it only ever saw the empty initial list,
// missing every ValidatingAdmissionPolicy created afterwards.
func NewMetadataLookup(ctx context.Context, client kubernetes.Interface, syncTimeout time.Duration) (*MetadataLookup, error) {
	factory := informers.NewSharedInformerFactory(client, 10*time.Minute)
	informer := factory.Admissionregistration().V1().ValidatingAdmissionPolicies()

	// informer.Informer() must be called (registering it with the factory)
	// before factory.Start, or Start has nothing to start: registration
	// happens lazily on first access, not when .ValidatingAdmissionPolicies()
	// is called.
	sharedInformer := informer.Informer()
	factory.Start(ctx.Done())

	syncCtx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	if !cache.WaitForCacheSync(syncCtx.Done(), sharedInformer.HasSynced) {
		return nil, fmt.Errorf("syncing ValidatingAdmissionPolicy informer cache: %w", syncCtx.Err())
	}

	return &MetadataLookup{lister: informer.Lister()}, nil
}

// MetadataFor returns the named policy's Metadata (severity and category), and
// whether it was present and valid. A missing policy (not yet synced,
// deleted, or never existed), a missing annotation, or a value outside the
// enum openreports.io/v1alpha1.ResultSeverity accepts all return ok=false -
// callers should fall back to their own default metadata in that case.
func (m *MetadataLookup) MetadataFor(policyName string) (Metadata, bool) {
	policy, err := m.lister.Get(policyName)
	if err != nil {
		return Metadata{}, false
	}

	return Metadata{
		Severity: policy.Annotations[SeverityAnnotation],
		Category: policy.Annotations[CategoryAnnotation],
	}, true
}
