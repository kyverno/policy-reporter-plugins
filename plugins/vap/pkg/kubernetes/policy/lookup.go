// Package policy resolves per-policy metadata from ValidatingAdmissionPolicy
// objects themselves - data the audit log doesn't carry, since it's not
// part of any admission event, only of the policy resource's own metadata.
package policy

import (
	admissionregistrationv1listers "k8s.io/client-go/listers/admissionregistration/v1"
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

// NewMetadataLookup builds a MetadataLookup backed by lister. lister must
// already be backed by a running, synced informer - starting the informer
// and waiting for its initial cache sync is the caller's responsibility
// (see config.Resolver.VAPLister), since that informer is shared with other
// consumers (e.g. the plugin API's policy.Client) and so can't be owned by
// any one of them. In particular, whoever starts it must do so with a
// long-lived (e.g. application-lifetime) context, NOT one that's cancelled
// once the initial sync completes: doing that kills the informer's watch
// itself moments after startup, since a stop channel doesn't distinguish
// "done syncing" from "done for good" - it would only ever see the empty
// initial list, missing every ValidatingAdmissionPolicy created afterwards.
func NewMetadataLookup(lister admissionregistrationv1listers.ValidatingAdmissionPolicyLister) *MetadataLookup {
	return &MetadataLookup{lister: lister}
}

// Lister returns the shared informer-backed lister backing this
// MetadataLookup, so other consumers (e.g. the plugin API's policy.Client)
// can reuse the same local cache instead of hitting the KubeAPI directly or
// maintaining a second cache of their own.
func (m *MetadataLookup) Lister() admissionregistrationv1listers.ValidatingAdmissionPolicyLister {
	return m.lister
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
