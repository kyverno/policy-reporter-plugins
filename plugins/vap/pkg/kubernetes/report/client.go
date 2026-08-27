// Package report persists parsed VAP audit results as openreports.io
// Report/ClusterReport custom resources: one per audited resource, whose
// Results are replaced wholesale by the batch from each audit event rather
// than accumulated as history - see Client.Upsert.
package report

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/kyverno/policy-reporter/vap-plugin/pkg/audit"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/builder"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/mapper"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/policy"
	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	versioned "github.com/openreports/reports-api/pkg/client/clientset/versioned"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

// ManagedByLabel marks every Report/ClusterReport this app writes, so they
// can be listed/reconciled/cleaned up without touching reports other
// engines own.
const ManagedByLabel = "app.kubernetes.io/managed-by"

// ManagedByValue is the value paired with ManagedByLabel.
const ManagedByValue = "vap-plugin"

// LastObservedAnnotation records when a Report/ClusterReport was last
// touched by an audit event (RFC3339). This is the primary staleness signal
// the reconcile package's TTL sweep uses to clean up reports whose target
// resource is gone: verified against a real cluster (k8s v1.36.1) that
// audit ObjectRef almost never carries a UID for ordinary create/update/
// delete requests on the primary resource (only subresource requests like
// status/binding do), so an OwnerReference-based owner check - the more
// obvious mechanism - only rarely applies. See setOwnerReference, which is
// still set best-effort for the cases a UID is available.
const LastObservedAnnotation = "vap-plugin.io/last-observed"

// resourceGetter fetches a resource's current UID directly from the
// cluster. Audit events almost never carry one (see LastObservedAnnotation),
// so this is how a newly created Report still gets a real OwnerReference
// for the common case where the resource actually exists.
type resourceGetter interface {
	GetUID(ctx context.Context, gvr schema.GroupVersionResource, namespace, name string) (types.UID, error)
}

// dynamicResourceGetter implements resourceGetter via the dynamic client,
// since the audited resource's concrete Go type isn't known at compile
// time - it's whatever a ValidatingAdmissionPolicy happens to match.
type dynamicResourceGetter struct {
	client dynamic.Interface
}

func (d dynamicResourceGetter) GetUID(ctx context.Context, gvr schema.GroupVersionResource, namespace, name string) (types.UID, error) {
	var (
		obj *unstructured.Unstructured
		err error
	)
	if namespace == "" {
		obj, err = d.client.Resource(gvr).Get(ctx, name, metav1.GetOptions{})
	} else {
		obj, err = d.client.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	}
	if err != nil {
		return "", err
	}

	return obj.GetUID(), nil
}

// policyMetadataLookup resolves a ValidatingAdmissionPolicy's own
// annotation overrides (severity, category), if any. Implemented by
// *policy.MetadataLookup; kept as a small interface here so it's fakeable
// in tests, and so c.policyMeta can be left a true nil interface to disable
// both overrides entirely.
type policyMetadataLookup interface {
	MetadataFor(policyName string) (policy.Metadata, bool)
}

// Client upserts openreports.io Report/ClusterReport objects from parsed
// VAP audit results.
type Client struct {
	reports     versioned.Interface
	mapper      mapper.Mapper
	resources   resourceGetter
	policyMeta  policyMetadataLookup
	labels      map[string]string
	annotations map[string]string
	builderOpts builder.Options
}

// New builds a report Client. labels/annotations are applied to every
// Report/ClusterReport this app creates or updates, in addition to
// ManagedByLabel which is always set. dynamicClient is used to backfill a
// resource's UID (for OwnerReference) when a new Report is created for it;
// pass nil to disable that lookup entirely. policyMeta, if non-nil,
// overrides each ReportResult's severity/category with its policy's
// policy.SeverityAnnotation/policy.CategoryAnnotation, falling back to
// opts.Severity/opts.Category when a policy has neither (or an invalid
// severity value); pass nil to disable both overrides entirely.
func New(reports versioned.Interface, m mapper.Mapper, dynamicClient dynamic.Interface, policyMeta *policy.MetadataLookup, labels, annotations map[string]string, opts builder.Options) *Client {
	merged := map[string]string{ManagedByLabel: ManagedByValue}
	for k, v := range labels {
		merged[k] = v
	}

	c := &Client{
		reports:     reports,
		mapper:      m,
		labels:      merged,
		annotations: annotations,
		builderOpts: opts,
	}
	// Both left as true nil interfaces (rather than wrapping a nil pointer
	// in a non-nil struct/interface value) when their concrete argument is
	// nil - that's what lets a plain `== nil` check at the call site work.
	if dynamicClient != nil {
		c.resources = dynamicResourceGetter{client: dynamicClient}
	}
	if policyMeta != nil {
		c.policyMeta = policyMeta
	}

	return c
}

// Upsert persists a batch of VAP results - all of them, since they come
// from a single audit event, which targets exactly one resource - into the
// Report (namespaced resources) or ClusterReport (cluster-scoped
// resources) that scopes their shared target resource.
//
// The batch entirely replaces whatever Results the Report previously held,
// rather than merging into them: each audit event is a fresh, complete
// evaluation of the resource's current state, so a policy result left over
// from an earlier event but absent from this batch (its binding no longer
// matches, or it simply wasn't re-evaluated this time) is dropped, not
// carried forward as stale history. A single Get/Update round trip persists
// the whole batch, rather than one per result.
func (c *Client) Upsert(ctx context.Context, event audit.Event) error {
	results := event.Results
	if len(results) == 0 {
		return nil
	}

	res := event.Resource
	gvr := schema.GroupVersionResource{
		Group:    res.APIGroup,
		Version:  res.APIVersion,
		Resource: res.Resource,
	}

	gvk, err := c.mapper.KindFor(gvr)
	if err != nil {
		return fmt.Errorf("resolving kind for %s: %w", gvr.String(), err)
	}

	reportResults := make([]openreportsv1alpha1.ReportResult, 0, len(results))
	for _, r := range results {
		result := builder.Build(event, r, c.builderOpts)
		if c.policyMeta != nil {
			if meta, ok := c.policyMeta.MetadataFor(r.Policy); ok {
				if meta.Severity != "" {
					result.Severity = openreportsv1alpha1.ResultSeverity(meta.Severity)
				}
				if meta.Category != "" {
					result.Category = meta.Category
				}
			}
		}
		reportResults = append(reportResults, result)
	}

	if res.Namespace == "" {
		return c.upsertClusterReport(ctx, gvr, gvk, event.HasAudit, res, reportResults)
	}

	return c.upsertReport(ctx, gvr, gvk, event.HasAudit, res, reportResults)
}

func (c *Client) upsertReport(ctx context.Context, gvr schema.GroupVersionResource, gvk schema.GroupVersionKind, hasAudit bool, res audit.Resource, results []openreportsv1alpha1.ReportResult) error {
	client := c.reports.OpenreportsV1alpha1().Reports(res.Namespace)
	name := reportName(gvk, res.Namespace, res.Name)

	existing, err := client.Get(ctx, name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		if hasAudit {
			res = c.withLiveUID(ctx, gvr, res)
		}

		created := &openreportsv1alpha1.Report{
			Name:        name,
			Namespace:   res.Namespace,
			Labels:      c.labels,
			Annotations: c.annotations,
			Source:      builder.Source,
			Scope:       scopeFor(gvk, res),
		}
		existing, err = client.Create(ctx, created, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating report %s/%s: %w", res.Namespace, name, err)
		}
	} else if err != nil {
		return fmt.Errorf("getting report %s/%s: %w", res.Namespace, name, err)
	}

	setOwnerReference(&existing.ObjectMeta, gvk, res)
	stampObserved(&existing.ObjectMeta)
	existing.Results = results
	existing.Summary = summarize(results)

	if _, err := client.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("updating report %s/%s: %w", res.Namespace, name, err)
	}

	zap.L().Debug("report created", zap.String("namespace", res.Namespace), zap.String("name", name), zap.Int("count", len(results)))

	return nil
}

func (c *Client) upsertClusterReport(ctx context.Context, gvr schema.GroupVersionResource, gvk schema.GroupVersionKind, hasAudit bool, res audit.Resource, results []openreportsv1alpha1.ReportResult) error {
	client := c.reports.OpenreportsV1alpha1().ClusterReports()
	name := reportName(gvk, "", res.Name)

	existing, err := client.Get(ctx, name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		if hasAudit {
			res = c.withLiveUID(ctx, gvr, res)
		}

		created := &openreportsv1alpha1.ClusterReport{
			Name:        name,
			Labels:      c.labels,
			Annotations: c.annotations,
			Source:      builder.Source,
			Scope:       scopeFor(gvk, res),
		}
		existing, err = client.Create(ctx, created, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating cluster report %s: %w", name, err)
		}
	} else if err != nil {
		return fmt.Errorf("getting cluster report %s: %w", name, err)
	}

	setOwnerReference(&existing.ObjectMeta, gvk, res)
	stampObserved(&existing.ObjectMeta)
	existing.Results = results
	existing.Summary = summarize(results)

	if _, err := client.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("updating cluster report %s: %w", name, err)
	}

	zap.L().Debug("cluster report created", zap.String("name", name), zap.Int("count", len(results)))

	return nil
}

// reportName is a deterministic identifier for the resource's report,
// derived from its identity (kind/namespace/name) rather than its UID:
// a denied Create never gets a UID (the object never exists), so identity
// is the only stable key available across the create-denied and
// already-exists cases alike.
func reportName(gvk schema.GroupVersionKind, namespace, name string) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s/%s/%s/%s", gvk.GroupVersion().String(), gvk.Kind, namespace, name)
	return "vap-report-" + hex.EncodeToString(h.Sum(nil))[:16]
}

func scopeFor(gvk schema.GroupVersionKind, res audit.Resource) *corev1.ObjectReference {
	ref := &corev1.ObjectReference{
		APIVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Namespace:  res.Namespace,
		Name:       res.Name,
	}
	if res.UID != "" {
		ref.UID = types.UID(res.UID)
	}

	return ref
}

// withLiveUID backfills res.UID from a live GET of the resource, when the
// audit event didn't carry one (the common case - see LastObservedAnnotation)
// and a Report is being created for it for the first time. Callers should
// only reach this when the batch had no Deny result: a Deny-action result
// means the request was rejected, so for a Create the resource never
// existed in the first place, and even for an Update/Delete it's not worth
// a live GET on the strength of "might happen to still exist" -
// Audit-only batches, by contrast, always come from a request that was
// actually allowed through, so the resource is expected to exist. A failed
// lookup (missing RBAC for this resource type, or a race with the resource
// being deleted again) is expected, not fatal: res is returned unchanged,
// leaving the report without an OwnerReference exactly as before, still
// cleaned up by the reconcile package's TTL sweep.
func (c *Client) withLiveUID(ctx context.Context, gvr schema.GroupVersionResource, res audit.Resource) audit.Resource {
	if res.UID != "" || c.resources == nil {
		return res
	}

	uid, err := c.resources.GetUID(ctx, gvr, res.Namespace, res.Name)
	if err != nil {
		return res
	}

	res.UID = string(uid)
	return res
}

// setOwnerReference makes Kubernetes garbage-collect the report when its
// scoped resource is deleted. Only possible when the resource actually
// exists (has a UID) - a Deny-blocked Create has no object to own, and is
// left without an owner reference; see the reconcile package for the TTL
// sweep that cleans those up instead.
func setOwnerReference(meta *metav1.ObjectMeta, gvk schema.GroupVersionKind, res audit.Resource) {
	if res.UID == "" {
		return
	}

	meta.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Name:       res.Name,
		UID:        types.UID(res.UID),
	}}
}

// stampObserved records the current time under LastObservedAnnotation,
// which is what the reconcile package's TTL sweep uses to decide whether a
// report's target resource is likely gone (see LastObservedAnnotation).
func stampObserved(meta *metav1.ObjectMeta) {
	if meta.Annotations == nil {
		meta.Annotations = map[string]string{}
	}
	meta.Annotations[LastObservedAnnotation] = time.Now().UTC().Format(time.RFC3339)
}

// summarize recomputes a ReportSummary from scratch for a full Results
// list, matching the batch-replace semantics of Upsert: counts always
// reflect exactly the current batch, never a running total adjusted
// incrementally against whatever was there before.
func summarize(results []openreportsv1alpha1.ReportResult) openreportsv1alpha1.ReportSummary {
	var s openreportsv1alpha1.ReportSummary
	for _, r := range results {
		switch r.Result {
		case "pass":
			s.Pass++
		case "fail":
			s.Fail++
		case "warn":
			s.Warn++
		case "error":
			s.Error++
		case "skip":
			s.Skip++
		}
	}
	return s
}
