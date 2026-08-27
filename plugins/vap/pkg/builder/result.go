// Package builder converts parsed VAP audit results into
// openreports.io/v1alpha1 ReportResult entries.
package builder

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"

	"github.com/kyverno/policy-reporter/vap-plugin/pkg/audit"
	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Source identifies this application as the producer of the ReportResult,
// stored in ReportResult.Source.
const Source = "ValidatingAdmissionPolicy"

// DefaultSeverity is used when no override is configured, since
// ValidatingAdmissionPolicy has no built-in severity concept.
const DefaultSeverity = openreportsv1alpha1.ResultSeverity("medium")

// Options controls how a Result is translated into a ReportResult.
type Options struct {
	// Severity is applied to every built ReportResult. Optional.
	Severity openreportsv1alpha1.ResultSeverity
	// Category is applied to every built ReportResult. Optional.
	Category string
}

// Build converts a single audit.Result into a ReportResult. The returned
// value's Properties["resultID"] is a stable identity for the
// (resource, policy, binding) triple, used by the report-persistence layer
// to upsert in place rather than accumulate duplicate entries.
func Build(ev audit.Event, r audit.Result, opts Options) openreportsv1alpha1.ReportResult {
	properties := map[string]string{
		"resultID": ResultID(ev, r),
		"action":   string(r.Action),
	}
	if r.ExpressionIndex != nil {
		properties["expressionIndex"] = fmt.Sprintf("%d", *r.ExpressionIndex)
	}

	return openreportsv1alpha1.ReportResult{
		Source:      Source,
		Policy:      r.Policy,
		Rule:        r.Binding,
		Category:    opts.Category,
		Severity:    opts.Severity,
		Timestamp:   metav1.Timestamp{Seconds: ev.Time.Unix()},
		Result:      openreportsv1alpha1.Result("fail"),
		Scored:      r.Action == audit.ActionDeny,
		Description: r.Message,
		Properties:  properties,
	}
}

// ResultID is a stable identity for one (resource, policy, binding)
// evaluation, used to upsert a ReportResult in place across repeated
// admission events for the same resource rather than appending history.
func ResultID(ev audit.Event, r audit.Result) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s/%s/%s/%s/%s/%s",
		ev.Resource.APIGroup, ev.Resource.Resource, ev.Resource.Namespace, ev.Resource.Name,
		r.Policy, r.Binding,
	)
	return hex.EncodeToString(h.Sum(nil))
}
