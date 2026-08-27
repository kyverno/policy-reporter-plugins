// Package audit extracts ValidatingAdmissionPolicy evaluation results from
// Kubernetes audit.k8s.io events received via the audit webhook backend.
package audit

import "time"

// Action is the ValidatingAdmissionPolicyBinding action that produced a Result.
type Action string

const (
	// ActionDeny means the request was rejected by the policy. Detected by
	// parsing the audit event's responseStatus.message: the API server does
	// not attach a validation_failure annotation for denied requests, only
	// for Audit-action ones (verified against
	// k8s.io/apiserver/pkg/admission/plugin/policy/validating/dispatcher.go).
	ActionDeny Action = "Deny"

	// ActionAudit means the request was allowed but flagged. Detected from
	// the validation.policy.admission.k8s.io/validation_failure audit
	// annotation.
	ActionAudit Action = "Audit"
)

// Resource identifies the object an audited admission request targeted.
//
// Kind is intentionally absent: audit.ObjectReference only carries the
// plural resource name (e.g. "pods"), not Kind. Resolving Kind requires a
// RESTMapper and is done by the report-persistence layer, not here.
type Resource struct {
	APIGroup   string
	APIVersion string
	Resource   string
	Namespace  string
	Name       string
	UID        string
}

// Result is a single VAP policy/binding evaluation extracted from one
// audit.k8s.io Event.
type Result struct {
	Policy  string
	Binding string
	Message string
	Action  Action

	// ExpressionIndex identifies which CEL expression within the policy
	// failed. Only populated for ActionAudit, since the Deny-message format
	// the API server produces does not include it.
	ExpressionIndex *int
}

type Event struct {
	Resource Resource
	HasAudit bool
	Time     time.Time
	Results  []Result
}
