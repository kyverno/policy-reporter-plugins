package audit

import (
	"encoding/json"
	"regexp"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
)

// validationFailureAnnotationKey is the audit annotation key the API server
// sets for Audit-action ValidatingAdmissionPolicy failures.
const validationFailureAnnotationKey = "validation.policy.admission.k8s.io/validation_failure"

// validationFailureAnnotation mirrors the unexported
// k8s.io/apiserver/.../validating.ValidationFailureValue JSON shape,
// redeclared locally to avoid depending on apiserver's admission plugin
// internals for a single struct.
type validationFailureAnnotation struct {
	Message           string   `json:"message"`
	Policy            string   `json:"policy"`
	Binding           string   `json:"binding"`
	ExpressionIndex   int      `json:"expressionIndex"`
	ValidationActions []string `json:"validationActions"`
}

// denyMessagePattern matches the fixed message format the API server
// produces for a Deny-action ValidatingAdmissionPolicy rejection:
//
//	ValidatingAdmissionPolicy 'policy' with binding 'binding' denied request: msg
//	ValidatingAdmissionPolicy 'policy' denied request: msg
//
// Deliberately not anchored at the start: verified against a real kind
// cluster (k8s v1.36.1) that responseStatus.message wraps this in a
// resource-specific prefix - e.g. `pods "x" is forbidden: <this>` - so
// matching is done as a substring search, not a full-string match. The
// unwrapped form appears verbatim in responseStatus.details.causes[].message
// (see parseDenyFailure), which is checked first and is the reliable source;
// responseStatus.message is only a fallback for the case causes is absent.
//
// Any other denial (RBAC, a validating webhook, a different admission
// plugin) will not match, so this also acts as the VAP-relevance filter for
// denied requests.
var denyMessagePattern = regexp.MustCompile(`(?s)ValidatingAdmissionPolicy '([^']*)'(?: with binding '([^']*)')? denied request: (.*)$`)

// Parse extracts every VAP Result from a single audit event. An event
// unrelated to VAP (or one whose shape isn't recognized) yields none. A
// single Deny-action rejection yields at most one Result; multiple
// Audit-action bindings can each contribute one, since the API server
// records every failed Audit-action binding for a request.
//
// reportDenied, when false (the default), suppresses the whole event
// whenever it contains a Deny-action rejection: Parse returns a zero Event,
// discarding not just the Deny result but any Audit-action results that
// happened to be recorded alongside it in the same event (see
// dispatcher.go: an Audit-action annotation can be written during the same
// evaluation pass that produces an unrelated binding's Deny). This is a
// whole-event decision, not a per-result filter - a mixed event isn't
// trimmed down to just its Audit-action results, it's dropped entirely.
// When reportDenied is true, Deny and Audit-action results are both
// returned exactly as parsed, with no filtering at all.
func Parse(reportDenied bool, event *auditv1.Event) Event {
	if event == nil {
		return Event{}
	}

	ts := eventTimestamp(event)
	res := resourceFromRef(event.ObjectRef)
	if res.Name == "" {
		zap.L().Warn("audit event has no resource name, skipping", zap.Any("event", event))
		return Event{}
	}

	var results []Result
	var hasAudit bool

	if r, ok := parseDenyFailure(event); ok {
		results = append(results, r)
		hasAudit = false

		if !reportDenied {
			zap.L().Info("skipped because reportDenied is false, skipping", zap.Any("event", event), zap.Any("results", results))
			return Event{}
		}
	}

	if r := parseAuditFailures(event); len(r) > 0 {
		results = append(results, r...)
		hasAudit = true
	}

	return Event{
		Resource: res,
		Time:     ts,
		HasAudit: hasAudit,
		Results:  results,
	}
}

func parseDenyFailure(event *auditv1.Event) (Result, bool) {
	if event.ResponseStatus == nil {
		return Result{}, false
	}

	// details.causes[].message carries the raw, unwrapped VAP message; the
	// top-level message is a fallback in case causes wasn't populated for
	// some reason (e.g. a future apiserver change to error construction).
	for _, cause := range causesMessages(event.ResponseStatus) {
		if r, ok := matchDenyMessage(cause); ok {
			return r, true
		}
	}

	return matchDenyMessage(event.ResponseStatus.Message)
}

func causesMessages(status *metav1.Status) []string {
	if status.Details == nil {
		return nil
	}

	messages := make([]string, 0, len(status.Details.Causes))
	for _, cause := range status.Details.Causes {
		messages = append(messages, cause.Message)
	}

	return messages
}

func matchDenyMessage(message string) (Result, bool) {
	m := denyMessagePattern.FindStringSubmatch(message)
	if m == nil {
		return Result{}, false
	}

	return Result{
		Policy:  m[1],
		Binding: m[2],
		Message: m[3],
		Action:  ActionDeny,
	}, true
}

func parseAuditFailures(event *auditv1.Event) []Result {
	raw, ok := event.Annotations[validationFailureAnnotationKey]
	if !ok || raw == "" {
		return nil
	}

	var failures []validationFailureAnnotation
	// A malformed or truncated payload (the API server caps this annotation
	// at 10KiB) is skipped rather than treated as fatal - it's one missed
	// result out of a stream, not a reason to drop the whole event.
	if err := json.Unmarshal([]byte(raw), &failures); err != nil {
		return nil
	}

	results := make([]Result, 0, len(failures))
	for _, f := range failures {
		expressionIndex := f.ExpressionIndex
		results = append(results, Result{
			Policy:          f.Policy,
			Binding:         f.Binding,
			Message:         f.Message,
			ExpressionIndex: &expressionIndex,
			Action:          ActionAudit,
		})
	}

	return results
}

func resourceFromRef(ref *auditv1.ObjectReference) Resource {
	if ref == nil {
		return Resource{}
	}

	return Resource{
		APIGroup:   ref.APIGroup,
		APIVersion: ref.APIVersion,
		Resource:   ref.Resource,
		Namespace:  ref.Namespace,
		Name:       ref.Name,
		UID:        string(ref.UID),
	}
}

func eventTimestamp(event *auditv1.Event) time.Time {
	if !event.StageTimestamp.IsZero() {
		return event.StageTimestamp.Time
	}

	return event.RequestReceivedTimestamp.Time
}
