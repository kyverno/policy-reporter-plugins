package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
)

// Fixtures below reflect real audit.k8s.io/v1 Event payloads captured from
// a kind (k8s v1.36.1) cluster running an actual ValidatingAdmissionPolicy
// with Deny and Audit action bindings (plan Milestone 0). Notably:
//   - responseStatus.message wraps the VAP message in a resource-specific
//     prefix (e.g. `pods "x" is forbidden: <msg>`); the unwrapped message
//     appears in responseStatus.details.causes[].message instead.
//   - objectRef.uid is absent for ordinary create/update/delete requests on
//     the primary resource - it's only populated for subresource requests
//     (status, binding) that already know the object's identity. Report
//     persistence must not assume a UID is available.

func objectRef() *auditv1.ObjectReference {
	return &auditv1.ObjectReference{
		APIGroup:   "apps",
		APIVersion: "v1",
		Resource:   "deployments",
		Namespace:  "default",
		Name:       "web",
	}
}

func baseEvent() *auditv1.Event {
	ts := metav1.NewMicroTime(time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC))
	return &auditv1.Event{
		Level:          auditv1.LevelMetadata,
		Stage:          auditv1.StageResponseComplete,
		Verb:           "create",
		ObjectRef:      objectRef(),
		StageTimestamp: ts,
	}
}

// deniedStatus builds a responseStatus matching the real shape a Deny-action
// VAP rejection produces: a wrapped top-level message, and the unwrapped VAP
// message duplicated into details.causes[0].message.
func deniedStatus(wrappedPrefix, policy, binding, msg string) *metav1.Status {
	var vapMessage string
	if binding != "" {
		vapMessage = "ValidatingAdmissionPolicy '" + policy + "' with binding '" + binding + "' denied request: " + msg
	} else {
		vapMessage = "ValidatingAdmissionPolicy '" + policy + "' denied request: " + msg
	}

	return &metav1.Status{
		Status:  metav1.StatusFailure,
		Message: wrappedPrefix + vapMessage,
		Reason:  metav1.StatusReasonInvalid,
		Details: &metav1.StatusDetails{
			Causes: []metav1.StatusCause{{Message: vapMessage}},
		},
	}
}

func TestParse_DenyWithBinding(t *testing.T) {
	event := baseEvent()
	event.ResponseStatus = deniedStatus(`deployments "web" is forbidden: `, "require-labels", "require-labels-binding", "labels are required")

	ev := Parse(true, event)
	assert.False(t, ev.HasAudit, "expected HasAudit to be false for a Deny action")
	require.Len(t, ev.Results, 1)

	r := ev.Results[0]
	assert.Equal(t, ActionDeny, r.Action)
	assert.Equal(t, "require-labels", r.Policy)
	assert.Equal(t, "require-labels-binding", r.Binding)
	assert.Equal(t, "labels are required", r.Message)
	assert.Equal(t, "web", ev.Resource.Name)
	assert.Equal(t, "default", ev.Resource.Namespace)
}

func TestParse_DenyWithoutBinding(t *testing.T) {
	event := baseEvent()
	event.ResponseStatus = deniedStatus(`deployments "web" is forbidden: `, "require-labels", "", "labels are required")

	ev := Parse(true, event)
	require.Len(t, ev.Results, 1)
	assert.Empty(t, ev.Results[0].Binding)
}

func TestParse_DenyFallsBackToTopLevelMessageWhenCausesAbsent(t *testing.T) {
	event := baseEvent()
	event.ResponseStatus = &metav1.Status{
		Message: `deployments "web" is forbidden: ValidatingAdmissionPolicy 'require-labels' with binding 'require-labels-binding' denied request: labels are required`,
	}

	ev := Parse(true, event)
	require.Len(t, ev.Results, 1)
	assert.Equal(t, "require-labels", ev.Results[0].Policy)
}

func TestParse_NonVAPDenial(t *testing.T) {
	event := baseEvent()
	event.ResponseStatus = &metav1.Status{
		Message: "admission webhook \"pod-policy.example.com\" denied the request: nope",
	}

	ev := Parse(true, event)
	assert.Empty(t, ev.Results, "expected 0 results for a non-VAP denial")
}

func TestParse_AuditActionSingleFailure(t *testing.T) {
	event := baseEvent()
	event.Annotations = map[string]string{
		validationFailureAnnotationKey: `[{"message":"replicas should be at least 2","policy":"min-replicas","binding":"min-replicas-binding","expressionIndex":0,"validationActions":["Audit"]}]`,
	}

	ev := Parse(true, event)
	assert.True(t, ev.HasAudit, "expected HasAudit to be true for an Audit action")
	require.Len(t, ev.Results, 1)

	r := ev.Results[0]
	assert.Equal(t, ActionAudit, r.Action)
	assert.Equal(t, "min-replicas", r.Policy)
	assert.Equal(t, "min-replicas-binding", r.Binding)
}

func TestParse_AuditActionMultipleFailures(t *testing.T) {
	event := baseEvent()
	event.Annotations = map[string]string{
		validationFailureAnnotationKey: `[
			{"message":"m1","policy":"p1","binding":"b1","expressionIndex":0,"validationActions":["Audit"]},
			{"message":"m2","policy":"p2","binding":"b2","expressionIndex":0,"validationActions":["Audit"]}
		]`,
	}

	ev := Parse(true, event)
	assert.Len(t, ev.Results, 2)
}

func TestParse_MalformedAnnotationIsSkipped(t *testing.T) {
	event := baseEvent()
	event.Annotations = map[string]string{
		validationFailureAnnotationKey: `not-json`,
	}

	ev := Parse(true, event)
	assert.Empty(t, ev.Results, "expected 0 results for malformed annotation")
}

func TestParse_NoSignalYieldsNoResults(t *testing.T) {
	ev := Parse(true, baseEvent())
	assert.Empty(t, ev.Results)
}

func TestParse_NilEvent(t *testing.T) {
	ev := Parse(true, nil)
	assert.Empty(t, ev.Results, "expected no results for a nil event")
}

func TestParse_DenyAndAuditCombined(t *testing.T) {
	// A single request can be denied by one binding while an unrelated
	// Audit-action binding also recorded a failure for it (see
	// dispatcher.go: Audit-action annotations are written during the same
	// evaluation pass that produces the Deny, regardless of its outcome).
	// Parse surfaces both as separate Results, each carrying its own
	// Action - that per-result Action is what callers should key off of
	// (e.g. pkg/builder.Build scores each result by its own r.Action, not
	// by the event's).
	event := baseEvent()
	event.ResponseStatus = deniedStatus(`deployments "web" is forbidden: `, "require-labels", "require-labels-binding", "labels are required")
	event.Annotations = map[string]string{
		validationFailureAnnotationKey: `[{"message":"m","policy":"other-policy","binding":"other-binding","expressionIndex":0,"validationActions":["Audit"]}]`,
	}

	ev := Parse(true, event)
	require.Len(t, ev.Results, 2)

	assert.Equal(t, ActionDeny, ev.Results[0].Action)
	assert.Equal(t, "require-labels", ev.Results[0].Policy)
	assert.Equal(t, ActionAudit, ev.Results[1].Action)
	assert.Equal(t, "other-policy", ev.Results[1].Policy)

	// Event.HasAudit itself does NOT mean "this event has no Deny result":
	// Parse sets it whenever any Audit-action failures are present at all,
	// independent of whether a Deny result also exists. It's true here even
	// though this event also contains a Deny result. Downstream code that
	// branches on it (e.g. pkg/kubernetes/report.Client gating its live-UID
	// lookup on event.HasAudit) should be aware a mixed event like this one
	// reads as "has audit" there, despite containing a real Deny result -
	// see Result.Action for the reliable per-result signal.
	assert.True(t, ev.HasAudit, "expected Event.HasAudit to be true for a mixed event (see comment above)")
}

func TestParse_DenyOnlyEventDroppedEntirelyWhenReportDeniedDisabled(t *testing.T) {
	event := baseEvent()
	event.ResponseStatus = deniedStatus(`deployments "web" is forbidden: `, "require-labels", "require-labels-binding", "labels are required")

	ev := Parse(false, event)
	assert.Equal(t, Event{}, ev, "expected a zero Event: reportDenied=false drops the whole event, not just the Deny result")
}

func TestParse_MixedEventDroppedEntirelyWhenReportDeniedDisabled(t *testing.T) {
	// reportDenied is a whole-event decision, not a per-result filter: a
	// Deny alongside an unrelated Audit-action failure in the same event
	// (see TestParse_DenyAndAuditCombined) doesn't get trimmed down to just
	// the Audit result when reportDenied is false - the entire event,
	// Audit result included, is dropped.
	event := baseEvent()
	event.ResponseStatus = deniedStatus(`deployments "web" is forbidden: `, "require-labels", "require-labels-binding", "labels are required")
	event.Annotations = map[string]string{
		validationFailureAnnotationKey: `[{"message":"m","policy":"other-policy","binding":"other-binding","expressionIndex":0,"validationActions":["Audit"]}]`,
	}

	ev := Parse(false, event)
	assert.Equal(t, Event{}, ev, "expected a zero Event: the co-occurring Audit result is dropped along with the Deny")
}

func TestParse_DenyOnlyEventKeptWhenReportDeniedEnabled(t *testing.T) {
	event := baseEvent()
	event.ResponseStatus = deniedStatus(`deployments "web" is forbidden: `, "require-labels", "require-labels-binding", "labels are required")

	ev := Parse(true, event)
	require.Len(t, ev.Results, 1)
	assert.Equal(t, ActionDeny, ev.Results[0].Action)
	assert.Equal(t, "require-labels", ev.Results[0].Policy)
	assert.False(t, ev.HasAudit)
}
