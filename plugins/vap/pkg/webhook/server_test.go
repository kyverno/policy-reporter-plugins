package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"

	"github.com/kyverno/policy-reporter/vap-plugin/pkg/audit"
)

// recordingPersister records each Upsert call as one Event (results
// extracted from a single audit event, plus its Resource/Action), rather
// than flattening every result into one list - that batching is exactly
// what's under test here.
type recordingPersister struct {
	mu     sync.Mutex
	events []audit.Event
	done   chan struct{}
}

func newRecordingPersister(expectEvents int) *recordingPersister {
	return &recordingPersister{done: make(chan struct{}, expectEvents)}
}

func (p *recordingPersister) Upsert(_ context.Context, event audit.Event) error {
	p.mu.Lock()
	p.events = append(p.events, event)
	p.mu.Unlock()
	p.done <- struct{}{}
	return nil
}

func (p *recordingPersister) waitFor(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-p.done:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %d persisted events", n)
		}
	}
}

func TestServer_ParsesAndPersistsDenyEvent(t *testing.T) {
	persister := newRecordingPersister(1)
	server := NewServer(persister, zap.NewNop(), 16, true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Run(ctx, 2)

	list := auditv1.EventList{
		Items: []auditv1.Event{{
			ObjectRef: &auditv1.ObjectReference{
				APIGroup: "apps", APIVersion: "v1", Resource: "deployments",
				Namespace: "default", Name: "web", UID: "uid-1",
			},
			ResponseStatus: &metav1.Status{
				Message: "ValidatingAdmissionPolicy 'require-labels' with binding 'require-labels-binding' denied request: nope",
			},
		}},
	}

	body, err := json.Marshal(list)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	persister.waitFor(t, 1)

	persister.mu.Lock()
	defer persister.mu.Unlock()
	require.Len(t, persister.events, 1)
	ev := persister.events[0]
	assert.False(t, ev.HasAudit)
	require.Len(t, ev.Results, 1)
	assert.Equal(t, "require-labels", ev.Results[0].Policy)
}

func TestServer_MultipleResultsFromOneEventFormOneBatch(t *testing.T) {
	persister := newRecordingPersister(1)
	server := NewServer(persister, zap.NewNop(), 16, true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Run(ctx, 2)

	// Two Audit-action bindings failing on the same request - see
	// audit.TestParse_DenyAndAuditCombined for the case where a Deny and an
	// Audit failure land in the same event's Results together.
	list := auditv1.EventList{
		Items: []auditv1.Event{{
			ObjectRef: &auditv1.ObjectReference{
				APIGroup: "apps", APIVersion: "v1", Resource: "deployments",
				Namespace: "default", Name: "web", UID: "uid-1",
			},
			Annotations: map[string]string{
				"validation.policy.admission.k8s.io/validation_failure": `[
					{"message":"m1","policy":"policy-1","binding":"binding-1","expressionIndex":0,"validationActions":["Audit"]},
					{"message":"m2","policy":"policy-2","binding":"binding-2","expressionIndex":0,"validationActions":["Audit"]}
				]`,
			},
		}},
	}

	body, err := json.Marshal(list)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	persister.waitFor(t, 1)

	persister.mu.Lock()
	defer persister.mu.Unlock()
	require.Len(t, persister.events, 1, "expected both results delivered as 1 event (1 Upsert call)")
	assert.Len(t, persister.events[0].Results, 2, "expected 2 results in the event")
}

func TestServer_RejectsNonPost(t *testing.T) {
	server := NewServer(newRecordingPersister(0), zap.NewNop(), 16, true)

	req := httptest.NewRequest(http.MethodGet, "/webhook", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestServer_RejectsMalformedBody(t *testing.T) {
	server := NewServer(newRecordingPersister(0), zap.NewNop(), 16, true)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader([]byte("not-json")))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestServer_EventWithNoVAPSignalIsNotPersisted(t *testing.T) {
	persister := newRecordingPersister(0)
	server := NewServer(persister, zap.NewNop(), 16, true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Run(ctx, 2)

	list := auditv1.EventList{Items: []auditv1.Event{{
		ObjectRef: &auditv1.ObjectReference{Resource: "pods", Name: "irrelevant"},
	}}}
	body, err := json.Marshal(list)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	select {
	case <-persister.done:
		t.Fatalf("expected no persisted events")
	case <-time.After(100 * time.Millisecond):
	}
}
