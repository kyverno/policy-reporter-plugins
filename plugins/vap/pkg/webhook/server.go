// Package webhook implements the HTTPS receiver the API server's audit
// webhook backend POSTs audit.k8s.io EventList batches to.
package webhook

import (
	"context"
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"

	"github.com/kyverno/policy-reporter/vap-plugin/pkg/audit"
)

// Persister writes a batch of parsed VAP results - everything extracted
// from a single audit event, all sharing that event's target resource - to
// its Report/ClusterReport in one call. Implemented by *report.Client; kept
// as an interface here so the handler is testable without a real
// Kubernetes API.
type Persister interface {
	Upsert(ctx context.Context, event audit.Event) error
}

// Server is the audit webhook HTTPS receiver. It decodes each EventList
// inline (JSON decoding is fast; this is not where backpressure comes
// from) but hands the actual parsing+persistence work to a bounded worker
// pool via a channel, so a burst of admission traffic can't block the HTTP
// response the API server is waiting on - a slow/unavailable Kubernetes API
// server should not make audit logging itself unreliable.
type Server struct {
	log          *zap.Logger
	events       chan *auditv1.Event
	persist      Persister
	reportDenied bool
}

// NewServer builds a Server. bufferSize bounds how many parsed audit events
// can be queued for processing before new ones are dropped (with a logged
// warning) rather than blocking the HTTP handler.
func NewServer(persist Persister, log *zap.Logger, bufferSize int, reportDenied bool) *Server {
	return &Server{
		log:          log,
		events:       make(chan *auditv1.Event, bufferSize),
		persist:      persist,
		reportDenied: reportDenied,
	}
}

// Run starts worker goroutines that drain the event queue and persist any
// VAP results they contain. It blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context, workers int) {
	for i := 0; i < workers; i++ {
		go s.worker(ctx)
	}
	<-ctx.Done()
}

func (s *Server) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.events:
			s.process(ctx, event)
		}
	}
}

func (s *Server) process(ctx context.Context, event *auditv1.Event) {
	ev := audit.Parse(s.reportDenied, event)
	if len(ev.Results) == 0 {
		return
	}

	if err := s.persist.Upsert(ctx, ev); err != nil {
		s.log.Error("failed to persist VAP results",
			zap.Int("count", len(ev.Results)),
			zap.String("namespace", ev.Resource.Namespace),
			zap.String("name", ev.Resource.Name),
			zap.Error(err),
		)
	}
}

// ServeHTTP implements the audit webhook backend contract: the API server
// POSTs an audit.k8s.io/v1 EventList and expects a fast 2xx response.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var list auditv1.EventList
	if err := json.NewDecoder(r.Body).Decode(&list); err != nil {
		s.log.Warn("failed to decode audit event list", zap.Error(err))
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	for i := range list.Items {
		select {
		case s.events <- &list.Items[i]:
		default:
			s.log.Warn("audit event queue full, dropping event",
				zap.String("auditID", string(list.Items[i].AuditID)))
		}
	}

	w.WriteHeader(http.StatusOK)
}
