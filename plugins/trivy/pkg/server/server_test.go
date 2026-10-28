package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type failingPoliciesHandler struct{}

func (failingPoliciesHandler) Register(group *gin.RouterGroup) error {
	group.GET("/policies", func(ctx *gin.Context) {
		ctx.Status(http.StatusInternalServerError)
	})
	return nil
}

func TestHealthEndpointsIndependentOfAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	s := NewServer(engine, []ServerOption{
		WithBasicAuth(BasicAuth{Username: "user", Password: "secret"}),
	})
	if err := s.Register("/vulnr/v1", failingPoliciesHandler{}); err != nil {
		t.Fatalf("register failing API: %v", err)
	}

	t.Run("policy API still requires authentication", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/vulnr/v1/policies", nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("got HTTP %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("simulated vulnerability API failure", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/vulnr/v1/policies", nil)
		req.SetBasicAuth("user", "secret")
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("got HTTP %d, want %d", rec.Code, http.StatusInternalServerError)
		}
	})

	for _, path := range []string{"/healthz", "/ready"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			engine.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s: got HTTP %d, want %d", path, rec.Code, http.StatusOK)
			}
		})
	}
}
