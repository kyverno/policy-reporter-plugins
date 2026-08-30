// Package server implements the HTTP server exposing the Policy Reporter
// plugin API (see github.com/kyverno/policy-reporter-plugins/sdk/api) -
// separate from pkg/webhook's HTTPS audit webhook receiver, which serves an
// unrelated purpose (ingesting Kubernetes audit events, not answering
// Policy Reporter UI queries) and must stay on its own TLS listener.
package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/pprof"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type ServerOption func(s *Server) error

type Handler interface {
	Register(group *gin.RouterGroup) error
}

type BasicAuth struct {
	Username string
	Password string
}

type Server struct {
	middleware []gin.HandlerFunc
	engine     *gin.Engine
	port       int
	httpServer *http.Server
}

func (s *Server) Start() error {
	err := s.httpServer.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}

// Shutdown gracefully stops the underlying HTTP server, waiting for
// in-flight requests to finish until ctx is done.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) Register(path string, handler Handler) error {
	return handler.Register(s.engine.Group(path, s.middleware...))
}

func NewServer(engine *gin.Engine, options []ServerOption) *Server {
	server := &Server{
		engine: engine,
		port:   8080,
	}

	for _, opt := range options {
		if err := opt(server); err != nil {
			zap.L().Error("failed to apply server function", zap.Error(err))
		}
	}

	server.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", server.port),
		Handler: server.engine,
	}

	return server
}

func WithBasicAuth(auth BasicAuth) ServerOption {
	return func(s *Server) error {
		s.middleware = append(s.middleware, gin.BasicAuth(gin.Accounts{
			auth.Username: auth.Password,
		}))

		return nil
	}
}

func WithLogging(logger *zap.Logger) ServerOption {
	return func(s *Server) error {
		s.engine.Use(ginzap.Ginzap(logger, time.RFC3339, true))
		s.engine.Use(ginzap.RecoveryWithZap(logger, true))

		return nil
	}
}

func WithGZIP() ServerOption {
	return func(s *Server) error {
		s.engine.Use(gzip.Gzip(gzip.DefaultCompression, gzip.WithExcludedPaths([]string{"/metrics"})))

		return nil
	}
}

func WithRecovery() ServerOption {
	return func(s *Server) error {
		s.engine.Use(gin.Recovery())

		return nil
	}
}

func WithPort(port int) ServerOption {
	return func(s *Server) error {
		s.port = port

		return nil
	}
}

func WithProfiling() ServerOption {
	return func(s *Server) error {
		pprof.Register(s.engine)

		return nil
	}
}
