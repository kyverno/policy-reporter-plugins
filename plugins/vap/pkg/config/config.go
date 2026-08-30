// Package config defines and loads vap-plugin's runtime configuration.
package config

import (
	"time"

	"k8s.io/client-go/tools/clientcmd"
)

// Config is the root application configuration, bound from a YAML file and
// environment variables (see Load).
type Config struct {
	Kubeconfig clientcmd.ConfigOverrides `mapstructure:"-"`
	Local      bool                      `mapstructure:"-"`

	Server          ServerConfig         `mapstructure:"server"`
	Webhook         WebhookConfig        `mapstructure:"webhook"`
	Report          ReportConfig         `mapstructure:"report"`
	LeaderElection  LeaderElectionConfig `mapstructure:"leaderElection"`
	Reconcile       ReconcileConfig      `mapstructure:"reconcile"`
	API             APIConfig            `mapstructure:"api"`
	Logging         LoggingConfig        `mapstructure:"logging"`
	AutoMemoryLimit AutoMemoryLimit      `mapstructure:"autoMemoryLimit"`
}

type AutoMemoryLimit struct {
	Enabled bool    `mapstructure:"enabled"`
	Ratio   float64 `mapstructure:"ratio"`
}

// ServerConfig configures the audit webhook HTTPS listener. The API
// server's audit webhook backend requires HTTPS.
type ServerConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	Port        int    `mapstructure:"port"`
	TLSCertFile string `mapstructure:"tlsCertFile"`
	TLSKeyFile  string `mapstructure:"tlsKeyFile"`
}

// WebhookConfig tunes the internal event queue between the HTTP handler and
// the workers that parse/persist results.
type WebhookConfig struct {
	// BufferSize bounds how many audit events can be queued before new ones
	// are dropped rather than blocking the HTTP response.
	BufferSize int `mapstructure:"bufferSize"`
	// Workers is the number of goroutines draining the queue.
	Workers int `mapstructure:"workers"`
}

// ReportConfig controls fields applied uniformly to every ReportResult and
// every Report/ClusterReport this app writes.
type ReportConfig struct {
	// Severity applied to every ReportResult; VAP has no built-in severity.
	Severity string `mapstructure:"severity"`
	// Category applied to every ReportResult.
	Category string `mapstructure:"category"`
	// Labels merged onto every managed Report/ClusterReport, in addition to
	// the always-present managed-by label.
	Labels map[string]string `mapstructure:"labels"`
	// Annotations merged onto every managed Report/ClusterReport.
	Annotations map[string]string `mapstructure:"annotations"`
	// ReportDenied controls whether Deny-action VAP results (requests
	// Kubernetes actually blocked) are persisted as ReportResults at all.
	// Defaults to false: a Deny already surfaces to the caller as a
	// rejected request, so by default only Audit-action results - allowed
	// through silently otherwise - are persisted. Set to true to also
	// report Deny-action results. This is a whole-event decision (see
	// pkg/audit.Parse): when false, any audit event containing a Deny
	// result is dropped entirely - including any Audit-action result
	// recorded alongside it in that same event - not just the Deny part.
	ReportDenied bool `mapstructure:"reportDenied"`
}

// LeaderElectionConfig configures the Lease used to run the reconcile
// Sweeper on exactly one replica.
type LeaderElectionConfig struct {
	Enabled       bool          `mapstructure:"enabled"`
	PodName       string        `mapstructure:"podName"`
	Namespace     string        `mapstructure:"namespace"`
	LeaseName     string        `mapstructure:"leaseName"`
	LeaseDuration time.Duration `mapstructure:"leaseDuration"`
	RenewDeadline time.Duration `mapstructure:"renewDeadline"`
	RetryPeriod   time.Duration `mapstructure:"retryPeriod"`
}

// ReconcileConfig controls the periodic sweep that (a) deletes Reports left
// over from denied Create requests once they're older than OrphanTTL (they
// have no owner reference to be garbage-collected by), and (b) reconciles
// managed-by labels/annotations after a config change.
type ReconcileConfig struct {
	Interval  time.Duration `mapstructure:"interval"`
	OrphanTTL time.Duration `mapstructure:"orphanTTL"`
}

// APIConfig configures the Policy Reporter plugin API server (see
// pkg/server), which serves policy list/detail lookups for the Policy
// Reporter UI. This is a separate plain-HTTP listener from ServerConfig's
// TLS audit webhook receiver - the two serve unrelated purposes and must
// not share a port.
type APIConfig struct {
	Enabled bool            `mapstructure:"enabled"`
	Port    int             `mapstructure:"port"`
	Debug   bool            `mapstructure:"debug"`
	Auth    BasicAuthConfig `mapstructure:"basicAuth"`
}

// BasicAuthConfig optionally protects the plugin API server with HTTP basic
// auth. Both fields must be set for auth to be enabled.
type BasicAuthConfig struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// LoggingConfig configures the zap logger.
type LoggingConfig struct {
	Level       string `mapstructure:"level"`
	Development bool   `mapstructure:"development"`
}

// Default returns the configuration used when no file/env value overrides
// a field.
func Default() Config {
	return Config{
		Server: ServerConfig{
			Enabled: true,
			Port:    8443,
		},
		Webhook: WebhookConfig{
			BufferSize: 1000,
			Workers:    4,
		},
		Report: ReportConfig{
			ReportDenied: false,
		},
		LeaderElection: LeaderElectionConfig{
			Enabled:       false,
			LeaseName:     "vap-plugin",
			LeaseDuration: 15 * time.Second,
			RenewDeadline: 10 * time.Second,
			RetryPeriod:   2 * time.Second,
		},
		Reconcile: ReconcileConfig{
			Interval:  10 * time.Minute,
			OrphanTTL: 24 * time.Hour,
		},
		API: APIConfig{
			Enabled: true,
			Port:    8080,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}
