package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	openreportsclient "github.com/openreports/reports-api/pkg/client/clientset/versioned"

	"github.com/kyverno/policy-reporter/vap-plugin/pkg/builder"
	appconfig "github.com/kyverno/policy-reporter/vap-plugin/pkg/config"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/leaderelection"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/mapper"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/policy"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/reconcile"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/report"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/logging"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/webhook"
)

func newRunCommand() *cobra.Command {
	var configPath string
	var kubeconfig string

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the audit webhook receiver",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.Context(), configPath, kubeconfig)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to config.yaml")
	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "path to a kubeconfig file (defaults to in-cluster config)")

	return cmd
}

func run(ctx context.Context, configPath, kubeconfigFlag string) error {
	cfg, err := appconfig.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if kubeconfigFlag != "" {
		cfg.Kubeconfig = kubeconfigFlag
	}

	log, err := logging.New(logging.Config{Level: cfg.Logging.Level, Development: cfg.Logging.Development})
	if err != nil {
		return fmt.Errorf("building logger: %w", err)
	}
	defer func() { _ = log.Sync() }()

	// Established early and used for everything below - including the
	// policy metadata lookup's informer, which must live for the app's
	// whole lifetime, not just through its own startup sync (see
	// newPolicyMetadataLookup).
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	restConfig, err := appconfig.RESTConfig(cfg.Kubeconfig)
	if err != nil {
		return fmt.Errorf("building kubernetes client config: %w", err)
	}

	reportsClient, err := openreportsclient.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("building openreports client: %w", err)
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("building discovery client: %w", err)
	}
	restMapper := mapper.New(discoveryClient)

	dynamicClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("building dynamic client: %w", err)
	}

	// Needed unconditionally now (not just under LeaderElection.Enabled
	// below): the policy metadata lookup runs per-replica, independent of
	// leader election, same as the webhook hot path itself.
	kubeClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("building kubernetes client: %w", err)
	}

	policyMeta := newPolicyMetadataLookup(ctx, kubeClient, log)

	builderOpts := builder.Options{
		Severity: openreportsv1alpha1.ResultSeverity(cfg.Report.Severity),
		Category: cfg.Report.Category,
	}
	reportClient := report.New(reportsClient, restMapper, dynamicClient, policyMeta, cfg.Report.Labels, cfg.Report.Annotations, builderOpts)

	server := webhook.NewServer(reportClient, log, cfg.Webhook.BufferSize, cfg.Report.ReportDenied)
	go server.Run(ctx, cfg.Webhook.Workers)

	if cfg.LeaderElection.Enabled {
		go startReconciliation(ctx, cfg, kubeClient, reportsClient, log)
	}

	return serve(ctx, cfg, server, log)
}

// newPolicyMetadataLookup syncs a policy.MetadataLookup within a bounded
// startup window (so an unreachable/misbehaving ValidatingAdmissionPolicy
// API doesn't block the webhook receiver from starting at all - the
// severity/category overrides are best-effort, see report.New, so a sync
// failure here just falls back to the configured defaults for every
// result, logged rather than fatal), but ctx itself must be the app's
// long-lived lifetime context: policy.NewMetadataLookup's own doc comment
// covers why passing something that gets cancelled once this function
// returns would silently kill the informer's watch moments after startup.
func newPolicyMetadataLookup(ctx context.Context, kubeClient kubernetes.Interface, log *zap.Logger) *policy.MetadataLookup {
	lookup, err := policy.NewMetadataLookup(ctx, kubeClient, 30*time.Second)
	if err != nil {
		log.Warn("failed to sync ValidatingAdmissionPolicy metadata lookup; falling back to the configured default severity/category for every result",
			zap.Error(err))
		return nil
	}

	return lookup
}

// startReconciliation runs the periodic orphan-TTL sweep and label
// reconciliation (see pkg/kubernetes/reconcile) on whichever replica holds
// the leader election lease. Blocks until ctx is cancelled.
func startReconciliation(ctx context.Context, cfg appconfig.Config, kubeClient kubernetes.Interface, reportsClient openreportsclient.Interface, log *zap.Logger) {
	sweeper := reconcile.NewSweeper(reportsClient, cfg.Report.Labels, cfg.Report.Annotations, cfg.Reconcile.OrphanTTL, log)

	leCfg := leaderelection.Config{
		Namespace:     cfg.LeaderElection.Namespace,
		LeaseName:     cfg.LeaderElection.LeaseName,
		LeaseDuration: cfg.LeaderElection.LeaseDuration,
		RenewDeadline: cfg.LeaderElection.RenewDeadline,
		RetryPeriod:   cfg.LeaderElection.RetryPeriod,
	}

	if err := leaderelection.Run(ctx, kubeClient, leCfg, log, func(leaderCtx context.Context) {
		sweeper.Run(leaderCtx, cfg.Reconcile.Interval)
	}); err != nil {
		log.Error("leader election stopped", zap.Error(err))
	}
}

func serve(ctx context.Context, cfg appconfig.Config, handler http.Handler, log *zap.Logger) error {
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: handler,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	log.Info("starting audit webhook receiver", zap.Int("port", cfg.Server.Port))

	var serveErr error
	if cfg.Server.TLSCertFile != "" && cfg.Server.TLSKeyFile != "" {
		serveErr = httpServer.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
	} else {
		log.Warn("no TLS certificate configured; serving audit webhook over plain HTTP (the Kubernetes audit webhook backend requires HTTPS in production)")
		serveErr = httpServer.ListenAndServe()
	}

	if serveErr != nil && serveErr != http.ErrServerClosed {
		return serveErr
	}

	return nil
}
