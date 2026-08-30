package cmd

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/tools/clientcmd"

	appconfig "github.com/kyverno/policy-reporter/vap-plugin/pkg/config"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/leaderelection"
)

func newRunCommand() *cobra.Command {
	var configPath string
	var local bool
	var kubeConfig clientcmd.ConfigOverrides

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the audit webhook receiver",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.Context(), configPath, local, kubeConfig)
		},
	}
	clientcmd.BindOverrideFlags(&kubeConfig, cmd.Flags(), clientcmd.RecommendedConfigOverrideFlags("kube-"))

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to config.yaml")
	cmd.Flags().BoolVar(&local, "local", false, "run the plugin locally (for development purposes)")
	flag.Parse()

	return cmd
}

func run(ctx context.Context, configPath string, local bool, kubeConfig clientcmd.ConfigOverrides) error {
	fmt.Println(local)
	cfg, err := appconfig.Load(configPath, local, kubeConfig)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if err := appconfig.SetupMemLimit(ctx, cfg); err != nil {
		return fmt.Errorf("setting up memory limit: %w", err)
	}

	resolver := appconfig.NewResolver(cfg)

	log, err := resolver.Logger()
	if err != nil {
		return err
	}
	defer func() { _ = log.Sync() }()

	// Established early and used for everything below - including the
	// ValidatingAdmissionPolicy informer behind the policy metadata lookup
	// and plugin API, which must live for the app's whole lifetime, not
	// just through its own startup sync (see config.Resolver.VAPLister).
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	group := &errgroup.Group{}

	if cfg.Server.Enabled {
		webhookServer, err := resolver.WebhookServer(ctx)
		if err != nil {
			return err
		}

		go webhookServer.Run(ctx, cfg.Webhook.Workers)

		group.Go(func() error {
			return serve(ctx, cfg, webhookServer, log)
		})
	} else {
		log.Info("audit webhook receiver disabled")
	}

	go startReconciliation(ctx, resolver)

	if cfg.API.Enabled {
		apiServer, err := resolver.APIServer(ctx)
		if err != nil {
			return fmt.Errorf("building plugin api server: %w", err)
		}

		group.Go(func() error {
			log.Info("starting policy reporter plugin api server", zap.Int("port", cfg.API.Port))
			if err := apiServer.Start(); err != nil {
				return fmt.Errorf("plugin api server stopped: %w", err)
			}

			return nil
		})
	} else {
		log.Info("policy reporter plugin api server disabled")
	}

	return group.Wait()
}

// startReconciliation runs the periodic orphan-TTL sweep and label
// reconciliation (see pkg/kubernetes/reconcile). With leader election
// enabled, it only runs on whichever replica holds the lease; with it
// disabled, it runs directly on this replica (suitable for single-replica
// deployments, where coordinating a lease would be pure overhead). Blocks
// until ctx is cancelled.
func startReconciliation(ctx context.Context, resolver *appconfig.Resolver) {
	sweeper, err := resolver.Sweeper()
	if err != nil {
		zap.L().Error("building sweeper", zap.Error(err))
		return
	}

	kubeClient, err := resolver.KubeClient()
	if err != nil {
		zap.L().Error("building kube client", zap.Error(err))
		return
	}

	cfg := resolver.Config()

	if !cfg.LeaderElection.Enabled {
		sweeper.Run(ctx, cfg.Reconcile.Interval)
		return
	}

	leCfg := leaderelection.Config{
		Namespace:     cfg.LeaderElection.Namespace,
		Identity:      cfg.LeaderElection.PodName,
		LeaseName:     cfg.LeaderElection.LeaseName,
		LeaseDuration: cfg.LeaderElection.LeaseDuration,
		RenewDeadline: cfg.LeaderElection.RenewDeadline,
		RetryPeriod:   cfg.LeaderElection.RetryPeriod,
	}

	if err := leaderelection.Run(ctx, kubeClient, leCfg, zap.L(), func(leaderCtx context.Context) {
		sweeper.Run(leaderCtx, cfg.Reconcile.Interval)
	}); err != nil {
		zap.L().Error("leader election stopped", zap.Error(err))
	}
}

func serve(ctx context.Context, cfg appconfig.Config, handler http.Handler, log *zap.Logger) error {
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: handler,
	}

	go func() {
		<-ctx.Done()
		fmt.Println("shutdown")
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

	fmt.Println("stopped serving", serveErr)

	if serveErr != nil && serveErr != http.ErrServerClosed {
		return serveErr
	}

	return nil
}
