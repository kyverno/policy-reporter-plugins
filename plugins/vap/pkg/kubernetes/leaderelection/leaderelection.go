// Package leaderelection runs a callback on exactly one replica, using a
// Kubernetes Lease. Only the periodic reconciliation sweep needs this - the
// webhook hot path is naturally load-balanced across replicas by the
// Service in front of it and needs no coordination.
package leaderelection

import (
	"context"
	"os"
	"time"

	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// Config controls the Lease used for leader election.
type Config struct {
	Namespace     string
	LeaseName     string
	Identity      string
	LeaseDuration time.Duration
	RenewDeadline time.Duration
	RetryPeriod   time.Duration
}

// Run blocks, invoking fn each time this process becomes the leader and
// stopping fn's context when leadership is lost. Returns when ctx is
// cancelled.
func Run(ctx context.Context, client kubernetes.Interface, cfg Config, log *zap.Logger, fn func(ctx context.Context)) error {
	identity := cfg.Identity
	if identity == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		identity = hostname
	}

	lock, err := resourcelock.New(
		resourcelock.LeasesResourceLock,
		cfg.Namespace,
		cfg.LeaseName,
		client.CoreV1(),
		client.CoordinationV1(),
		resourcelock.ResourceLockConfig{Identity: identity},
	)
	if err != nil {
		return err
	}

	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:          lock,
		LeaseDuration: cfg.LeaseDuration,
		RenewDeadline: cfg.RenewDeadline,
		RetryPeriod:   cfg.RetryPeriod,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				log.Info("acquired leadership", zap.String("identity", identity))
				fn(ctx)
			},
			OnStoppedLeading: func() {
				log.Info("lost leadership", zap.String("identity", identity))
			},
		},
		ReleaseOnCancel: true,
	})

	return nil
}
