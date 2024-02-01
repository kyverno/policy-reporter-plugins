package cmd

import (
	"context"
	"flag"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/config"
	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/server"
	v1 "github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/server/v1"
	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/violation"
)

var configFile string

func newRunCMD() *cobra.Command {
	c := &config.Config{}

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run Policy Reporter Kyverno Plugin",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := config.Load(c, configFile)
			if err != nil {
				return err
			}

			resolver := config.NewResolver(c)
			logger := resolver.Logger()

			client, err := resolver.KyvernoClient()
			if err != nil {
				return err
			}

			coreAPI, err := resolver.CoreClient(cmd.Context())
			if err != nil {
				return err
			}

			server, err := resolver.Server(cmd.Context(), []server.ServerOption{
				v1.WithAPI(client, coreAPI),
				server.WithPort(c.Server.Port),
			})
			if err != nil {
				return err
			}

			if c.BlockReports.Enabled {
				logger.Info("block reports enabled", zap.Int("resultsPerReport", c.BlockReports.Results.MaxPerReport))
				eventClient, err := resolver.EventClient()
				if err != nil {
					return err
				}

				policyReportClient, err := resolver.PolicyReportClient()
				if err != nil {
					return err
				}

				resolver.ViolationPublisher().RegisterListener(func(pv violation.PolicyViolation) {
					policyReportClient.ProcessViolation(cmd.Context(), pv)
				})

				var stop chan struct{}
				defer close(stop)

				if c.LeaderElection.Enabled {
					leClient, err := resolver.LeaderElectionClient()
					if err != nil {
						return err
					}

					leClient.RegisterOnStart(func(c context.Context) {
						logger.Info("started leadership")

						stop = make(chan struct{})

						if err = eventClient.Run(c, stop); err != nil {
							logger.Error("failed to run EventClient", zap.Error(err))
						}
					}).RegisterOnNew(func(currentID, lockID string) {
						if currentID != lockID {
							logger.Info("leadership", zap.String("leader", currentID))
						}
					}).RegisterOnStop(func() {
						logger.Info("stopped leadership")
						close(stop)
					})

					go leClient.Run(cmd.Context())
				} else {
					stop = make(chan struct{})
					if err = eventClient.Run(cmd.Context(), stop); err != nil {
						return err
					}
				}
			}

			logger.Info("server starts", zap.Int("port", c.Server.Port))
			return server.Start()
		},
	}

	// For local usage
	clientcmd.BindOverrideFlags(&c.KubeConfig, cmd.Flags(), clientcmd.RecommendedConfigOverrideFlags("kube-"))

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "target configuration file")
	cmd.Flags().StringVar(&c.LeaderElection.LockName, "lease-name", "kyverno-plugin", "name of the LeaseLock")
	cmd.Flags().IntVar(&c.Server.Port, "port", 8080, "Kyverno Plugin server port")
	cmd.Flags().BoolVar(&c.Local, "local", false, "use kube config to connect to cluster")
	flag.Parse()

	return cmd
}
