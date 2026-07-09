package cmd

import (
	"flag"
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/config"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/logging"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/server"
	v1 "github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/server/vulnr/v1"
)

var configFile string

func newRunCMD() *cobra.Command {
	c := &config.Config{}

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run Policy Reporter Trivy Plugin",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := config.Load(c, configFile)
			if err != nil {
				return err
			}
			logger, err := logging.New(c.Logging)
			if err != nil {
				return fmt.Errorf("failed to setup logger: %w", err)
			}
			if err := config.SetupMemLimit(c); err != nil {
				return fmt.Errorf("failed to setup memlimit: %w", err)
			}

			resolver := config.NewResolver(c)

			coreAPI, err := resolver.CoreClient(cmd.Context())
			if err != nil {
				return err
			}

			service, err := resolver.VulnrService()
			if err != nil {
				return err
			}

			server, err := resolver.Server(cmd.Context(), []server.ServerOption{
				v1.WithAPI(coreAPI, service),
				server.WithPort(c.Server.Port),
			})
			if err != nil {
				return err
			}

			logger.Info("server starts", zap.Int("port", c.Server.Port))
			return server.Start()
		},
	}

	// For local usage
	clientcmd.BindOverrideFlags(&c.KubeConfig, cmd.Flags(), clientcmd.RecommendedConfigOverrideFlags("kube-"))

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "target configuration file")
	cmd.Flags().IntVar(&c.Server.Port, "port", 8080, "Trivy Plugin server port")
	cmd.Flags().BoolVar(&c.Local, "local", false, "use kube config to connect to cluster")
	cmd.Flags().BoolVar(&c.AutoMemoryLimit.Enabled, "auto-memory-enabled", true, "Enable automatic GOMEMLIMIT configuration based on container or system memory.")
	cmd.Flags().Float64Var(&c.AutoMemoryLimit.Ratio, "auto-memory-ratio", 0.9, "The ratio of reserved GOMEMLIMIT memory to the detected maximum container or system memory. Must be greater than 0 and less than or equal to 1.")
	flag.Parse()

	return cmd
}
