package cmd

import (
	"flag"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/config"
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

			resolver := config.NewResolver(c)
			logger := resolver.Logger()

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
	flag.Parse()

	return cmd
}
