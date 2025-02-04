package config

import (
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/kubernetes/secrets"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/logging"
)

type BasicAuth struct {
	Username  string `mapstructure:"username"`
	Password  string `mapstructure:"password"`
	SecretRef string `mapstructure:"secretRef"`
}

type Server struct {
	Port      int       `mapstructure:"port"`
	Debug     bool      `mapstructure:"debug"`
	BasicAuth BasicAuth `mapstructure:"basicAuth"`
}

type CoreAPI struct {
	Host        string    `mapstructure:"host"`
	SkipTLS     bool      `mapstructure:"skipTLS"`
	Certificate string    `mapstructure:"certificate"`
	SecretRef   string    `mapstructure:"secretRef"`
	BasicAuth   BasicAuth `mapstructure:"basicAuth"`
}

func (a CoreAPI) FromValues(values secrets.Values) CoreAPI {
	if values.Host != "" {
		a.Host = values.Host
	}
	if values.Certificate != "" {
		a.Certificate = values.Certificate
	}
	if values.SkipTLS {
		a.SkipTLS = values.SkipTLS
	}
	if values.Username != "" {
		a.BasicAuth.Username = values.Username
	}
	if values.Password != "" {
		a.BasicAuth.Password = values.Password
	}

	return a
}

type Trivy struct {
	DBDir string `mapstructure:"dbDir"`
}

type Github struct {
	Token string `mapstructure:"token"`
}

type Config struct {
	KubeConfig clientcmd.ConfigOverrides
	Namespace  string         `mapstructure:"namespace"`
	Logging    logging.Config `mapstructure:"logging"`
	Server     Server         `mapstructure:"server"`
	Local      bool           `mapstructure:"local"`
	CoreAPI    CoreAPI        `mapstructure:"core"`
	Trivy      Trivy          `mapstructure:"trivy"`
	Github     Github         `mapstructure:"token"`
}
