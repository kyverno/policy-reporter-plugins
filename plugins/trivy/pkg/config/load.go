package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func Load(c *Config, cfgFile string) error {
	v := viper.New()

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.AddConfigPath(".")
		v.SetConfigName("config")
	}

	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		fmt.Printf("[INFO] No configuration file found: %v\n", err)
	}

	if err := v.BindEnv("namespace", "POD_NAMESPACE"); err != nil {
		zap.L().Warn("failed to bind env POD_NAMESPACE")
	}

	err := v.Unmarshal(c)
	if err != nil {
		return err
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		c.Github.Token = token
	}

	return nil
}
