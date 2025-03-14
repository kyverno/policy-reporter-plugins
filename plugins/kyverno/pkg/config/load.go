package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

func Load(c *Config, cfgFile string) error {
	v := viper.NewWithOptions(viper.KeyDelimiter("!"))

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.AddConfigPath(".")
		v.SetConfigName("config")
		v.AllKeys()
	}

	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		fmt.Printf("[INFO] No configuration file found: %v\n", err)
	}

	err := v.Unmarshal(c)
	if err != nil {
		return err
	}

	if c.LeaderElection.PodName == "" {
		c.LeaderElection.PodName = os.Getenv("POD_NAME")
	}

	if c.Namespace == "" {
		c.Namespace = os.Getenv("POD_NAMESPACE")
	}

	return nil
}
