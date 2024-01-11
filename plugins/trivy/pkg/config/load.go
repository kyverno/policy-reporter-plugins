package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
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
	err := v.Unmarshal(c)

	return err
}
