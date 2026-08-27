package config

import (
	"errors"
	"strings"

	"github.com/spf13/viper"
)

// Load reads configuration from the YAML file at path (or ./config.yaml if
// path is empty and that file exists), then applies environment variable
// overrides of the form SECTION_FIELD (e.g. SERVER_PORT, WEBHOOK_WORKERS),
// on top of Default().
func Load(path string) (Config, error) {
	cfg := Default()

	v := viper.New()
	v.SetConfigType("yaml")
	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath(".")
	}

	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var notFound viper.ConfigFileNotFoundError
	if err := v.ReadInConfig(); err != nil && !errors.As(err, &notFound) {
		return cfg, err
	}

	if err := v.Unmarshal(&cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}
