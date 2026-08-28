// Package logging builds the application's zap logger.
package logging

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Config controls logger construction.
type Config struct {
	// Level is one of debug, info, warn, error. Defaults to info.
	Level string
	// Development enables a human-readable console encoder instead of JSON.
	Development bool
}

// New builds a zap.Logger from Config.
func New(cfg Config) (*zap.Logger, error) {
	level := zapcore.InfoLevel
	if cfg.Level != "" {
		if err := level.UnmarshalText([]byte(cfg.Level)); err != nil {
			return nil, err
		}
	}

	var zapCfg zap.Config
	if cfg.Development {
		zapCfg = zap.NewDevelopmentConfig()
	} else {
		zapCfg = zap.NewProductionConfig()
	}
	zapCfg.Level = zap.NewAtomicLevelAt(level)

	return zapCfg.Build()
}
