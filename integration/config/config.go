package config

import (
	trivyconfig "github.com/aquasecurity/trivy/internal/standalone/config"
)

// Config ...
type Config struct {
	TrivyConfig trivyconfig.Config
}

// NewDbConfig ...
func NewDbConfig(dir string) (*Config, error) {
	config := &Config{}
	trivyConfig, err := trivyconfig.NewDbConfig(dir)
	if err != nil {
		panic(err)
	}
	config.TrivyConfig = trivyConfig
	return config, err
}

// NewConfig ...
func NewConfig(dir string) (*Config, error) {
	config := &Config{}
	trivyConfig, err := trivyconfig.NewConfig(dir)
	if err != nil {
		panic(err)
	}
	config.TrivyConfig = trivyConfig
	return config, err
}
