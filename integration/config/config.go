package config

import (
	trivyconfig "github.com/aquasecurity/trivy/internal/artifact/config"
)

// Config ...
type Config struct {
	TrivyConfig trivyconfig.Config
}

// NewConfig ...
func NewConfig(dir string) (*Config, error) {
	config := &Config{}

	trivyConfig, err := trivyconfig.NewTrivyConfig(dir)
	if err != nil {
		panic(err)
	}

	err = trivyConfig.InitTrivy()
	if err != nil {
		panic(err)
	}

	config.TrivyConfig = trivyConfig

	return config, err
}
