package config

import (
	"fmt"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/stretchr/testify/assert"
	"testing"
)

func loadTestConfig[I interface{}](configPath *string) (*I, error) {
	k := koanf.New(".")

	var err error

	if err = k.Load(file.Provider(*configPath), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("failed to load config from: %s: %w", *configPath, err)
	}

	c := new(I)
	err = k.Unmarshal("", &c)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return c, nil
}

func TestDefaultConfigNotEnoughForValidation(t *testing.T) {
	// given
	cfg := NewConfig()

	// when
	if err := cfg.Validate(); err == nil {

		// then
		t.Error("The default config is missing mandatory parameters. This should not validate without error.")
	}
}

func TestMinimalConfigValidates(t *testing.T) {
	// given
	configPath := "./config.yaml"

	// when
	cfg, err := Load(&configPath)

	// then
	if err != nil {
		t.Error(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Error(err)
	}
}

func TestLoadingMinimalConfig(t *testing.T) {
	// given
	configPath := "./config.yaml"
	defaultConfig := NewConfig()

	// when
	cfg, err := Load(&configPath)
	if err != nil {
		t.Error(err)
	}

	assert.NotNil(t, cfg)
	assert.Equal(t, defaultConfig.Address, cfg.Address)
}

func TestMissingApiKeyFailure(t *testing.T) {
	// given
	cfg := NewConfig()

	// when
	err := cfg.Validate()

	// then
	assert.NotNil(t, err)
	assert.Equal(t, "at least one api key must be defined", err.Error())
}
