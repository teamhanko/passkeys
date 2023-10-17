package config

import (
	"fmt"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"reflect"
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
	assert.Equal(t, "60eb263e-1bfb-4e6b-818f-fdb9668f1504", cfg.ApiKey)
	assert.Equal(t, defaultConfig.Server.Address, cfg.Server.Address)
}

func TestMissingApiKeyFailure(t *testing.T) {
	// given
	cfg := NewConfig()

	// when
	err := cfg.Validate()

	// then
	assert.NotNil(t, err)
	assert.Equal(t, "api key needs to be defined and at least 32 bytes long", err.Error())
}

func TestEnvironmentVariables(t *testing.T) {
	err := os.Setenv("WEBAUTHN_RELYING_PARTY_ORIGINS", "https://hanko.io,https://auth.hanko.io")
	require.NoError(t, err)

	configPath := "./config.yaml"
	cfg, err := Load(&configPath)
	require.NoError(t, err)

	assert.True(t, reflect.DeepEqual([]string{"https://hanko.io", "https://auth.hanko.io"}, cfg.Webauthn.RelyingParty.Origins))
}
