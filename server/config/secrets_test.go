package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseValidSecretsConfig(t *testing.T) {
	// given
	configPath := "./testdata/secrets-config.yaml"

	// when
	secretConfig, err := loadTestConfig[Secrets](&configPath)

	// then
	if err != nil {
		t.Error(err)
	}
	assert.NotNil(t, secretConfig)
	assert.Equal(t, 1, len(secretConfig.Keys))
	assert.Equal(t, "super-long-and-super-secret", secretConfig.Keys[0])
}

func TestSecretsValidate(t *testing.T) {
	// given
	secretsConfig := &Secrets{Keys: []string{"super-long-and-super-strong"}}

	// when
	err := secretsConfig.Validate()

	// then
	assert.Nil(t, err)
}

func TestSecretsValidateWithoutKeys(t *testing.T) {
	// given
	secretsConfig := &Secrets{Keys: make([]string, 0)}

	// when
	err := secretsConfig.Validate()

	// then
	assert.NotNil(t, err)
	assert.Equal(t, "at least one secret key must be defined", err.Error())
}
