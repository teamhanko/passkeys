package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseValidServerConfig(t *testing.T) {
	// given
	configPath := "./testdata/server-config.yaml"

	// when
	serverConfig, err := loadTestConfig[Server](&configPath)

	// then
	if err != nil {
		t.Error(err)
	}
	assert.NotNil(t, serverConfig)
	assert.Equal(t, "http://localhost:8000", serverConfig.Address)
	assert.False(t, serverConfig.Cors.UnsafeWildcardOriginAllowed)
	assert.Len(t, serverConfig.Cors.AllowOrigins, 2)
	assert.Equal(t, "localhost:8000", serverConfig.Cors.AllowOrigins[0])
	assert.Equal(t, "localhost:8888", serverConfig.Cors.AllowOrigins[1])
}

func TestValidateServerConfig(t *testing.T) {
	// given
	serverConfig := &Server{
		Address: "localhost:8000",
		Cors: Cors{
			AllowOrigins:                []string{"localhost:8999"},
			UnsafeWildcardOriginAllowed: false,
		},
	}

	// when
	err := serverConfig.Validate()

	// then
	assert.Nil(t, err)
}

func TestFailingValidation(t *testing.T) {
	tests := []struct {
		name          string
		address       string
		cors          string
		expectedError string
	}{
		{
			name:          "error on empty address",
			address:       "",
			cors:          "localhost:8000",
			expectedError: "field Address must not be empty",
		},
		{
			name:          "error on wrong address",
			address:       "plappor",
			cors:          "localhost:8000",
			expectedError: "field Address must be formatted as 'host%zone:port', '[host]:port' or '[host%zone]:port'",
		},
		{
			name:          "error on cors wildcard",
			address:       "localhost:8000",
			cors:          "*",
			expectedError: "found wildcard '*' origin in server.cors.allow_origins, if this is intentional set server.cors.unsafe_wildcard_origin_allowed to true",
		},
	}

	for _, testData := range tests {
		t.Run(testData.name, func(t *testing.T) {
			// given
			serverConfig := &Server{
				Address: testData.address,
				Cors: Cors{
					AllowOrigins:                []string{testData.cors},
					UnsafeWildcardOriginAllowed: false,
				},
			}

			// when
			err := serverConfig.Validate()

			// then
			assert.NotNil(t, err)
			assert.Equal(t, testData.expectedError, err.Error())
		})
	}
}
