package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseValidDatabaseConfig(t *testing.T) {
	// given
	configPath := "./testdata/database-config.yaml"

	// when
	databaseConfig, err := loadTestConfig[Database](&configPath)

	// then
	if err != nil {
		t.Error(err)
	}
	assert.NotNil(t, databaseConfig)
	assert.Equal(t, "hanko", databaseConfig.Database)
	assert.Equal(t, "test", databaseConfig.User)
	assert.Equal(t, "strong-password", databaseConfig.Password)
	assert.Equal(t, "3456", databaseConfig.Port)
	assert.Equal(t, "postgres", databaseConfig.Dialect)
	assert.Equal(t, "postgres://test@localhost:3456/postgres", databaseConfig.Url)
}

func TestDatabaseValidation(t *testing.T) {
	tests := []struct {
		name          string
		database      string
		user          string
		password      string
		host          string
		port          string
		dialect       string
		url           string
		expectedError string
	}{
		{
			name:          "error on missing database",
			database:      "",
			user:          "test",
			password:      "strong-password",
			host:          "localhost",
			port:          "3456",
			dialect:       "postgres",
			expectedError: "database must not be empty",
		},
		{
			name:          "error on missing user",
			database:      "hanko",
			user:          "",
			port:          "3456",
			dialect:       "postgres",
			expectedError: "user must not be empty",
		},
		{
			name:          "error on missing host",
			database:      "hanko",
			user:          "test",
			password:      "strong-password",
			host:          "",
			port:          "3456",
			dialect:       "postgres",
			expectedError: "host must not be empty",
		},
		{
			name:          "error on missing port",
			database:      "hanko",
			user:          "test",
			password:      "strong-password",
			host:          "localhost",
			port:          "",
			dialect:       "postgres",
			expectedError: "port must not be empty",
		},
		{
			name:          "error on missing dialect",
			database:      "hanko",
			user:          "test",
			password:      "strong-password",
			host:          "localhost",
			port:          "3456",
			dialect:       "",
			expectedError: "dialect must not be empty",
		},
	}

	for _, testData := range tests {
		t.Run(testData.name, func(t *testing.T) {
			// given
			cfg := &Database{
				Database: testData.database,
				User:     testData.user,
				Password: testData.password,
				Host:     testData.host,
				Port:     testData.port,
				Dialect:  testData.dialect,
				Url:      "",
			}

			// when
			err := cfg.Validate()

			// then
			assert.NotNil(t, err)
			assert.Equal(t, testData.expectedError, err.Error())
		})
	}
}

func TestDatabaseValidations(t *testing.T) {
	// given
	cfg := &Database{
		Database: "hanko",
		User:     "test",
		Password: "strong-password",
		Host:     "localhost",
		Port:     "3456",
		Dialect:  "postgres",
		Url:      "",
	}

	// when
	err := cfg.Validate()

	// then
	assert.Nil(t, err)
}

func TestDatabaseValidationWithUrl(t *testing.T) {
	// given
	databaseConfig := &Database{
		Url: "postgres://test@localhost:3456",
	}

	// when
	err := databaseConfig.Validate()

	// then
	assert.NotNil(t, databaseConfig)
	assert.Nil(t, err)
	assert.Equal(t, "", databaseConfig.Database)
	assert.Equal(t, "", databaseConfig.User)
	assert.Equal(t, "", databaseConfig.Password)
	assert.Equal(t, "", databaseConfig.Port)
	assert.Equal(t, "", databaseConfig.Dialect)
}
