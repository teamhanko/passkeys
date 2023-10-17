package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseValidWebauthnConfig(t *testing.T) {
	// given
	configPath := "./testdata/webauthn-config.yaml"

	// when
	webauthnConfig, err := loadTestConfig[Webauthn](&configPath)

	// then
	if err != nil {
		t.Error(err)
	}
	assert.NotNil(t, webauthnConfig)
	assert.Equal(t, 1000, webauthnConfig.Timeout)
	assert.Equal(t, "preferred", webauthnConfig.UserVerification)
	assert.Equal(t, "localhost", webauthnConfig.RelyingParty.Id)
	assert.Equal(t, "Hanko Passkey Service", webauthnConfig.RelyingParty.DisplayName)
	assert.Equal(t, "lorem", webauthnConfig.RelyingParty.Icon)
	assert.Equal(t, "localhost:8000", webauthnConfig.RelyingParty.Origins[0])
	assert.Len(t, webauthnConfig.RelyingParty.Origins, 1)
}

func TestValidWebauthnConfig(t *testing.T) {
	// given
	webauthnConfig := &Webauthn{
		RelyingParty: RelyingParty{
			Id:          "localhost",
			DisplayName: "Hanko Passkey Service",
			Icon:        "Icon",
			Origins:     []string{"localhost"},
		},
		Timeout:          1000,
		UserVerification: "preferred",
	}

	// when
	err := webauthnConfig.Validate()

	// then
	assert.Nil(t, err)
}

func TestInvalidateWebauthnConfig(t *testing.T) {
	tests := []struct {
		name             string
		userVerification string
		origins          []string
		expectedError    string
	}{
		{
			name:             "error on nonexistent user verification",
			userVerification: "none",
			origins:          []string{"localhost"},
			expectedError:    "expected user_verification to be one of",
		},
		{
			name:             "error on empty origins",
			userVerification: "preferred",
			origins:          make([]string, 0),
			expectedError:    "at least one origin must be defined",
		},
	}

	for _, testData := range tests {
		// given
		webauthnConfig := &Webauthn{
			RelyingParty: RelyingParty{
				Origins: testData.origins,
			},
			Timeout:          1000,
			UserVerification: testData.userVerification,
		}

		// when
		err := webauthnConfig.Validate()

		// then
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), testData.expectedError)
	}
}
