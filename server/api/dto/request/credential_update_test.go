package request_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/api/validators"
)

func TestUpdateCredentialValidation(t *testing.T) {
	for _, tt := range []struct {
		body  string
		valid bool
	}{
		{`{"name":"Renamed"}`, true},
		{`{"is_mfa":false}`, true},
		{`{"is_mfa":true}`, true},
		{`{"name":"Renamed","is_mfa":false}`, true},
		{`{}`, false},
		{`{"unknown":true}`, false},
		{`{"is_mfa":null}`, false},
		{`{"name":null}`, false},
		{`{"name":""}`, false},
		{`{"name":"","is_mfa":false}`, false},
		{`{"is_mfa":"false"}`, false},
		{`{"is_mfa":0}`, false},
	} {
		t.Run(tt.body, func(t *testing.T) {
			dto := request.UpdateCredentialsDto{CredentialId: "credential"}
			err := json.Unmarshal([]byte(tt.body), &dto)
			if err == nil {
				err = validators.NewCustomValidator().Validate(dto)
			}
			if tt.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
