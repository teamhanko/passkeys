package auditlog

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	zeroLogger "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"github.com/teamhanko/passkey-server/persistence/models"
)

func TestCredentialAuditConsoleDetails(t *testing.T) {
	var output bytes.Buffer
	previousLogger := zeroLogger.Logger
	zeroLogger.Logger = zerolog.New(&output)
	t.Cleanup(func() { zeroLogger.Logger = previousLogger })
	ctx := echo.New().NewContext(httptest.NewRequest("PATCH", "/", nil), httptest.NewRecorder())
	l := NewLogger(nil, models.AuditLogConfig{ConsoleEnabled: true}, ctx, &models.Tenant{ID: uuid.Must(uuid.NewV4())})
	old, current := true, false
	require.NoError(t, l.CreateWithConnection(nil, models.AuditLogWebAuthnCredentialUpdated, nil, nil, nil,
		models.CredentialAuditDetails{CredentialID: "credential", OldIsMFA: &old, NewIsMFA: &current}))
	var entry map[string]interface{}
	require.NoError(t, json.Unmarshal(output.Bytes(), &entry))
	require.Equal(t, "credential", entry["credential_id"])
	require.Equal(t, true, entry["old_is_mfa"])
	require.Equal(t, false, entry["new_is_mfa"])

	output.Reset()
	require.NoError(t, l.CreateWithConnection(nil, models.AuditLogWebAuthnCredentialUpdated, nil, nil, nil,
		models.CredentialAuditDetails{CredentialID: "credential"}))
	entry = nil
	require.NoError(t, json.Unmarshal(output.Bytes(), &entry))
	require.NotContains(t, entry, "old_is_mfa")
	require.NotContains(t, entry, "new_is_mfa")
}

func TestCredentialAuditJSON(t *testing.T) {
	id := "credential"
	old, current := true, false
	data, err := json.Marshal(models.AuditLog{CredentialID: &id, OldIsMFA: &old, NewIsMFA: &current})
	require.NoError(t, err)
	require.Contains(t, string(data), `"new_is_mfa":false`)
	data, err = json.Marshal(models.AuditLog{})
	require.NoError(t, err)
	require.NotContains(t, string(data), "is_mfa")
	require.NotContains(t, string(data), "credential_id")
}
