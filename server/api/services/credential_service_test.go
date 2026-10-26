package services

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"github.com/teamhanko/passkey-server/api/dto/request"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
)

type credentialUpdateStore struct {
	persisters.WebauthnCredentialPersister
	credential  *models.WebauthnCredential
	tenantID    uuid.UUID
	updated     bool
	updateError error
}

func (s *credentialUpdateStore) Get(id string, tenantID uuid.UUID) (*models.WebauthnCredential, error) {
	if tenantID != s.tenantID || id != s.credential.ID {
		return nil, nil
	}
	c := *s.credential
	return &c, nil
}

func (s *credentialUpdateStore) Update(c *models.WebauthnCredential) error {
	if s.updateError != nil {
		return s.updateError
	}
	s.updated = true
	s.credential = c
	return nil
}

func TestCredentialUpdate(t *testing.T) {
	newName := "New name"
	yes, no := true, false
	for _, tt := range []struct {
		name         string
		initialMFA   bool
		newMFA       *bool
		newName      *string
		expectedMFA  bool
		expectedName string
	}{
		{"enable standalone login", true, &no, nil, false, "Original"},
		{"restrict to MFA", false, &yes, nil, true, "Original"},
		{"rename preserves MFA", true, nil, &newName, true, newName},
		{"rename preserves passkey", false, nil, &newName, false, newName},
		{"update both", true, &no, &newName, false, newName},
		{"idempotent false", false, &no, nil, false, "Original"},
		{"idempotent true", true, &yes, nil, true, "Original"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			name := "Original"
			tenant := models.Tenant{ID: uuid.Must(uuid.NewV4())}
			store := &credentialUpdateStore{tenantID: tenant.ID, credential: &models.WebauthnCredential{ID: "credential", Name: &name, IsMFA: tt.initialMFA, PublicKey: "unchanged"}}
			ctx := echo.New().NewContext(httptest.NewRequest("PATCH", "/", nil), httptest.NewRecorder())
			service := NewCredentialService(ctx, tenant, store)
			result, err := service.Update(request.UpdateCredentialsDto{CredentialId: "credential", Name: tt.newName, IsMFA: tt.newMFA})
			require.NoError(t, err)
			require.True(t, store.updated)
			require.Equal(t, tt.expectedMFA, result.IsMFA)
			require.Equal(t, tt.initialMFA, result.PreviousIsMFA)
			require.Equal(t, tt.expectedName, *result.Name)
			require.Equal(t, "unchanged", result.PublicKey)
		})
	}
}

func TestCredentialUpdateFailure(t *testing.T) {
	for _, reason := range []string{"other tenant", "missing credential", "persistence failure"} {
		t.Run(reason, func(t *testing.T) {
			tenant := models.Tenant{ID: uuid.Must(uuid.NewV4())}
			store := &credentialUpdateStore{tenantID: tenant.ID, credential: &models.WebauthnCredential{ID: "credential", IsMFA: true}}
			id := "credential"
			if reason == "other tenant" {
				store.tenantID = uuid.Must(uuid.NewV4())
			}
			if reason == "missing credential" {
				id = "missing"
			}
			if reason == "persistence failure" {
				store.updateError = errors.New("write failed")
			}
			ctx := echo.New().NewContext(httptest.NewRequest("PATCH", "/", nil), httptest.NewRecorder())
			no := false
			_, err := NewCredentialService(ctx, tenant, store).Update(request.UpdateCredentialsDto{CredentialId: id, IsMFA: &no})
			require.Error(t, err)
			require.False(t, store.updated)
			require.True(t, store.credential.IsMFA)
		})
	}
}
