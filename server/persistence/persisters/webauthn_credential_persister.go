package persisters

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/gofrs/uuid"

	"github.com/gobuffalo/pop/v6"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type WebauthnCredentialPersister interface {
	Get(id string, tenantId uuid.UUID) (*models.WebauthnCredential, error)
	Create(credential *models.WebauthnCredential) error
	Update(credential *models.WebauthnCredential) error
	Delete(credential *models.WebauthnCredential) error
	GetFromUser(string, uuid.UUID) ([]models.WebauthnCredential, error)
}

type webauthnCredentialPersister struct {
	database *pop.Connection
}

func NewWebauthnCredentialPersister(database *pop.Connection) WebauthnCredentialPersister {
	return &webauthnCredentialPersister{
		database: database,
	}
}

func (w *webauthnCredentialPersister) Get(id string, tenantId uuid.UUID) (*models.WebauthnCredential, error) {
	credential := models.WebauthnCredential{}
	err := w.database.
		Where("webauthn_credentials.id = ? AND u.tenant_id = ?", id, tenantId).
		LeftJoin("webauthn_users u", "u.id = webauthn_credentials.webauthn_user_id").
		First(&credential)

	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	return &credential, nil
}

func (w *webauthnCredentialPersister) Create(credential *models.WebauthnCredential) error {
	vErr, err := w.database.ValidateAndCreate(credential)
	if err != nil {
		return fmt.Errorf("failed to store credential: %w", err)
	}

	if vErr != nil && vErr.HasAny() {
		return fmt.Errorf("credential object validation failed: %w", vErr)
	}

	return nil
}

func (w *webauthnCredentialPersister) Update(credential *models.WebauthnCredential) error {
	vErr, err := w.database.ValidateAndUpdate(credential)
	if err != nil {
		return fmt.Errorf("failed to update credential: %w", err)
	}

	if vErr != nil && vErr.HasAny() {
		return fmt.Errorf("credential object validation failed: %w", vErr)
	}

	return nil
}

func (w *webauthnCredentialPersister) Delete(credential *models.WebauthnCredential) error {
	err := w.database.Destroy(credential)
	if err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	return nil
}

func (w *webauthnCredentialPersister) GetFromUser(userId string, tenantId uuid.UUID) ([]models.WebauthnCredential, error) {
	var credentials []models.WebauthnCredential
	err := w.database.Eager().
		Where("webauthn_credentials.user_id = ? AND u.tenant_id = ?", &userId, tenantId).
		LeftJoin("webauthn_users u", "u.id = webauthn_credentials.webauthn_user_id").
		Order("created_at asc").All(&credentials)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return credentials, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	return credentials, nil
}
