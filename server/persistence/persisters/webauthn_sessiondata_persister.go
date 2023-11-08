package persisters

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type WebauthnSessionDataPersister interface {
	Get(id uuid.UUID) (*models.WebauthnSessionData, error)
	GetByChallenge(challenge string, tenantId uuid.UUID) (*models.WebauthnSessionData, error)
	Create(sessionData models.WebauthnSessionData) error
	Update(sessionData models.WebauthnSessionData) error
	Delete(sessionData models.WebauthnSessionData) error
}

type webauthnSessionDataPersister struct {
	database *pop.Connection
}

func NewWebauthnSessionDataPersister(db *pop.Connection) WebauthnSessionDataPersister {
	return &webauthnSessionDataPersister{database: db}
}

func (w *webauthnSessionDataPersister) Get(id uuid.UUID) (*models.WebauthnSessionData, error) {
	sessionData := models.WebauthnSessionData{}
	err := w.database.Eager().Find(&sessionData, id)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get sessionData: %w", err)
	}

	return &sessionData, nil
}

func (w *webauthnSessionDataPersister) GetByChallenge(challenge string, tenantId uuid.UUID) (*models.WebauthnSessionData, error) {
	var sessionData []models.WebauthnSessionData
	err := w.database.Eager().Where("challenge = ? AND tenant_id = ?", challenge, tenantId).All(&sessionData)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get sessionData: %w", err)
	}

	if len(sessionData) <= 0 {
		return nil, nil
	}

	return &sessionData[0], nil
}

func (w *webauthnSessionDataPersister) Create(sessionData models.WebauthnSessionData) error {
	vErr, err := w.database.Eager().ValidateAndCreate(&sessionData)
	if err != nil {
		return fmt.Errorf("failed to store sessionData: %w", err)
	}

	if vErr != nil && vErr.HasAny() {
		return fmt.Errorf("sessionData object validation failed: %w", vErr)
	}

	return nil
}

func (w *webauthnSessionDataPersister) Update(sessionData models.WebauthnSessionData) error {
	vErr, err := w.database.Eager().ValidateAndUpdate(&sessionData)
	if err != nil {
		return fmt.Errorf("failed to update sessionData: %w", err)
	}

	if vErr != nil && vErr.HasAny() {
		return fmt.Errorf("sessionData object validation failed: %w", vErr)
	}

	return nil
}

func (w *webauthnSessionDataPersister) Delete(sessionData models.WebauthnSessionData) error {
	err := w.database.Destroy(&sessionData)
	if err != nil {
		return fmt.Errorf("failed to delete sessionData: %w", err)
	}

	return nil
}
