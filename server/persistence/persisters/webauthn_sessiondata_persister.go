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
	GetByChallenge(challenge string, tenantId uuid.UUID) (*models.WebauthnSessionData, error)
	Create(sessionData models.WebauthnSessionData) error
	Delete(sessionData models.WebauthnSessionData) error
}

type sessionDataPersister struct {
	database *pop.Connection
}

func NewWebauthnSessionDataPersister(db *pop.Connection) WebauthnSessionDataPersister {
	return &sessionDataPersister{database: db}
}

func (ws *sessionDataPersister) GetByChallenge(challenge string, tenantId uuid.UUID) (*models.WebauthnSessionData, error) {
	var sessionData []models.WebauthnSessionData
	err := ws.database.Eager().Where("challenge = ? AND tenant_id = ?", challenge, tenantId).All(&sessionData)
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

func (ws *sessionDataPersister) Create(sessionData models.WebauthnSessionData) error {
	vErr, err := ws.database.Eager().ValidateAndCreate(&sessionData)
	if err != nil {
		return fmt.Errorf("failed to store sessionData: %w", err)
	}

	if vErr != nil && vErr.HasAny() {
		return fmt.Errorf("sessionData object validation failed: %w", vErr)
	}

	return nil
}

func (ws *sessionDataPersister) Delete(sessionData models.WebauthnSessionData) error {
	err := ws.database.Destroy(&sessionData)
	if err != nil {
		return fmt.Errorf("failed to delete sessionData: %w", err)
	}

	return nil
}
