package persisters

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type WebauthnUserPersister interface {
	Create(webauthnUser *models.WebauthnUser) error
	GetByUserId(userId string, tenantId uuid.UUID) (*models.WebauthnUser, error)
	Update(webauthnUser *models.WebauthnUser) error
}

type webauthnUserPersister struct {
	database *pop.Connection
}

func NewWebauthnUserPersister(database *pop.Connection) WebauthnUserPersister {
	return &webauthnUserPersister{
		database: database,
	}
}

func (p *webauthnUserPersister) Create(webauthnUser *models.WebauthnUser) error {
	vErr, err := p.database.ValidateAndCreate(webauthnUser)
	if err != nil {
		return fmt.Errorf("failed to store webauthn user: %w", err)
	}
	if vErr != nil && vErr.HasAny() {
		return fmt.Errorf("webauthn user object validation failed: %w", vErr)
	}

	return nil
}

func (p *webauthnUserPersister) GetByUserId(userId string, tenantId uuid.UUID) (*models.WebauthnUser, error) {
	weauthnUser := models.WebauthnUser{}
	err := p.database.Eager().Where("user_id = ? AND tenant_id = ?", userId, tenantId).First(&weauthnUser)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get webauthn user by user id: %w", err)
	}

	return &weauthnUser, nil
}

func (p *webauthnUserPersister) Update(webauthnUser *models.WebauthnUser) error {
	vErr, err := p.database.ValidateAndUpdate(webauthnUser)
	if err != nil {
		return fmt.Errorf("failed to update webauthn user: %w", err)
	}

	if vErr != nil && vErr.HasAny() {
		return fmt.Errorf("webauthn user object validation failed: %w", vErr)
	}

	return nil
}
