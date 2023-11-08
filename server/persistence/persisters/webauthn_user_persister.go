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
	Get(id uuid.UUID) (*models.WebauthnUser, error)
	GetByUserId(userId uuid.UUID, tenantId uuid.UUID) (*models.WebauthnUser, error)
	Delete(webauthnUser *models.WebauthnUser) error
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
		fmt.Printf("%s", err.Error())
		return fmt.Errorf("failed to store webauthn user: %w", err)
	}
	if vErr != nil && vErr.HasAny() {
		fmt.Printf("%s", vErr.Error())
		fmt.Printf("Debug: %v", webauthnUser)
		return fmt.Errorf("webauthn user object validation failed: %w", vErr)
	}

	return nil
}

func (p *webauthnUserPersister) Get(id uuid.UUID) (*models.WebauthnUser, error) {
	webauthnUser := models.WebauthnUser{}
	err := p.database.Eager().Find(&webauthnUser, id)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get webauthn user: %w", err)
	}

	return &webauthnUser, nil
}

func (p *webauthnUserPersister) Delete(webauthnUser *models.WebauthnUser) error {
	err := p.database.Eager().Destroy(webauthnUser)
	if err != nil {
		return fmt.Errorf("failed to delete auditlog: %w", err)
	}

	return nil
}

func (p *webauthnUserPersister) GetByUserId(userId uuid.UUID, tenantId uuid.UUID) (*models.WebauthnUser, error) {
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
