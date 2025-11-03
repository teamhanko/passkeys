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
	AllForTenant(tenantId uuid.UUID, page int, perPage int, sort string) (models.WebauthnUsers, error)
	Count(tenantId uuid.UUID) (int, error)
	GetById(id uuid.UUID) (*models.WebauthnUser, error)
	GetByUserId(userId string, tenantId uuid.UUID) (*models.WebauthnUser, error)
	Update(webauthnUser *models.WebauthnUser) error
	Delete(user *models.WebauthnUser) error
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

func (p *webauthnUserPersister) AllForTenant(tenantId uuid.UUID, page int, perPage int, sort string) (models.WebauthnUsers, error) {
	webauthnUsers := models.WebauthnUsers{}
	err := p.database.
		Where("tenant_id = ?", tenantId).
		Order(fmt.Sprintf("created_at %s", sort)).
		Paginate(page, perPage).
		All(&webauthnUsers)

	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return webauthnUsers, nil
	}

	if err != nil {
		return webauthnUsers, fmt.Errorf("failed to get webauthn users for tenant %w", err)
	}

	return webauthnUsers, nil
}

func (p *webauthnUserPersister) GetById(id uuid.UUID) (*models.WebauthnUser, error) {
	webauthnUser := models.WebauthnUser{}
	err := p.database.Eager().Find(&webauthnUser, id)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get webauthn user by id: %w", err)
	}

	return &webauthnUser, nil
}

func (p *webauthnUserPersister) GetByUserId(userId string, tenantId uuid.UUID) (*models.WebauthnUser, error) {
	webauthnUser := models.WebauthnUser{}
	err := p.database.Eager().Where("user_id = ? AND tenant_id = ?", userId, tenantId).First(&webauthnUser)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get webauthn user by user id: %w", err)
	}

	return &webauthnUser, nil
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

func (p *webauthnUserPersister) Delete(user *models.WebauthnUser) error {
	err := p.database.Destroy(user)
	if err != nil {
		return fmt.Errorf("failed to delete webauthn user: %w", err)
	}

	return nil
}

func (p *webauthnUserPersister) Count(tenantId uuid.UUID) (int, error) {
	count, err := p.database.Where("tenant_id = ?", tenantId).Count(&models.WebauthnUser{})
	if err != nil {
		return 0, fmt.Errorf("failed to get user count: %w", err)
	}

	return count, nil
}
