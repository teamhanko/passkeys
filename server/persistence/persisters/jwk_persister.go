package persisters

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/gofrs/uuid"

	"github.com/gobuffalo/pop/v6"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type JwkPersister interface {
	GetAll() ([]models.Jwk, error)
	GetAllForTenant(tenantId uuid.UUID) ([]models.Jwk, error)
	GetLast(tenantId uuid.UUID) (*models.Jwk, error)
	Create(models.Jwk) error
	Delete(*models.Jwk) error
}

const (
	GetFailureMessageFormat = "failed to get jwk: %w"
)

type jwkPersister struct {
	db *pop.Connection
}

func NewJwkPersister(db *pop.Connection) JwkPersister {
	return &jwkPersister{db: db}
}

func (p *jwkPersister) GetAll() ([]models.Jwk, error) {
	var jwks []models.Jwk
	err := p.db.All(&jwks)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get all jwks: %w", err)
	}
	return jwks, nil
}

func (p *jwkPersister) GetAllForTenant(tenantId uuid.UUID) ([]models.Jwk, error) {
	var jwks []models.Jwk
	err := p.db.Where("tenant_id = ?", &tenantId).All(&jwks)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get all jwks: %w", err)
	}
	return jwks, nil
}

func (p *jwkPersister) GetLast(tenantId uuid.UUID) (*models.Jwk, error) {
	jwk := models.Jwk{}
	err := p.db.Where("tenant_id = ?", tenantId).Last(&jwk)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf(GetFailureMessageFormat, err)
	}
	return &jwk, nil
}

func (p *jwkPersister) Create(jwk models.Jwk) error {
	vErr, err := p.db.ValidateAndCreate(&jwk)
	if err != nil {
		return fmt.Errorf("failed to store jwk: %w", err)
	}

	if vErr != nil && vErr.HasAny() {
		return fmt.Errorf("jwk object validation failed: %w", vErr)
	}

	return nil
}

func (p *jwkPersister) Delete(jwk *models.Jwk) error {
	err := p.db.Destroy(jwk)

	if err != nil {
		return fmt.Errorf("failed to delete jwk: %w", err)
	}

	return nil
}
