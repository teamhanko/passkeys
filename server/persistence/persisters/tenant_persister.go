package persisters

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type TenantPersister interface {
	Create(tenant *models.Tenant) error
	Get(tenantId uuid.UUID) (*models.Tenant, error)
	List() (models.Tenants, error)
	Update(tenant *models.Tenant) error
	Delete(tenant *models.Tenant) error
}

type tenantPersister struct {
	database *pop.Connection
}

func NewTenantPersister(database *pop.Connection) TenantPersister {
	return &tenantPersister{database: database}
}

func (t tenantPersister) Create(tenant *models.Tenant) error {
	validationErr, err := t.database.ValidateAndCreate(tenant)
	if err != nil {
		return fmt.Errorf("failed to store tenant: %w", err)
	}

	if validationErr != nil && validationErr.HasAny() {
		return fmt.Errorf("tenant validation failed: %w", validationErr)
	}

	return nil
}

func (t tenantPersister) Get(tenantId uuid.UUID) (*models.Tenant, error) {
	tenant := models.Tenant{}
	err := t.database.Eager(
		"Config.Secrets",
		"Config.WebauthnConfigs.RelyingParty.Origins",
		"Config.Cors.Origins",
		"Config.AuditLogConfig",
	).Find(&tenant, tenantId)

	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	return &tenant, nil
}

func (t tenantPersister) List() (models.Tenants, error) {
	tenants := models.Tenants{}
	err := t.database.All(&tenants)

	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return tenants, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get tenants: %w", err)
	}

	return tenants, nil
}

func (t tenantPersister) Update(tenant *models.Tenant) error {
	validationErr, err := t.database.ValidateAndUpdate(tenant)
	if err != nil {
		return fmt.Errorf("failed to store tenant: %w", err)
	}

	if validationErr != nil && validationErr.HasAny() {
		return fmt.Errorf("tenant validation failed: %w", validationErr)
	}

	return nil
}

func (t tenantPersister) Delete(tenant *models.Tenant) error {
	err := t.database.Destroy(tenant)
	if err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	return nil
}
