package persisters

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/gobuffalo/pop/v6"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type SecretsPersister interface {
	GetByName(name string, isApiSecret bool) (*models.Secret, error)
	Create(secret *models.Secret) error
	Delete(secret *models.Secret) error
	Update(secret *models.Secret) error
}

type secretsPersister struct {
	database *pop.Connection
}

func NewSecretsPersister(database *pop.Connection) SecretsPersister {
	return &secretsPersister{database: database}
}

func (sp secretsPersister) GetByName(name string, isApiSecret bool) (*models.Secret, error) {
	secret := &models.Secret{}
	err := sp.database.Where("name = ? AND is_api_secret = ?", name, isApiSecret).First(secret)

	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return secret, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get secrets: %w", err)
	}

	return secret, nil
}

func (sp secretsPersister) Create(secret *models.Secret) error {
	validationErr, err := sp.database.ValidateAndCreate(secret)
	if err != nil {
		return fmt.Errorf("failed to store secret: %w", err)
	}

	if validationErr != nil && validationErr.HasAny() {
		return fmt.Errorf("secret validation failed: %w", validationErr)
	}

	return nil
}

func (sp secretsPersister) Delete(secret *models.Secret) error {
	err := sp.database.Eager().Destroy(secret)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	return nil
}

func (sp secretsPersister) Update(secret *models.Secret) error {
	validationErr, err := sp.database.ValidateAndUpdate(secret)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	if validationErr != nil && validationErr.HasAny() {
		return fmt.Errorf("secret validation failed: %w", validationErr)
	}

	return nil
}
