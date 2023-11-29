package persisters

import (
	"fmt"

	"github.com/gobuffalo/pop/v6"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type SecretsPersister interface {
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
