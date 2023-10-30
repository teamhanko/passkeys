package persisters

import (
	"fmt"
	"github.com/gobuffalo/pop/v6"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type ConfigPersister interface {
	Create(config *models.Config) error
	Delete(config *models.Config) error
}

type configPersister struct {
	database *pop.Connection
}

func NewConfigPersister(database *pop.Connection) ConfigPersister {
	return &configPersister{
		database: database,
	}
}

func (cp *configPersister) Create(config *models.Config) error {
	validationErr, err := cp.database.ValidateAndCreate(config)
	if err != nil {
		return fmt.Errorf("failed to store config: %w", err)
	}

	if validationErr != nil && validationErr.HasAny() {
		return fmt.Errorf("config validation failed: %w", validationErr)
	}

	return nil
}

func (cp *configPersister) Delete(config *models.Config) error {
	err := cp.database.Eager().Destroy(config)
	if err != nil {
		return fmt.Errorf("failed to delete config: %w", err)
	}

	return nil
}
