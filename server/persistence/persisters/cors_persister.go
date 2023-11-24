package persisters

import (
	"fmt"

	"github.com/gobuffalo/pop/v6"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type CorsPersister interface {
	Create(cors *models.Cors) error
}

type corsPersister struct {
	database *pop.Connection
}

func NewCorsPersister(database *pop.Connection) CorsPersister {
	return &corsPersister{database: database}
}

func (cp *corsPersister) Create(cors *models.Cors) error {
	validationErr, err := cp.database.Eager().ValidateAndCreate(cors)
	if err != nil {
		return fmt.Errorf("failed to store cors: %w", err)
	}

	if validationErr != nil && validationErr.HasAny() {
		return fmt.Errorf("cors validation failed: %w", validationErr)
	}

	return nil
}
