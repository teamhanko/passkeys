package persisters

import (
	"fmt"

	"github.com/gobuffalo/pop/v6"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type WebauthnConfigPersister interface {
	Create(webauthnConfigModel *models.WebauthnConfig) error
}

type webauthnConfigPersister struct {
	database *pop.Connection
}

func NewWebauthnConfigPersister(database *pop.Connection) WebauthnConfigPersister {
	return &webauthnConfigPersister{database: database}
}

func (wp *webauthnConfigPersister) Create(webauthnConfigModel *models.WebauthnConfig) error {
	validationErr, err := wp.database.ValidateAndCreate(webauthnConfigModel)
	if err != nil {
		return fmt.Errorf("failed to store webauthnConfigModel: %w", err)
	}

	if validationErr != nil && validationErr.HasAny() {
		return fmt.Errorf("webauthnConfigModel validation failed: %w", validationErr)
	}

	return nil
}
