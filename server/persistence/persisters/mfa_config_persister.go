package persisters

import (
	"fmt"

	"github.com/gobuffalo/pop/v6"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type MFAConfigPersister interface {
	Create(mfaConfig *models.MfaConfig) error
}

type mfaConfigPersister struct {
	database *pop.Connection
}

func NewMFAConfigPersister(database *pop.Connection) MFAConfigPersister {
	return &mfaConfigPersister{database: database}
}

func (mp *mfaConfigPersister) Create(mfaConfig *models.MfaConfig) error {
	validationErr, err := mp.database.ValidateAndCreate(mfaConfig)
	if err != nil {
		return fmt.Errorf("failed to store mfa config: %w", err)
	}

	if validationErr != nil && validationErr.HasAny() {
		return fmt.Errorf("mfa config validation failed: %w", validationErr)
	}

	return nil
}
