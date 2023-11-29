package persisters

import (
	"fmt"

	"github.com/gobuffalo/pop/v6"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type WebauthnRelyingPartyPersister interface {
	Create(relyingParty *models.RelyingParty) error
}

type webauthnRelyingPartyPersister struct {
	database *pop.Connection
}

func NewWebauthnRelyingPartyPersister(database *pop.Connection) WebauthnRelyingPartyPersister {
	return &webauthnRelyingPartyPersister{database: database}
}

func (wp *webauthnRelyingPartyPersister) Create(relyingParty *models.RelyingParty) error {
	validationErr, err := wp.database.Eager().ValidateAndCreate(relyingParty)
	if err != nil {
		return fmt.Errorf("failed to store relying party: %w", err)
	}

	if validationErr != nil && validationErr.HasAny() {
		return fmt.Errorf("relying party validation failed: %w", validationErr)
	}

	return nil
}
