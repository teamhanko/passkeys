package models

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gobuffalo/validate/v3/validators"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/validate/v3"
	"github.com/gofrs/uuid"
)

// WebauthnConfig is used by pop to map your webauthn_configs database table to your go code.
type WebauthnConfig struct {
	ID               uuid.UUID                            `json:"id" db:"id"`
	Config           *Config                              `json:"config" belongs_to:"configs"`
	ConfigID         uuid.UUID                            `json:"config_id" db:"config_id"`
	RelyingParty     RelyingParty                         `json:"relying_party" has_one:"relying_parties"`
	Timeout          int                                  `json:"timeout" db:"timeout"`
	CreatedAt        time.Time                            `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time                            `json:"updated_at" db:"updated_at"`
	UserVerification protocol.UserVerificationRequirement `json:"user_verification" db:"user_verification"`
}

// Validate gets run every time you call a "pop.Validate*" (pop.ValidateAndSave, pop.ValidateAndCreate, pop.ValidateAndUpdate) method.
// This method is not required and may be deleted.
func (webauthn *WebauthnConfig) Validate(tx *pop.Connection) (*validate.Errors, error) {
	return validate.Validate(
		&validators.UUIDIsPresent{Name: "ID", Field: webauthn.ID},
		&validators.IntIsPresent{Name: "Timeout", Field: webauthn.Timeout},
		&validators.StringIsPresent{Name: "UserVerification", Field: string(webauthn.UserVerification)},
		&validators.TimeIsPresent{Name: "UpdatedAt", Field: webauthn.UpdatedAt},
		&validators.TimeIsPresent{Name: "CreatedAt", Field: webauthn.CreatedAt},
	), nil
}
