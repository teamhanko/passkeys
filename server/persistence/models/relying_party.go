package models

import (
	"github.com/gobuffalo/validate/v3/validators"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/validate/v3"
	"github.com/gofrs/uuid"
)

// RelyingParty is used by pop to map your relying_parties database table to your go code.
type RelyingParty struct {
	ID               uuid.UUID       `json:"id" db:"id"`
	WebauthnConfig   *WebauthnConfig `json:"webauthn_config" belongs_to:"webauthn_configs"`
	WebauthnConfigID uuid.UUID       `json:"webauthn_config_id" db:"webauthn_config_id"`
	RPId             string          `json:"rp_id" db:"rp_id"`
	DisplayName      string          `json:"display_name" db:"display_name"`
	Icon             *string         `json:"icon" db:"icon"`
	Origins          WebauthnOrigins `json:"origins" has_many:"webauthn_origins"`
	CreatedAt        time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at" db:"updated_at"`
}

// RelyingParties is not required by pop and may be deleted
type RelyingParties []RelyingParty

// Validate gets run every time you call a "pop.Validate*" (pop.ValidateAndSave, pop.ValidateAndCreate, pop.ValidateAndUpdate) method.
// This method is not required and may be deleted.
func (rp *RelyingParty) Validate(tx *pop.Connection) (*validate.Errors, error) {
	return validate.Validate(
		&validators.UUIDIsPresent{Name: "ID", Field: rp.ID},
		&validators.StringIsPresent{Name: "RPId", Field: rp.RPId},
		&validators.StringIsPresent{Name: "DisplayName", Field: rp.DisplayName},
		&validators.TimeIsPresent{Name: "UpdatedAt", Field: rp.UpdatedAt},
		&validators.TimeIsPresent{Name: "CreatedAt", Field: rp.CreatedAt},
	), nil
}
