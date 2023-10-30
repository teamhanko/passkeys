package models

import (
	"github.com/gobuffalo/validate/v3/validators"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/validate/v3"
	"github.com/gofrs/uuid"
)

// WebauthnOrigin is used by pop to map your webauthn_origins database table to your go code.
type WebauthnOrigin struct {
	ID             uuid.UUID     `json:"id" db:"id"`
	RelyingParty   *RelyingParty `json:"relying_party" belongs_to:"relying_parties"`
	RelyingPartyID uuid.UUID     `json:"relying_party_id" db:"relying_party_id"`
	Origin         string        `json:"origin" db:"origin"`
	CreatedAt      time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at" db:"updated_at"`
}

// WebauthnOrigins is not required by pop and may be deleted
type WebauthnOrigins []WebauthnOrigin

// Validate gets run every time you call a "pop.Validate*" (pop.ValidateAndSave, pop.ValidateAndCreate, pop.ValidateAndUpdate) method.
// This method is not required and may be deleted.
func (origin *WebauthnOrigin) Validate(tx *pop.Connection) (*validate.Errors, error) {
	return validate.Validate(
		&validators.UUIDIsPresent{Name: "ID", Field: origin.ID},
		&validators.StringIsPresent{Name: "Origin", Field: origin.Origin},
		&validators.TimeIsPresent{Name: "UpdatedAt", Field: origin.UpdatedAt},
		&validators.TimeIsPresent{Name: "CreatedAt", Field: origin.CreatedAt},
	), nil
}
