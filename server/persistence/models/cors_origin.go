package models

import (
	"github.com/gobuffalo/validate/v3/validators"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/validate/v3"
	"github.com/gofrs/uuid"
)

// CorsOrigin is used by pop to map your cors_origins database table to your go code.
type CorsOrigin struct {
	ID        uuid.UUID `json:"id" db:"id"`
	Cors      *Cors     `json:"cors" belongs_to:"cors"`
	CorsID    uuid.UUID `json:"cors_id" db:"cors_id"`
	Origin    string    `json:"origin" db:"origin"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// CorsOrigins is not required by pop and may be deleted
type CorsOrigins []CorsOrigin

// Validate gets run every time you call a "pop.Validate*" (pop.ValidateAndSave, pop.ValidateAndCreate, pop.ValidateAndUpdate) method.
// This method is not required and may be deleted.
func (origin *CorsOrigin) Validate(tx *pop.Connection) (*validate.Errors, error) {
	return validate.Validate(
		&validators.UUIDIsPresent{Name: "ID", Field: origin.ID},
		&validators.StringIsPresent{Name: "Origin", Field: origin.Origin},
		&validators.TimeIsPresent{Name: "UpdatedAt", Field: origin.UpdatedAt},
		&validators.TimeIsPresent{Name: "CreatedAt", Field: origin.CreatedAt},
	), nil
}
