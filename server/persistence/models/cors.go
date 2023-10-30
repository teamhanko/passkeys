package models

import (
	"github.com/gobuffalo/validate/v3/validators"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/validate/v3"
	"github.com/gofrs/uuid"
)

// Cors is used by pop to map your cors database table to your go code.
type Cors struct {
	ID          uuid.UUID   `json:"id" db:"id"`
	Config      *Config     `json:"config" belongs_to:"configs"`
	ConfigID    uuid.UUID   `json:"config_id" db:"config_id"`
	AllowUnsafe bool        `json:"allow_unsafe" db:"allow_unsafe"`
	Origins     CorsOrigins `json:"origins" has_many:"cors_origins"`
	CreatedAt   time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at" db:"updated_at"`
}

// Validate gets run every time you call a "pop.Validate*" (pop.ValidateAndSave, pop.ValidateAndCreate, pop.ValidateAndUpdate) method.
// This method is not required and may be deleted.
func (cors *Cors) Validate(tx *pop.Connection) (*validate.Errors, error) {
	return validate.Validate(
		&validators.UUIDIsPresent{Name: "ID", Field: cors.ID},
		&validators.TimeIsPresent{Name: "UpdatedAt", Field: cors.UpdatedAt},
		&validators.TimeIsPresent{Name: "CreatedAt", Field: cors.CreatedAt},
	), nil
}
