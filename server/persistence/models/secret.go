package models

import (
	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/validate/v3"
	"github.com/gobuffalo/validate/v3/validators"
	"github.com/gofrs/uuid"
	"time"
)

// Secret is used by pop to map your api_keys database table to your go code.
type Secret struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Key         string    `json:"key" db:"key"`
	IsAPISecret bool      `json:"is_api_secret" db:"is_api_secret"`
	ConfigID    uuid.UUID `json:"config_id" db:"config_id"`
	Config      *Config   `json:"config" belongs_to:"configs"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Secrets is not required by pop and may be deleted
type Secrets []Secret

// Validate gets run every time you call a "pop.Validate*" (pop.ValidateAndSave, pop.ValidateAndCreate, pop.ValidateAndUpdate) method.
// This method is not required and may be deleted.
func (secret *Secret) Validate(tx *pop.Connection) (*validate.Errors, error) {
	return validate.Validate(
		&validators.UUIDIsPresent{Name: "ID", Field: secret.ID},
		&validators.StringIsPresent{Name: "Name", Field: secret.Name},
		&validators.StringIsPresent{Name: "Key", Field: secret.Key},
		&validators.TimeIsPresent{Name: "UpdatedAt", Field: secret.UpdatedAt},
		&validators.TimeIsPresent{Name: "CreatedAt", Field: secret.CreatedAt},
	), nil
}
