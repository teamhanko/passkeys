package models

import (
	"github.com/gofrs/uuid"
	"time"

	"github.com/gobuffalo/validate/v3/validators"

	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/validate/v3"
)

// Jwk is used by pop to map your jwks database table to your go code.
type Jwk struct {
	ID       int       `json:"id" db:"id"`
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Tenant   *Tenant   `json:"tenant" belongs_to:"tenants"`
	KeyData  string    `json:"key_data" db:"key_data"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type Jwks []Jwk

func (jwk *Jwk) Validate(tx *pop.Connection) (*validate.Errors, error) {
	return validate.Validate(
		&validators.StringIsPresent{Name: "KeyData", Field: jwk.KeyData},
		&validators.TimeIsPresent{Name: "CreatedAt", Field: jwk.CreatedAt},
	), nil
}
