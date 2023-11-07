package models

import (
	"github.com/gobuffalo/validate/v3/validators"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/validate/v3"
	"github.com/gofrs/uuid"
)

// Tenant is used by pop to map your tenants database table to your go code.
type Tenant struct {
	ID          uuid.UUID `json:"id" db:"id"`
	DisplayName string    `json:"display_name" db:"display_name"`

	Config        Config                `json:"config" has_one:"config"`
	AuditLogs     AuditLogs             `json:"audit_logs,omitempty" has_many:"audit_logs"`
	Jwks          Jwks                  `json:"jwks,omitempty" has_many:"jwks"`
	SessionData   []WebauthnSessionData `has_many:"webauthn_session_data"`
	WebauthnUsers WebauthnUsers         `json:"webauthn_users,omitempty" has_many:"webauthn_users"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Tenants is not required by pop and may be deleted
type Tenants []Tenant

// Validate gets run every time you call a "pop.Validate*" (pop.ValidateAndSave, pop.ValidateAndCreate, pop.ValidateAndUpdate) method.
// This method is not required and may be deleted.
func (tenant *Tenant) Validate(tx *pop.Connection) (*validate.Errors, error) {
	return validate.Validate(
		&validators.UUIDIsPresent{Name: "ID", Field: tenant.ID},
		&validators.StringIsPresent{Name: "DisplayName", Field: tenant.DisplayName},
		&validators.TimeIsPresent{Name: "UpdatedAt", Field: tenant.UpdatedAt},
		&validators.TimeIsPresent{Name: "CreatedAt", Field: tenant.CreatedAt},
	), nil
}
