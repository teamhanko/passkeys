package models

import (
	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/validate/v3"
	"github.com/gobuffalo/validate/v3/validators"
	"time"

	"github.com/gofrs/uuid"
)

// Config is used by pop to map your tenant_configs database table to your go code.
type Config struct {
	ID       uuid.UUID `json:"id" db:"id"`
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Tenant   *Tenant   `json:"tenant,omitempty" belongs_to:"tenant"`

	WebauthnConfigs []WebauthnConfig `json:"webauthn_config,omitempty" has_many:"webauthn_config"`
	Cors            Cors             `json:"cors,omitempty" has_one:"cor"`
	AuditLogConfig  AuditLogConfig   `json:"audit_log_config,omitempty" has_one:"audit_log_config"`
	Secrets         Secrets          `json:"secrets,omitempty" has_many:"secrets"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Validate gets run every time you call a "pop.Validate*" (pop.ValidateAndSave, pop.ValidateAndCreate, pop.ValidateAndUpdate) method.
// This method is not required and may be deleted.
func (config *Config) Validate(tx *pop.Connection) (*validate.Errors, error) {
	return validate.Validate(
		&validators.UUIDIsPresent{Name: "ID", Field: config.ID},
		&validators.TimeIsPresent{Name: "UpdatedAt", Field: config.UpdatedAt},
		&validators.TimeIsPresent{Name: "CreatedAt", Field: config.CreatedAt},
	), nil
}
