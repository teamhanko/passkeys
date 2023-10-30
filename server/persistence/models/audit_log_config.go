package models

import (
	"github.com/gobuffalo/validate/v3/validators"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/validate/v3"
	"github.com/gofrs/uuid"
)

// AuditLogConfig is used by pop to map your audit_log_configs database table to your go code.
type AuditLogConfig struct {
	ID             uuid.UUID `json:"id" db:"id"`
	Config         *Config   `json:"config" belongs_to:"configs"`
	ConfigID       uuid.UUID `json:"config_id" db:"config_id"`
	OutputStream   string    `json:"output_stream" db:"output_stream"`
	ConsoleEnabled bool      `json:"enable_console" db:"enable_console"`
	StorageEnabled bool      `json:"enable_storage" db:"enable_storage"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

// AuditLogConfigs is not required by pop and may be deleted
type AuditLogConfigs []AuditLogConfig

// Validate gets run every time you call a "pop.Validate*" (pop.ValidateAndSave, pop.ValidateAndCreate, pop.ValidateAndUpdate) method.
// This method is not required and may be deleted.
func (auditLogConfig *AuditLogConfig) Validate(tx *pop.Connection) (*validate.Errors, error) {
	return validate.Validate(
		&validators.UUIDIsPresent{Name: "ID", Field: auditLogConfig.ID},
		&validators.StringIsPresent{Name: "OutputStream", Field: auditLogConfig.OutputStream},
		&validators.TimeIsPresent{Name: "UpdatedAt", Field: auditLogConfig.UpdatedAt},
		&validators.TimeIsPresent{Name: "CreatedAt", Field: auditLogConfig.CreatedAt},
	), nil
}
