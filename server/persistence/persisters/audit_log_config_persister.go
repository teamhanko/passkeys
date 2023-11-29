package persisters

import (
	"fmt"

	"github.com/gobuffalo/pop/v6"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type AuditLogConfigPersister interface {
	Create(auditLogConfig *models.AuditLogConfig) error
}

type auditLogConfigPersister struct {
	database *pop.Connection
}

func NewAuditLogConfigPersister(database *pop.Connection) AuditLogConfigPersister {
	return &auditLogConfigPersister{database: database}
}

func (ap *auditLogConfigPersister) Create(auditLogConfig *models.AuditLogConfig) error {
	validationErr, err := ap.database.Eager().ValidateAndCreate(auditLogConfig)
	if err != nil {
		return fmt.Errorf("failed to store audit log config: %w", err)
	}

	if validationErr != nil && validationErr.HasAny() {
		return fmt.Errorf("audit log config validation failed: %w", validationErr)
	}

	return nil
}
