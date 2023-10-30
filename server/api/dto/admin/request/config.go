package request

import (
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/persistence/models"
	"time"
)

type CreateConfigDto struct {
	Cors     CreateCorsDto     `json:"cors" validate:"required"`
	Webauthn CreateWebauthnDto `json:"webauthn" validate:"required"`
}

func (dto *CreateConfigDto) ToModel(tenant models.Tenant) models.Config {
	configId, _ := uuid.NewV4()
	now := time.Now()

	auditLogId, _ := uuid.NewV4()
	auditLogModel := models.AuditLogConfig{
		ID:             auditLogId,
		ConfigID:       configId,
		OutputStream:   config.OutputStreamStdOut,
		ConsoleEnabled: true,
		StorageEnabled: true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	configModel := models.Config{
		ID:             configId,
		TenantID:       tenant.ID,
		AuditLogConfig: auditLogModel,
		Secrets:        nil,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	return configModel
}

type UpdateConfigDto struct {
	GetTenantDto
	CreateConfigDto
}
