package request

import (
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
	"time"
)

type CreateTenantDto struct {
	DisplayName string          `json:"display_name" validate:"required"`
	Config      CreateConfigDto `json:"config" validate:"required"`
}

func (dto *CreateTenantDto) ToModel() models.Tenant {
	tenantId, _ := uuid.NewV4()
	now := time.Now()

	tenant := models.Tenant{
		ID:          tenantId,
		DisplayName: dto.DisplayName,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	return tenant
}

type GetTenantDto struct {
	Id string `param:"tenant_id" validate:"required,uuid4"`
}

type UpdateTenantDto struct {
	GetTenantDto
	DisplayName string `json:"display_name" validate:"required"`
}
