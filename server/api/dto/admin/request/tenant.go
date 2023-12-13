package request

import (
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
	"time"
)

type CreateTenantDto struct {
	DisplayName  string          `json:"display_name" validate:"required"`
	Config       CreateConfigDto `json:"config" validate:"required"`
	CreateApiKey bool            `json:"create_api_key"`
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

type UpdateTenantDto struct {
	DisplayName string `json:"display_name" validate:"required"`
}
