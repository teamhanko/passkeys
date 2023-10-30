package response

import (
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type ListTenantResponse struct {
	Id          uuid.UUID `json:"id"`
	DisplayName string    `json:"display_name"`
}

func ToListTenantResponse(tenant *models.Tenant) ListTenantResponse {
	return ListTenantResponse{
		Id:          tenant.ID,
		DisplayName: tenant.DisplayName,
	}
}

type GetTenantResponse struct {
	ListTenantResponse
	Config GetConfigResponse `json:"config"`
}

func ToGetTenantResponse(tenant *models.Tenant) GetTenantResponse {
	return GetTenantResponse{
		ListTenantResponse: ToListTenantResponse(tenant),
		Config:             ToGetConfigResponse(&tenant.Config),
	}
}

type CreateTenantResponse struct {
	Id     uuid.UUID         `json:"id"`
	ApiKey SecretResponseDto `json:"api_key"`
}

func ToCreateTenantResponse(tenant *models.Tenant, apiKey *models.Secret) CreateTenantResponse {
	return CreateTenantResponse{
		Id:     tenant.ID,
		ApiKey: ToSecretResponse(apiKey),
	}
}
