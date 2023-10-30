package request

import (
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/crypto"
	"github.com/teamhanko/passkey-server/persistence/models"
	"time"
)

type CreateSecretDto struct {
	GetTenantDto
	Name string `json:"name"`
}

func (dto *CreateSecretDto) ToModel(config *models.Config, isApiKey bool) (*models.Secret, error) {
	secretId, _ := uuid.NewV4()

	secretKey, err := crypto.GenerateRandomStringURLSafe(64)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	return &models.Secret{
		ID:          secretId,
		Name:        dto.Name,
		Key:         secretKey,
		IsAPISecret: isApiKey,
		Config:      config,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

type RemoveSecretDto struct {
	GetTenantDto
	SecretId string `param:"secret_id" validate:"required,uuid4"`
}
