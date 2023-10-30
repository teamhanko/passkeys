package response

import (
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
	"time"
)

type SecretResponseDto struct {
	Id        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Secret    string    `json:"secret"`
	CreatedAt time.Time `json:"created_at"`
}

func ToSecretResponse(secret *models.Secret) SecretResponseDto {
	return SecretResponseDto{
		Id:        secret.ID,
		Name:      secret.Name,
		Secret:    secret.Key,
		CreatedAt: secret.CreatedAt,
	}
}
