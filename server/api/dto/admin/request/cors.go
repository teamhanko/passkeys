package request

import (
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
	"time"
)

type CreateCorsDto struct {
	AllowedOrigins      []string `json:"allowed_origins" validate:"required,min=1"`
	AllowUnsafeWildcard *bool    `json:"allow_unsafe_wildcard" validate:"required,boolean"`
}

func (dto *CreateCorsDto) ToModel(config models.Config) models.Cors {
	corsId, _ := uuid.NewV4()
	now := time.Now()

	var origins models.CorsOrigins

	for _, origin := range dto.AllowedOrigins {
		originId, _ := uuid.NewV4()
		originModel := models.CorsOrigin{
			ID:        originId,
			Origin:    origin,
			CreatedAt: now,
			UpdatedAt: now,
		}

		origins = append(origins, originModel)
	}

	cors := models.Cors{
		ID:          corsId,
		ConfigID:    config.ID,
		AllowUnsafe: *dto.AllowUnsafeWildcard,
		Origins:     origins,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	return cors
}
