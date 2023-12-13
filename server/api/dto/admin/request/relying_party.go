package request

import (
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
	"time"
)

type CreateRelyingPartyDto struct {
	Id          string   `json:"id" validate:"required"`
	DisplayName string   `json:"display_name" validate:"required"`
	Icon        *string  `json:"icon" validate:"omitempty,url"`
	Origins     []string `json:"origins" validate:"required,min=1"`
}

func (dto *CreateRelyingPartyDto) ToModel(config models.WebauthnConfig) models.RelyingParty {
	rpId, _ := uuid.NewV4()
	now := time.Now()
	var origins models.WebauthnOrigins

	for _, origin := range dto.Origins {
		originId, _ := uuid.NewV4()
		originModel := models.WebauthnOrigin{
			ID:        originId,
			Origin:    origin,
			CreatedAt: now,
			UpdatedAt: now,
		}

		origins = append(origins, originModel)
	}

	relyingParty := models.RelyingParty{
		ID:               rpId,
		WebauthnConfigID: config.ID,
		RPId:             dto.Id,
		DisplayName:      dto.DisplayName,
		Icon:             dto.Icon,
		Origins:          origins,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	return relyingParty
}
