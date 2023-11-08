package request

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
	"time"
)

type CreateWebauthnDto struct {
	RelyingParty     CreateRelyingPartyDto                `json:"relying_party" validate:"required"`
	Timeout          int                                  `json:"timeout" validate:"required,number"`
	UserVerification protocol.UserVerificationRequirement `json:"user_verification" validate:"required,oneof=required preferred discouraged"`
}

func (dto *CreateWebauthnDto) ToModel(configModel models.Config) models.WebauthnConfig {
	webauthnConfigId, _ := uuid.NewV4()
	now := time.Now()

	webauthnConfig := models.WebauthnConfig{
		ID:               webauthnConfigId,
		ConfigID:         configModel.ID,
		Timeout:          dto.Timeout,
		CreatedAt:        now,
		UpdatedAt:        now,
		UserVerification: dto.UserVerification,
	}

	return webauthnConfig
}
