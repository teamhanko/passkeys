package request

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
	"time"
)

type CreateWebauthnDto struct {
	RelyingParty           CreateRelyingPartyDto                `json:"relying_party" validate:"required"`
	Timeout                int                                  `json:"timeout" validate:"required,number"`
	UserVerification       protocol.UserVerificationRequirement `json:"user_verification" validate:"required,oneof=required preferred discouraged"`
	Attachment             *protocol.AuthenticatorAttachment    `json:"attachment" validate:"omitempty,oneof=platform cross-platform"`
	AttestationPreference  *protocol.ConveyancePreference       `json:"attestation_preference" validate:"omitempty,oneof=none indirect direct enterprise"`
	ResidentKeyRequirement *protocol.ResidentKeyRequirement     `json:"resident_key_requirement" validate:"omitempty,oneof=discouraged preferred required"`
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
		Attachment:       dto.Attachment,
	}

	if dto.AttestationPreference == nil {
		webauthnConfig.AttestationPreference = protocol.PreferNoAttestation
	} else {
		webauthnConfig.AttestationPreference = *dto.AttestationPreference
	}

	if dto.ResidentKeyRequirement == nil {
		webauthnConfig.ResidentKeyRequirement = protocol.ResidentKeyRequirementRequired
	} else {
		webauthnConfig.ResidentKeyRequirement = *dto.ResidentKeyRequirement
	}

	return webauthnConfig
}
