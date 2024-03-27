package request

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
	"time"
)

type CreateWebauthnConfigDto struct {
	RelyingParty           CreateRelyingPartyDto                 `json:"relying_party" validate:"required"`
	Timeout                int                                   `json:"timeout" validate:"required,number"`
	UserVerification       *protocol.UserVerificationRequirement `json:"user_verification" validate:"omitempty,oneof=required preferred discouraged"`
	Attachment             *protocol.AuthenticatorAttachment     `json:"attachment" validate:"omitempty,oneof=platform cross-platform"`
	AttestationPreference  *protocol.ConveyancePreference        `json:"attestation_preference" validate:"omitempty,oneof=none indirect direct enterprise"`
	ResidentKeyRequirement *protocol.ResidentKeyRequirement      `json:"resident_key_requirement" validate:"omitempty,oneof=discouraged preferred required"`
}

func (dto *CreateWebauthnConfigDto) ToModel(configModel models.Config) models.WebauthnConfig {
	passkeyConfigId, _ := uuid.NewV4()
	now := time.Now()

	passkeyConfig := models.WebauthnConfig{
		ID:        passkeyConfigId,
		ConfigID:  configModel.ID,
		Timeout:   dto.Timeout,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if dto.AttestationPreference == nil {
		passkeyConfig.AttestationPreference = protocol.PreferDirectAttestation
	} else {
		passkeyConfig.AttestationPreference = *dto.AttestationPreference
	}

	passkeyConfig.Attachment = dto.Attachment

	if dto.ResidentKeyRequirement == nil {
		passkeyConfig.ResidentKeyRequirement = protocol.ResidentKeyRequirementRequired
	} else {
		passkeyConfig.ResidentKeyRequirement = *dto.ResidentKeyRequirement
	}

	if dto.UserVerification == nil {
		passkeyConfig.UserVerification = protocol.VerificationRequired
	} else {
		passkeyConfig.UserVerification = *dto.UserVerification
	}

	return passkeyConfig
}
