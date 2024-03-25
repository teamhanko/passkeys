package request

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/persistence/models"
	"time"
)

type CreateMFAConfigDto struct {
	Timeout                int                                   `json:"timeout" validate:"required,number"`
	UserVerification       *protocol.UserVerificationRequirement `json:"user_verification" validate:"omitempty,oneof=required preferred discouraged"`
	Attachment             *protocol.AuthenticatorAttachment     `json:"attachment" validate:"omitempty,oneof=platform cross-platform"`
	AttestationPreference  *protocol.ConveyancePreference        `json:"attestation_preference" validate:"omitempty,oneof=none indirect direct enterprise"`
	ResidentKeyRequirement *protocol.ResidentKeyRequirement      `json:"resident_key_requirement" validate:"omitempty,oneof=discouraged preferred required"`
}

func (dto *CreateMFAConfigDto) ToModel(configModel models.Config) models.MfaConfig {
	mfaConfigId, _ := uuid.NewV4()
	now := time.Now()

	mfaConfig := models.MfaConfig{
		ID:        mfaConfigId,
		ConfigID:  configModel.ID,
		Timeout:   dto.Timeout,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if dto.AttestationPreference == nil {
		mfaConfig.AttestationPreference = protocol.PreferNoAttestation
	} else {
		mfaConfig.AttestationPreference = *dto.AttestationPreference
	}

	if dto.ResidentKeyRequirement == nil {
		mfaConfig.ResidentKeyRequirement = protocol.ResidentKeyRequirementDiscouraged
	} else {
		mfaConfig.ResidentKeyRequirement = *dto.ResidentKeyRequirement
	}

	if dto.UserVerification == nil {
		mfaConfig.UserVerification = protocol.VerificationPreferred
	} else {
		mfaConfig.UserVerification = *dto.UserVerification
	}

	if dto.Attachment == nil {
		mfaConfig.Attachment = protocol.CrossPlatform
	} else {
		mfaConfig.Attachment = *dto.Attachment
	}

	return mfaConfig
}
