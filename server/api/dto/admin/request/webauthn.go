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

func (dto *CreateWebauthnConfigDto) toModel(configModel models.Config) models.WebauthnConfig {
	webauthnConfigId, _ := uuid.NewV4()
	now := time.Now()

	webauthnConfig := models.WebauthnConfig{
		ID:        webauthnConfigId,
		ConfigID:  configModel.ID,
		Timeout:   dto.Timeout,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if dto.AttestationPreference == nil {
		webauthnConfig.AttestationPreference = protocol.PreferNoAttestation
	} else {
		webauthnConfig.AttestationPreference = *dto.AttestationPreference
	}

	return webauthnConfig
}

func (dto *CreateWebauthnConfigDto) ToPasskeyModel(configModel models.Config) models.WebauthnConfig {
	passkeyConfig := dto.toModel(configModel)
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

func (dto *CreateWebauthnConfigDto) ToMfaModel(configModel models.Config) models.WebauthnConfig {
	mfaConfig := dto.toModel(configModel)
	mfaConfig.IsMfa = true

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
		cp := protocol.CrossPlatform
		mfaConfig.Attachment = &cp
	} else {
		mfaConfig.Attachment = dto.Attachment
	}

	return mfaConfig
}
