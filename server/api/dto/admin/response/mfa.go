package response

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type GetMFAResponse struct {
	Timeout                int                                  `json:"timeout"`
	UserVerification       protocol.UserVerificationRequirement `json:"user_verification"`
	Attachment             protocol.AuthenticatorAttachment     `json:"attachment"`
	AttestationPreference  protocol.ConveyancePreference        `json:"attestation_preference"`
	ResidentKeyRequirement protocol.ResidentKeyRequirement      `json:"resident_key_requirement"`
}

func ToGetMFAResponse(webauthn *models.MfaConfig) GetMFAResponse {
	return GetMFAResponse{
		Timeout:                webauthn.Timeout,
		UserVerification:       webauthn.UserVerification,
		Attachment:             webauthn.Attachment,
		AttestationPreference:  webauthn.AttestationPreference,
		ResidentKeyRequirement: webauthn.ResidentKeyRequirement,
	}
}
