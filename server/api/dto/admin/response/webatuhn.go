package response

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type GetWebauthnResponse struct {
	RelyingParty           GetRelyingPartyResponse              `json:"relying_party"`
	Timeout                int                                  `json:"timeout"`
	UserVerification       protocol.UserVerificationRequirement `json:"user_verification"`
	Attachment             *protocol.AuthenticatorAttachment    `json:"attachment,omitempty"`
	AttestationPreference  protocol.ConveyancePreference        `json:"attestation_preference"`
	ResidentKeyRequirement protocol.ResidentKeyRequirement      `json:"resident_key_requirement"`
}

func ToGetWebauthnResponse(webauthn *models.WebauthnConfig) GetWebauthnResponse {
	return GetWebauthnResponse{
		RelyingParty:           ToGetRelyingPartyResponse(&webauthn.RelyingParty),
		Timeout:                webauthn.Timeout,
		UserVerification:       webauthn.UserVerification,
		Attachment:             webauthn.Attachment,
		AttestationPreference:  webauthn.AttestationPreference,
		ResidentKeyRequirement: webauthn.ResidentKeyRequirement,
	}
}
