package response

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type GetWebauthnResponse struct {
	RelyingParty     GetRelyingPartyResponse              `json:"relying_party"`
	Timeout          int                                  `json:"timeout"`
	UserVerification protocol.UserVerificationRequirement `json:"user_verification"`
}

func ToGetWebauthnResponse(webauthn *models.WebauthnConfig) GetWebauthnResponse {
	return GetWebauthnResponse{
		RelyingParty:     ToGetRelyingPartyResponse(&webauthn.RelyingParty),
		Timeout:          webauthn.Timeout,
		UserVerification: webauthn.UserVerification,
	}
}
