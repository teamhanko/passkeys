package response

import "github.com/teamhanko/passkey-server/persistence/models"

type GetConfigResponse struct {
	Cors     GetCorsResponse     `json:"cors"`
	Webauthn GetWebauthnResponse `json:"webauthn"`
	Mfa      GetWebauthnResponse `json:"mfa"`
}

func ToGetConfigResponse(config *models.Config) GetConfigResponse {
	var passkeyConfig models.WebauthnConfig
	var mfaConfig models.WebauthnConfig
	for _, webauthnConfig := range config.WebauthnConfigs {
		if webauthnConfig.IsMfa {
			mfaConfig = webauthnConfig
		} else {
			passkeyConfig = webauthnConfig
		}
	}

	return GetConfigResponse{
		Cors:     ToGetCorsResponse(&config.Cors),
		Webauthn: ToGetWebauthnResponse(&passkeyConfig),
		Mfa:      ToGetWebauthnResponse(&mfaConfig),
	}
}
