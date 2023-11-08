package response

import "github.com/teamhanko/passkey-server/persistence/models"

type GetRelyingPartyResponse struct {
	Id          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	Icon        *string  `json:"icon,omitempty"`
	Origins     []string `json:"origins"`
}

func ToGetRelyingPartyResponse(relyingParty *models.RelyingParty) GetRelyingPartyResponse {
	var origins []string
	for _, origin := range relyingParty.Origins {
		origins = append(origins, origin.Origin)
	}

	return GetRelyingPartyResponse{
		Id:          relyingParty.RPId,
		DisplayName: relyingParty.DisplayName,
		Icon:        relyingParty.Icon,
		Origins:     origins,
	}
}
