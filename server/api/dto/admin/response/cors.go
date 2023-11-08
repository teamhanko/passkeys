package response

import "github.com/teamhanko/passkey-server/persistence/models"

type GetCorsResponse struct {
	AllowedOrigins []string `json:"allowed_origins"`
	AllowUnsafe    bool     `json:"allow_unsafe_wildcard"`
}

func ToGetCorsResponse(cors *models.Cors) GetCorsResponse {
	var origins []string
	for _, origin := range cors.Origins {
		origins = append(origins, origin.Origin)
	}

	return GetCorsResponse{
		AllowedOrigins: origins,
		AllowUnsafe:    cors.AllowUnsafe,
	}
}
