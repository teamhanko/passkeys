package helper

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/persistence/models"
)

func CheckApiKey(keys []models.Secret, apiKey string) error {
	var foundKey *models.Secret
	for _, key := range keys {
		if strings.TrimSpace(apiKey) == key.Key {
			foundKey = &key
			break
		}
	}

	if foundKey == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "The api key is invalid").
			SetInternal(fmt.Errorf("api keys needs to be an apiKey Header and 32 byte long"))
	}

	if !foundKey.IsAPISecret {
		return echo.NewHTTPError(http.StatusUnauthorized, "The api key is invalid").
			SetInternal(fmt.Errorf("provided key is not an api key"))
	}

	return nil
}
