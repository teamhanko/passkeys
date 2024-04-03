package helper

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
	"strings"
)

func CreateApiKeyError(keys []models.Secret, apiKey string) error {
	var foundKey *models.Secret
	for _, key := range keys {
		if strings.TrimSpace(apiKey) == key.Key {
			foundKey = &key
			break
		}
	}

	if foundKey == nil {
		title := "The api key is invalid"
		details := "api keys needs to be an apiKey Header and 32 byte long"

		return echo.NewHTTPError(http.StatusUnauthorized, title).SetInternal(fmt.Errorf(details))
	}

	if !foundKey.IsAPISecret {
		title := "The api key is invalid"
		details := "provided key is not an api key"

		return echo.NewHTTPError(http.StatusUnauthorized, title).SetInternal(fmt.Errorf(details))
	}

	return nil
}
