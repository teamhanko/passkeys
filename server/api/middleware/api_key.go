package middleware

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
	"strings"
)

func ApiKeyMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			apiKey := c.Request().Header.Get("apiKey")
			tenant := c.Get("tenant").(*models.Tenant)

			if tenant == nil {
				return echo.NewHTTPError(http.StatusNotFound, "tenant for api key not found")
			}

			var foundKey *models.Secret
			for _, key := range tenant.Config.Secrets {
				if strings.TrimSpace(apiKey) == key.Key {
					foundKey = &key
					break
				}
			}

			err := createApiKeyError(foundKey)
			if err != nil {
				return err
			}

			return next(c)
		}
	}
}

func createApiKeyError(key *models.Secret) error {
	if key == nil {
		title := "The api key is invalid"
		details := "api keys needs to be an apiKey Header and 32 byte long"

		return echo.NewHTTPError(http.StatusUnauthorized, title).SetInternal(fmt.Errorf(details))
	}

	if !key.IsAPISecret {
		title := "The api key is invalid"
		details := "provided key is not an api key"

		return echo.NewHTTPError(http.StatusUnauthorized, title).SetInternal(fmt.Errorf(details))
	}

	return nil
}
