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
		return func(ctx echo.Context) error {
			apiKey := ctx.Request().Header.Get("apiKey")
			tenant := ctx.Get("tenant").(*models.Tenant)

			if tenant == nil {
				ctx.Logger().Errorf("tenant for api key middleware net found")
				return echo.NewHTTPError(http.StatusNotFound, "tenant not found")
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

			return next(ctx)
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
