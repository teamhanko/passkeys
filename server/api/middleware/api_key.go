package middleware

import (
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

			var foundKey *models.Secret

			for _, key := range tenant.Config.Secrets {

				if strings.TrimSpace(apiKey) == key.Key {
					foundKey = &key
					break
				}
			}

			if foundKey == nil {
				errorType := "about:blank"
				title := "The api key is invalid"
				details := "api keys needs to be an apiKey Header and 32 byte long"
				status := http.StatusUnauthorized

				return c.JSON(http.StatusUnauthorized, &HttpError{
					ErrorType: &errorType,
					Title:     &title,
					Details:   &details,
					Status:    &status,
				})
			}

			if !foundKey.IsAPISecret {
				errorType := "about:blank"
				title := "The api key is invalid"
				details := "provided key is not an api key"
				status := http.StatusUnauthorized

				return c.JSON(http.StatusUnauthorized, &HttpError{
					ErrorType: &errorType,
					Title:     &title,
					Details:   &details,
					Status:    &status,
				})
			}

			return next(c)
		}
	}
}
