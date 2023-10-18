package middleware

import (
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/config"
	"net/http"
	"strings"
)

func ApiKeyMiddleware(cfg *config.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			apiKey := c.Request().Header.Get("apiKey")

			for _, key := range cfg.Secrets.ApiKeys {
				if strings.TrimSpace(apiKey) != key {
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
			}

			return next(c)
		}
	}
}
