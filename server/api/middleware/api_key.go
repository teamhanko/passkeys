package middleware

import (
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/helper"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
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

			err := helper.CheckApiKey(tenant.Config.Secrets, apiKey)
			if err != nil {
				return err
			}

			return next(ctx)
		}
	}
}
