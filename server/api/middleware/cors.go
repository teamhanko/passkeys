package middleware

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/teamhanko/passkey-server/persistence/models"
)

func CORSWithTenant() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			corsConfig := c.Get("tenant").(*models.Tenant).Config.Cors

			var origins []string
			for _, origin := range corsConfig.Origins {
				origins = append(origins, origin.Origin)
			}

			return middleware.CORSWithConfig(middleware.CORSConfig{
				UnsafeWildcardOriginWithAllowCredentials: corsConfig.AllowUnsafe,
				AllowOrigins:                             origins,
				ExposeHeaders:                            make([]string, 0),
				AllowCredentials:                         true,
				// Based on: Chromium (starting in v76) caps at 2 hours (7200 seconds).
				MaxAge: 7200,
			})(next)(c)
		}
	}
}
