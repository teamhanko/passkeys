package middleware

import (
	"github.com/labstack/echo/v4"
	hankoJwk "github.com/teamhanko/passkey-server/crypto/jwk"
	"github.com/teamhanko/passkey-server/crypto/jwt"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
)

func JWKMiddleware(persister persistence.Persister) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			tenant := ctx.Get("tenant").(*models.Tenant)
			secrets := tenant.Config.Secrets

			var keys []string
			for _, secret := range secrets {
				if !secret.IsAPISecret {
					keys = append(keys, secret.Key)
				}
			}

			jwkManager, err := hankoJwk.NewDefaultManager(keys, tenant.ID, persister.GetJwkPersister(nil))
			if err != nil {
				return ctx.JSON(http.StatusInternalServerError, NewHttpError(
					"about:blank",
					"unable to initialize jwt generator",
					err.Error(),
					http.StatusInternalServerError,
					nil,
				))
			}
			ctx.Set("jwk_manager", jwkManager)

			generator, err := jwt.NewGenerator(&tenant.Config.WebauthnConfig, jwkManager)
			if err != nil {
				return ctx.JSON(http.StatusInternalServerError, NewHttpError(
					"about:blank",
					"unable to initialize jwt generator",
					err.Error(),
					http.StatusInternalServerError,
					nil,
				))
			}

			ctx.Set("jwt_generator", generator)

			return next(ctx)
		}
	}
}
