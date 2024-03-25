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
			if tenant == nil {
				ctx.Logger().Errorf("tenant for JWK middleware net found")
				return echo.NewHTTPError(http.StatusNotFound, "tenant not found")
			}

			secrets := tenant.Config.Secrets

			var keys []string
			for _, secret := range secrets {
				if !secret.IsAPISecret {
					keys = append(keys, secret.Key)
				}
			}

			err := instantiateJwtGenerator(ctx, keys, *tenant, persister)
			if err != nil {
				return err
			}

			return next(ctx)
		}
	}
}

func instantiateJwtGenerator(ctx echo.Context, keys []string, tenant models.Tenant, persister persistence.Persister) error {
	jwkManager, err := hankoJwk.NewDefaultManager(keys, tenant.ID, persister.GetJwkPersister(nil))
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}
	ctx.Set("jwk_manager", jwkManager)

	generator, err := jwt.NewGenerator(&tenant.Config.WebauthnConfig, jwkManager, tenant.ID)
	if err != nil {
		return err
	}

	ctx.Set("jwt_generator", generator)

	return nil
}
