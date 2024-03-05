package middleware

import (
	"github.com/gofrs/uuid"
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

	for _, webauthnConfig := range tenant.Config.WebauthnConfigs {
		if webauthnConfig.IsMfa {
			err = createGeneratorFromConfig(ctx, "mfa_jwt_generator", webauthnConfig, jwkManager, tenant.ID)
		} else {
			err = createGeneratorFromConfig(ctx, "jwt_generator", webauthnConfig, jwkManager, tenant.ID)
		}

		if err != nil {
			ctx.Logger().Error(err)
			return err
		}
	}

	return nil
}

func createGeneratorFromConfig(ctx echo.Context, ctxKey string, cfg models.WebauthnConfig, manager hankoJwk.Manager, tenantId uuid.UUID) error {
	generator, err := jwt.NewGenerator(&cfg, manager, tenantId)
	if err != nil {
		return err
	}

	ctx.Set(ctxKey, generator)

	return nil
}
