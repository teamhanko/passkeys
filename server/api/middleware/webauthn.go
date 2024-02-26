package middleware

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
	"time"
)

func WebauthnMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			tenant := ctx.Get("tenant").(*models.Tenant)
			if tenant == nil {
				ctx.Logger().Errorf("tenant for webauthn middleware net found")
				return echo.NewHTTPError(http.StatusNotFound, "tenant not found")
			}

			cfg := tenant.Config

			var origins []string
			for _, origin := range cfg.WebauthnConfig.RelyingParty.Origins {
				origins = append(origins, origin.Origin)
			}

			f := false
			webauthnClient, err := webauthn.New(&webauthn.Config{
				RPDisplayName:         cfg.WebauthnConfig.RelyingParty.DisplayName,
				RPID:                  cfg.WebauthnConfig.RelyingParty.RPId,
				RPOrigins:             origins,
				AttestationPreference: cfg.WebauthnConfig.AttestationPreference,
				AuthenticatorSelection: protocol.AuthenticatorSelection{
					RequireResidentKey: &f,
					ResidentKey:        cfg.WebauthnConfig.ResidentKeyRequirement,
					UserVerification:   cfg.WebauthnConfig.UserVerification,
				},
				Debug: false,
				Timeouts: webauthn.TimeoutsConfig{
					Login: webauthn.TimeoutConfig{
						Timeout: time.Duration(cfg.WebauthnConfig.Timeout) * time.Millisecond,
						Enforce: true,
					},
					Registration: webauthn.TimeoutConfig{
						Timeout: time.Duration(cfg.WebauthnConfig.Timeout) * time.Millisecond,
						Enforce: true,
					},
				},
			})

			if err != nil {
				ctx.Logger().Error(err)
				return err
			}
			ctx.Set("webauthn_client", webauthnClient)

			return next(ctx)
		}
	}
}
