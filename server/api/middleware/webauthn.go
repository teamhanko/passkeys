package middleware

import (
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
	"time"
)

func WebauthnMiddleware(persister persistence.Persister) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			tenant := ctx.Get("tenant").(*models.Tenant)
			if tenant == nil {
				ctx.Logger().Errorf("tenant for webauthn middleware not found")
				return echo.NewHTTPError(http.StatusNotFound, "tenant not found")
			}

			ctx.Path()

			cfg := tenant.Config

			err := setWebauthnClientCtx(ctx, cfg, persister)
			if err != nil {
				ctx.Logger().Error(err)
				return err
			}

			return next(ctx)
		}
	}
}

func setWebauthnClientCtx(ctx echo.Context, cfg models.Config, persister persistence.Persister) error {
	var passkeyConfig models.WebauthnConfig
	for _, webauthnConfig := range cfg.WebauthnConfigs {
		var err error
		if webauthnConfig.IsMfa {
			err = createWebauthnClient(ctx, "mfa_client", webauthnConfig)
		} else {
			passkeyConfig = webauthnConfig
			err = createWebauthnClient(ctx, "webauthn_client", webauthnConfig)
		}

		if err != nil {
			ctx.Logger().Error(err)
			return err
		}
	}

	if ctx.Get("mfa_client") == nil {
		mfaConfig, err := createDefaultMfaConfig(persister, passkeyConfig)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}

		err = createWebauthnClient(ctx, "mfa_client", *mfaConfig)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}
	}

	return nil
}

func createWebauthnClient(ctx echo.Context, ctxKey string, cfg models.WebauthnConfig) error {
	var origins []string
	for _, origin := range cfg.RelyingParty.Origins {
		origins = append(origins, origin.Origin)
	}

	requireKey := cfg.ResidentKeyRequirement == protocol.ResidentKeyRequirementRequired

	webauthnClient, err := webauthn.New(&webauthn.Config{
		RPDisplayName:         cfg.RelyingParty.DisplayName,
		RPID:                  cfg.RelyingParty.RPId,
		RPOrigins:             origins,
		AttestationPreference: cfg.AttestationPreference,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: &requireKey,
			ResidentKey:        cfg.ResidentKeyRequirement,
			UserVerification:   cfg.UserVerification,
		},
		Debug: false,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Timeout: time.Duration(cfg.Timeout) * time.Millisecond,
				Enforce: true,
			},
			Registration: webauthn.TimeoutConfig{
				Timeout: time.Duration(cfg.Timeout) * time.Millisecond,
				Enforce: true,
			},
		},
	})

	if err != nil {
		return err
	}

	ctx.Set(ctxKey, webauthnClient)

	return nil
}

func createDefaultMfaConfig(persister persistence.Persister, passkeyConfig models.WebauthnConfig) (*models.WebauthnConfig, error) {
	configId, _ := uuid.NewV4()
	now := time.Now()

	cpAttachment := protocol.CrossPlatform

	mfaConfig := &models.WebauthnConfig{
		ID:                     configId,
		ConfigID:               passkeyConfig.ConfigID,
		RelyingParty:           passkeyConfig.RelyingParty,
		Timeout:                passkeyConfig.Timeout,
		CreatedAt:              now,
		UpdatedAt:              now,
		UserVerification:       protocol.VerificationPreferred,
		Attachment:             &cpAttachment,
		AttestationPreference:  protocol.PreferNoAttestation,
		ResidentKeyRequirement: protocol.ResidentKeyRequirementDiscouraged,
		IsMfa:                  true,
	}

	err := persister.GetWebauthnConfigPersister(nil).Create(mfaConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create default mfa config: %w", err)
	}

	return mfaConfig, nil
}
