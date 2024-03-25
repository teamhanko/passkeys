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

type clientParams struct {
	RP                     models.RelyingParty
	Timeout                int
	UserVerification       protocol.UserVerificationRequirement
	Attachment             *protocol.AuthenticatorAttachment
	AttestationPreference  protocol.ConveyancePreference
	ResidentKeyRequirement protocol.ResidentKeyRequirement
}

func WebauthnMiddleware(persister persistence.Persister) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			tenant := ctx.Get("tenant").(*models.Tenant)
			if tenant == nil {
				ctx.Logger().Errorf("tenant for webauthn middleware not found")
				return echo.NewHTTPError(http.StatusNotFound, "tenant not found")
			}

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

	err := createPasskeyCLient(ctx, cfg.WebauthnConfig)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	if cfg.MfaConfig == nil {
		cfg.MfaConfig, err = createDefaultMfaConfig(persister, passkeyConfig)
		if err != nil {
			ctx.Logger().Error(err)
			return err
		}
	}

	err = createMFAClient(ctx, *cfg.MfaConfig, cfg.WebauthnConfig.RelyingParty)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return nil
}

func createClient(ctx echo.Context, ctxKey string, params clientParams) error {
	var origins []string
	for _, origin := range params.RP.Origins {
		origins = append(origins, origin.Origin)
	}

	requireKey := params.ResidentKeyRequirement == protocol.ResidentKeyRequirementRequired

	webauthnClient, err := webauthn.New(&webauthn.Config{
		RPDisplayName:         params.RP.DisplayName,
		RPID:                  params.RP.RPId,
		RPOrigins:             origins,
		AttestationPreference: params.AttestationPreference,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: &requireKey,
			ResidentKey:        params.ResidentKeyRequirement,
			UserVerification:   params.UserVerification,
		},
		Debug: false,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Timeout: time.Duration(params.Timeout) * time.Millisecond,
				Enforce: true,
			},
			Registration: webauthn.TimeoutConfig{
				Timeout: time.Duration(params.Timeout) * time.Millisecond,
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

func createPasskeyCLient(ctx echo.Context, cfg models.WebauthnConfig) error {
	params := clientParams{
		RP:                     cfg.RelyingParty,
		Timeout:                cfg.Timeout,
		UserVerification:       cfg.UserVerification,
		Attachment:             cfg.Attachment,
		AttestationPreference:  cfg.AttestationPreference,
		ResidentKeyRequirement: cfg.ResidentKeyRequirement,
	}

	return createClient(ctx, "webauthn_client", params)
}

func createMFAClient(ctx echo.Context, cfg models.MfaConfig, rp models.RelyingParty) error {
	params := clientParams{
		RP:                     rp,
		Timeout:                cfg.Timeout,
		UserVerification:       cfg.UserVerification,
		Attachment:             &cfg.Attachment,
		AttestationPreference:  cfg.AttestationPreference,
		ResidentKeyRequirement: cfg.ResidentKeyRequirement,
	}

	return createClient(ctx, "mfa_client", params)
}

func createDefaultMfaConfig(persister persistence.Persister, passkeyConfig models.WebauthnConfig) (*models.MfaConfig, error) {
	configId, _ := uuid.NewV4()
	now := time.Now()

	mfaConfig := &models.MfaConfig{
		ID:                     configId,
		ConfigID:               passkeyConfig.ConfigID,
		Timeout:                passkeyConfig.Timeout,
		CreatedAt:              now,
		UpdatedAt:              now,
		UserVerification:       protocol.VerificationPreferred,
		Attachment:             protocol.CrossPlatform,
		AttestationPreference:  protocol.PreferNoAttestation,
		ResidentKeyRequirement: protocol.ResidentKeyRequirementDiscouraged,
	}

	err := persister.GetMFAConfigPersister(nil).Create(mfaConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create default mfa config: %w", err)
	}

	return mfaConfig, nil
}
