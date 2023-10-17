package handler

import (
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/request"
	auditlog "github.com/teamhanko/passkey-server/audit_log"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/crypto/jwt"
	"github.com/teamhanko/passkey-server/persistence"
	"time"
)

type WebauthnHandler interface {
	Init(ctx echo.Context) error
	Finish(ctx echo.Context) error
}

type webauthnHandler struct {
	config       *config.Config
	persister    persistence.Persister
	webauthn     *webauthn.WebAuthn
	auditLog     auditlog.Logger
	jwtGenerator jwt.Generator
}

func newWebAuthnHandler(cfg *config.Config, persister persistence.Persister, logger auditlog.Logger, generator jwt.Generator) (*webauthnHandler, error) {

	f := false
	webauthnClient, err := webauthn.New(&webauthn.Config{
		RPDisplayName:         cfg.Webauthn.RelyingParty.DisplayName,
		RPID:                  cfg.Webauthn.RelyingParty.Id,
		RPOrigins:             cfg.Webauthn.RelyingParty.Origins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: &f,
			ResidentKey:        protocol.ResidentKeyRequirementDiscouraged,
			UserVerification:   protocol.VerificationRequired,
		},
		Debug: false,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Timeout: time.Duration(cfg.Webauthn.Timeout) * time.Millisecond,
				Enforce: true,
			},
			Registration: webauthn.TimeoutConfig{
				Timeout: time.Duration(cfg.Webauthn.Timeout) * time.Millisecond,
				Enforce: true,
			},
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn instance: %w", err)
	}

	return &webauthnHandler{
		config:       cfg,
		persister:    persister,
		webauthn:     webauthnClient,
		auditLog:     logger,
		jwtGenerator: generator,
	}, nil
}

func BindAndValidateRequest[I request.CredentialRequest | request.InitRegistrationDto](ctx echo.Context) (*I, error) {
	fmt.Println("lorem")
	var requestDto I
	err := ctx.Bind(&requestDto)
	if err != nil {
		fmt.Println("Here")
		return nil, err
	}

	err = ctx.Validate(&requestDto)
	if err != nil {
		fmt.Println("Here2")
		return nil, err
	}

	return &requestDto, err
}
