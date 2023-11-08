package handler

import (
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/request"
	auditlog "github.com/teamhanko/passkey-server/audit_log"
	"github.com/teamhanko/passkey-server/persistence"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
)

type WebauthnHandler interface {
	Init(ctx echo.Context) error
	Finish(ctx echo.Context) error
}

type WebauthnContext struct {
	tenant   *models.Tenant
	webauthn *webauthn.WebAuthn
	config   models.Config
	auditLog auditlog.Logger
}

type webauthnHandler struct {
	persister persistence.Persister
}

func newWebAuthnHandler(persister persistence.Persister) (*webauthnHandler, error) {
	return &webauthnHandler{
		persister: persister,
	}, nil
}

func GetHandlerContext(ctx echo.Context) (*WebauthnContext, error) {
	ctxTenant := ctx.Get("tenant")
	if ctxTenant == nil {
		return nil, echo.NewHTTPError(http.StatusInternalServerError, "Unable to find tenant")
	}
	tenant := ctxTenant.(*models.Tenant)

	ctxWebautn := ctx.Get("webauthn_client")
	var webauthnClient *webauthn.WebAuthn
	if ctxWebautn != nil {
		webauthnClient = ctxWebautn.(*webauthn.WebAuthn)
	}

	ctxAuditLog := ctx.Get("audit_logger")
	var auditLogger auditlog.Logger
	if ctxAuditLog != nil {
		auditLogger = ctxAuditLog.(auditlog.Logger)
	}

	return &WebauthnContext{
		tenant:   tenant,
		webauthn: webauthnClient,
		config:   tenant.Config,
		auditLog: auditLogger,
	}, nil
}

func BindAndValidateRequest[I request.CredentialRequest | request.InitRegistrationDto](ctx echo.Context) (*I, error) {
	var requestDto I
	err := ctx.Bind(&requestDto)
	if err != nil {
		ctx.Logger().Error(err)
		return nil, echo.NewHTTPError(http.StatusBadRequest, err)
	}

	err = ctx.Validate(&requestDto)
	if err != nil {
		ctx.Logger().Error(err)
		return nil, echo.NewHTTPError(http.StatusBadRequest, err)
	}

	return &requestDto, nil
}
