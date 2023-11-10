package helper

import (
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
	auditlog "github.com/teamhanko/passkey-server/audit_log"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
)

type WebauthnContext struct {
	Tenant   *models.Tenant
	Webauthn *webauthn.WebAuthn
	Config   models.Config
	AuditLog auditlog.Logger
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
		Tenant:   tenant,
		Webauthn: webauthnClient,
		Config:   tenant.Config,
		AuditLog: auditLogger,
	}, nil
}
