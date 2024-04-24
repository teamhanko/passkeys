package helper

import (
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
	auditlog "github.com/teamhanko/passkey-server/audit_log"
	"github.com/teamhanko/passkey-server/crypto/jwt"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
)

type WebauthnContext struct {
	Tenant         *models.Tenant
	WebauthnClient *webauthn.WebAuthn
	Config         models.Config
	AuditLog       auditlog.Logger
	Generator      jwt.Generator
}

func getContext(ctx echo.Context, webauthnClientKey string) (*WebauthnContext, error) {
	ctxTenant := ctx.Get("tenant")
	if ctxTenant == nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, "Unable to find tenant")
	}
	tenant := ctxTenant.(*models.Tenant)

	webauthnClientCtx := ctx.Get(webauthnClientKey)
	var webauthnClient *webauthn.WebAuthn
	if webauthnClientCtx != nil {
		webauthnClient = webauthnClientCtx.(*webauthn.WebAuthn)
	}

	jwtGeneratorCtx := ctx.Get("jwt_generator")
	var jwtGenerator jwt.Generator
	if jwtGeneratorCtx != nil {
		jwtGenerator = jwtGeneratorCtx.(jwt.Generator)
	}

	ctxAuditLog := ctx.Get("audit_logger")
	var auditLogger auditlog.Logger
	if ctxAuditLog != nil {
		auditLogger = ctxAuditLog.(auditlog.Logger)
	}

	return &WebauthnContext{
		Tenant:         tenant,
		WebauthnClient: webauthnClient,
		Config:         tenant.Config,
		AuditLog:       auditLogger,
		Generator:      jwtGenerator,
	}, nil
}

func GetHandlerContext(ctx echo.Context) (*WebauthnContext, error) {
	return getContext(ctx, "webauthn_client")
}

func GetMfaHandlerContext(ctx echo.Context) (*WebauthnContext, error) {
	return getContext(ctx, "mfa_client")
}
