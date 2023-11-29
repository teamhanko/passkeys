package router

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/teamhanko/passkey-server/api/handler"
	passkeyMiddleware "github.com/teamhanko/passkey-server/api/middleware"
	"github.com/teamhanko/passkey-server/api/template"
	"github.com/teamhanko/passkey-server/api/validators"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/persistence"
)

const (
	InitEndpoint   = "/initialize"
	FinishEndpoint = "/finalize"
)

func NewMainRouter(cfg *config.Config, persister persistence.Persister) *echo.Echo {
	main := echo.New()
	main.Renderer = template.NewTemplateRenderer()
	main.HideBanner = true

	// Error Handling
	main.HTTPErrorHandler = passkeyMiddleware.NewHTTPErrorHandler(passkeyMiddleware.HTTPErrorHandlerConfig{
		Debug:  false,
		Logger: main.Logger,
	})

	// Add Request ID to Header
	main.Use(middleware.RequestID())

	// Validator
	main.Validator = validators.NewCustomValidator()

	rootGroup := main.Group("/:tenant_id", passkeyMiddleware.TenantMiddleware(persister))
	tenantGroup := rootGroup.Group(
		"",
		passkeyMiddleware.CORSWithTenant(),
		passkeyMiddleware.AuditLogger(persister),
		passkeyMiddleware.JWKMiddleware(persister),
	)

	logMetrics(cfg.Log.LogHealthAndMetrics, main, tenantGroup)

	RouteWellKnown(tenantGroup)
	RouteCredentials(tenantGroup, persister)
	RouteRegistration(tenantGroup, persister)
	RouteLogin(tenantGroup, persister)
	RouteTransaction(tenantGroup, persister)

	return main
}

func logMetrics(logMetrics bool, router *echo.Echo, group *echo.Group) {
	if logMetrics {
		router.Use(passkeyMiddleware.LoggerMiddleware())
	} else {
		group.Use(passkeyMiddleware.LoggerMiddleware())
	}
}

func RouteWellKnown(parent *echo.Group) {
	wellKnownHandler := handler.NewWellKnownHandler()

	group := parent.Group("/.well-known")
	group.GET("/jwks.json", wellKnownHandler.GetPublicKeys)
}

func RouteCredentials(parent *echo.Group, persister persistence.Persister) {
	credentialsHandler := handler.NewCredentialsHandler(persister)

	group := parent.Group("/credentials", passkeyMiddleware.ApiKeyMiddleware())
	group.GET("", credentialsHandler.List)
	group.PATCH("/:credential_id", credentialsHandler.Update)
	group.DELETE("/:credential_id", credentialsHandler.Delete)

	return
}

func RouteRegistration(parent *echo.Group, persister persistence.Persister) {
	registrationHandler := handler.NewRegistrationHandler(persister)

	group := parent.Group("/registration", passkeyMiddleware.WebauthnMiddleware())
	group.POST(InitEndpoint, registrationHandler.Init, passkeyMiddleware.ApiKeyMiddleware())
	group.POST(FinishEndpoint, registrationHandler.Finish)
}

func RouteLogin(parent *echo.Group, persister persistence.Persister) {
	loginHandler := handler.NewLoginHandler(persister)

	group := parent.Group("/login", passkeyMiddleware.WebauthnMiddleware())
	group.POST(InitEndpoint, loginHandler.Init)
	group.POST(FinishEndpoint, loginHandler.Finish)
}

func RouteTransaction(parent *echo.Group, persister persistence.Persister) {
	transactionHandler := handler.NewTransactionHandler(persister)

	group := parent.Group("/transaction", passkeyMiddleware.WebauthnMiddleware(), passkeyMiddleware.ApiKeyMiddleware())
	group.POST(InitEndpoint, transactionHandler.Init)
	group.POST(FinishEndpoint, transactionHandler.Finish)
}
