package router

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/teamhanko/passkey-server/api/handler"
	passkeyMiddleware "github.com/teamhanko/passkey-server/api/middleware"
	"github.com/teamhanko/passkey-server/api/template"
	"github.com/teamhanko/passkey-server/api/validators"
	auditlog "github.com/teamhanko/passkey-server/audit_log"
	"github.com/teamhanko/passkey-server/config"
	hankoJwk "github.com/teamhanko/passkey-server/crypto/jwk"
	"github.com/teamhanko/passkey-server/crypto/jwt"
	"github.com/teamhanko/passkey-server/persistence"
)

func NewMainRouter(cfg *config.Config, persister persistence.Persister) *echo.Echo {
	main := echo.New()
	main.Renderer = template.NewTemplateRenderer()
	main.HideBanner = true
	rootGroup := main.Group("")

	// Error Handling
	main.HTTPErrorHandler = passkeyMiddleware.NewHTTPErrorHandler(passkeyMiddleware.HTTPErrorHandlerConfig{
		Debug:  false,
		Logger: main.Logger,
	})

	// Add Request ID to Header
	main.Use(middleware.RequestID())

	// Log Metrics
	logMetrics(cfg.Log.LogHealthAndMetrics, main, rootGroup)

	// CORS
	main.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		UnsafeWildcardOriginWithAllowCredentials: cfg.Server.Cors.UnsafeWildcardOriginAllowed,
		AllowOrigins:                             cfg.Server.Cors.AllowOrigins,
		ExposeHeaders:                            make([]string, 0),
		AllowCredentials:                         true,
		// Based on: Chromium (starting in v76) caps at 2 hours (7200 seconds).
		MaxAge: 7200,
	}))

	// Validator
	main.Validator = validators.NewCustomValidator()

	// Audit Logger
	auditLogger := auditlog.NewLogger(persister, cfg.AuditLog)

	// jwk manager
	jwkManager, err := hankoJwk.NewDefaultManager(cfg.Secrets.Keys, persister.GetJwkPersister(nil))
	if err != nil {
		panic(err)
	}

	// jwt generator
	generator, err := jwt.NewGenerator(cfg, jwkManager)
	if err != nil {
		panic(fmt.Errorf("unable to create generator: %w", err))
	}

	RouteWellKnown(main, jwkManager)

	RouteCredentials(main, cfg, persister, auditLogger)
	RouteRegistration(main, cfg, persister, auditLogger, generator)
	RouteLogin(main, cfg, persister, auditLogger, generator)

	return main
}

func logMetrics(logMetrics bool, router *echo.Echo, group *echo.Group) {
	if logMetrics {
		router.Use(passkeyMiddleware.LoggerMiddleware())
	} else {
		group.Use(passkeyMiddleware.LoggerMiddleware())
	}
}

func RouteWellKnown(parent *echo.Echo, manager hankoJwk.Manager) {
	wellKnownHandler := handler.NewWellKnownHandler(manager)

	group := parent.Group("/.well-known")
	group.GET("/jwks.json", wellKnownHandler.GetPublicKeys)
}

func RouteCredentials(parent *echo.Echo, cfg *config.Config, persister persistence.Persister, logger auditlog.Logger) {
	credentialsHandler, err := handler.NewCredentialsHandler(cfg, persister, logger)
	if err != nil {
		panic(err)
	}

	group := parent.Group("/credentials", passkeyMiddleware.ApiKeyMiddleware(cfg))
	group.GET("", credentialsHandler.List)
	group.PATCH("/:credentialId", credentialsHandler.Update)
	group.DELETE("/:credentialId", credentialsHandler.Delete)

	return
}

func RouteRegistration(parent *echo.Echo, cfg *config.Config, persister persistence.Persister, logger auditlog.Logger, generator jwt.Generator) {
	registrationHandler, err := handler.NewRegistrationHandler(cfg, persister, logger, generator)
	if err != nil {
		panic(err)
	}

	group := parent.Group("/registration")
	group.POST("/initialize", registrationHandler.Init, passkeyMiddleware.ApiKeyMiddleware(cfg))
	group.POST("/finalize", registrationHandler.Finish)
}

func RouteLogin(parent *echo.Echo, cfg *config.Config, persister persistence.Persister, logger auditlog.Logger, generator jwt.Generator) {
	loginHandler, err := handler.NewLoginHandler(cfg, persister, logger, generator)
	if err != nil {
		panic(err)
	}

	group := parent.Group("/login")
	group.POST("/initialize", loginHandler.Init)
	group.POST("/finalize", loginHandler.Finish)
}
