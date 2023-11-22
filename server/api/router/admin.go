package router

import (
	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/teamhanko/passkey-server/api/handler/admin"
	passkeyMiddleware "github.com/teamhanko/passkey-server/api/middleware"
	"github.com/teamhanko/passkey-server/api/template"
	"github.com/teamhanko/passkey-server/api/validators"
	"github.com/teamhanko/passkey-server/config"
	"github.com/teamhanko/passkey-server/persistence"
)

func NewAdminRouter(cfg *config.Config, persister persistence.Persister, prometheus echo.MiddlewareFunc) *echo.Echo {
	main := echo.New()
	main.Renderer = template.NewTemplateRenderer()
	main.HideBanner = true

	rootGroup := main.Group("")

	main.HTTPErrorHandler = passkeyMiddleware.NewHTTPErrorHandler(passkeyMiddleware.HTTPErrorHandlerConfig{
		Debug:  false,
		Logger: main.Logger,
	})

	main.Use(middleware.RequestID())
	if cfg.Log.LogHealthAndMetrics {
		main.Use(passkeyMiddleware.LoggerMiddleware())
	} else {
		rootGroup.Use(passkeyMiddleware.LoggerMiddleware())
	}

	// add CORS for all
	main.Use(middleware.CORS())

	// Validator
	main.Validator = validators.NewCustomValidator()

	if prometheus != nil {
		main.Use(prometheus)
		main.GET("/metrics", echoprometheus.NewHandler())
	}

	statusHandler := admin.NewStatusHandler(persister)

	main.GET("/", statusHandler.Status)

	healthHandler := admin.NewHealthHandler()

	health := main.Group("/health")
	health.GET("/alive", healthHandler.Alive)
	health.GET("/ready", healthHandler.Ready)

	tenantHandler := admin.NewTenantHandler(persister)
	tenantsGroup := main.Group("/tenants")
	tenantsGroup.GET("", tenantHandler.List)
	tenantsGroup.POST("", tenantHandler.Create)

	singleGroup := tenantsGroup.Group("/:tenant_id")
	singleGroup.GET("", tenantHandler.Get)
	singleGroup.PUT("", tenantHandler.Update)
	singleGroup.DELETE("", tenantHandler.Remove)
	singleGroup.PUT("/config", tenantHandler.UpdateConfig)
	singleGroup.GET("/audit_logs", tenantHandler.ListAuditLog)

	secretHandler := admin.NewSecretsHandler(persister)
	apiKeyGroup := singleGroup.Group("/secrets/api")
	apiKeyGroup.GET("", secretHandler.ListAPIKeys)
	apiKeyGroup.POST("", secretHandler.CreateAPIKey)
	apiKeyGroup.DELETE("/:secret_id", secretHandler.RemoveAPIKey)

	jwkKeyGroup := singleGroup.Group("/secrets/jwk")
	jwkKeyGroup.GET("", secretHandler.ListJWKKeys)
	jwkKeyGroup.POST("", secretHandler.CreateJWKKey)
	jwkKeyGroup.DELETE("/:secret_id", secretHandler.RemoveJWKKey)

	return main
}
