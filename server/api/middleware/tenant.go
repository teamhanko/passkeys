package middleware

import (
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/persistence"
	"net/http"
)

func TenantMiddleware(persister persistence.Persister) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			tenantIdParam := ctx.Param("tenant_id")
			tenantId, err := uuid.FromString(tenantIdParam)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "tenant id is not a valid UUID").SetInternal(err)
			}

			tenant, err := persister.GetTenantPersister(nil).Get(tenantId)
			if err != nil || tenant == nil {
				return echo.NewHTTPError(http.StatusNotFound, "tenant not found").SetInternal(err)
			}

			ctx.Set("tenant", tenant)

			return next(ctx)
		}
	}
}
