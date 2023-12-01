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
				ctx.Logger().Error(err)
				return echo.NewHTTPError(http.StatusBadRequest, "tenant_id must be a valid uuid4")
			}

			tenant, err := persister.GetTenantPersister(nil).Get(tenantId)
			if err != nil {
				ctx.Logger().Error(err)
				return err
			}

			if tenant == nil {
				return echo.NewHTTPError(http.StatusNotFound, "tenant not found")
			}

			ctx.Set("tenant", tenant)

			return next(ctx)
		}
	}
}
