package middleware

import (
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/persistence"
	"net/http"
)

func TenantMiddleware(persister persistence.Persister) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			const errorType = "about:blank"

			tenantIdParam := ctx.Param("tenant_id")
			tenantId, err := uuid.FromString(tenantIdParam)
			if err != nil {
				return ctx.JSON(http.StatusBadRequest, NewHttpError(
					errorType,
					"bad tenant id",
					"tenant_id is not a valid UUID",
					http.StatusBadRequest,
					nil,
				))
			}

			tenant, err := persister.GetTenantPersister(nil).Get(tenantId)
			if err != nil || tenant == nil {
				return ctx.JSON(http.StatusNotFound, NewHttpError(
					errorType,
					"tenant not found",
					"unable to find tenant in database",
					http.StatusNotFound,
					nil,
				))
			}

			ctx.Set("tenant", tenant)
			fmt.Printf("Tenant: %v\n", tenant)

			return next(ctx)
		}
	}
}
