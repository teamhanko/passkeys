package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/admin/request"
	"github.com/teamhanko/passkey-server/api/helper"
	"github.com/teamhanko/passkey-server/api/pagination"
	"github.com/teamhanko/passkey-server/api/services/admin"
	"github.com/teamhanko/passkey-server/persistence"
)

type AuditLogHandler struct {
	persister persistence.Persister
}

func NewAuditLogHandler(persister persistence.Persister) *AuditLogHandler {
	return &AuditLogHandler{
		persister: persister,
	}
}

func (h *AuditLogHandler) List(ctx echo.Context) error {
	var dto request.ListAuditLogDto
	err := ctx.Bind(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to list audit logs").SetInternal(err)
	}

	err = ctx.Validate(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to list audit logs").SetInternal(err)
	}

	if dto.Page == 0 {
		dto.Page = 1
	}

	if dto.PerPage == 0 {
		dto.PerPage = 20
	}

	hCtx, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	service := admin.NewTenantService(admin.CreateTenantServiceParams{
		Ctx:    ctx,
		Tenant: hCtx.Tenant,

		AuditLogPersister: h.persister.GetAuditLogPersister(nil),
	})

	auditLogs, logCount, err := service.ListAuditLogs(dto)
	if err != nil {
		return err
	}

	u, _ := url.Parse(fmt.Sprintf("%s://%s%s", ctx.Scheme(), ctx.Request().Host, ctx.Request().RequestURI))

	ctx.Response().Header().Set("Link", pagination.CreateHeader(u, logCount, dto.Page, dto.PerPage))
	ctx.Response().Header().Set("X-Total-Count", strconv.FormatInt(int64(logCount), 10))

	return ctx.JSON(http.StatusOK, auditLogs)
}
